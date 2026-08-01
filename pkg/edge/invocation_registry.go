package edge

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	MaxProfileInvocationRegistrations = 128
	MaxProfileInvocationRequirements  = 128
)

// ProfileInvocationRegistration binds one mapper to an exact negotiated
// profile selector. Wildcards and fallback registrations are intentionally
// unsupported.
type ProfileInvocationRegistration struct {
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	Operation         string
	Mapper            ProfileInvocationMapper
	// SuccessfulReceiptPolicy is optional. Its zero value preserves the
	// compatible full-quoted-price success charge. Explicit proportional
	// policies must be constructed with
	// NewProportionalSuccessfulReceiptPolicy.
	SuccessfulReceiptPolicy SuccessfulReceiptPolicy
}

// ProfileInvocationRequirement is one exact profile selector that a local
// deployment intends to advertise or route. It carries no code and grants no
// authority.
type ProfileInvocationRequirement struct {
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	Operation         string
}

type profileInvocationSelector struct {
	ProfileID         string   `json:"profileId"`
	ProfileVersion    string   `json:"profileVersion"`
	ProfileExtensions []string `json:"profileExtensions,omitempty"`
	Operation         string   `json:"operation"`
}

// ProfileInvocationRegistry is immutable after construction. Concurrent
// lookups cannot grow its state; mapper implementations themselves must be
// safe for the concurrency admitted by their deployment.
type ProfileInvocationRegistry struct {
	mappers         map[string]ProfileInvocationMapper
	successPolicies map[string]SuccessfulReceiptPolicy
}

// ProfileInvocationPlan is an immutable, fail-closed deployment binding. It
// contains only exact selectors that were both installed and declared as
// startup requirements. Installing an additional mapper does not make that
// mapper callable through the plan.
type ProfileInvocationPlan struct {
	registry *ProfileInvocationRegistry
	enabled  map[string]struct{}
}

func NewProfileInvocationRegistry(
	registrations []ProfileInvocationRegistration,
) (*ProfileInvocationRegistry, error) {
	if len(registrations) == 0 ||
		len(registrations) > MaxProfileInvocationRegistrations {
		return nil, fmt.Errorf(
			"profile invocation registry must contain 1..%d registrations",
			MaxProfileInvocationRegistrations,
		)
	}
	mappers := make(map[string]ProfileInvocationMapper, len(registrations))
	successPolicies := make(
		map[string]SuccessfulReceiptPolicy,
		len(registrations),
	)
	for index, registration := range registrations {
		if nilProfileInvocationMapper(registration.Mapper) {
			return nil, fmt.Errorf(
				"profile invocation registration %d has a nil mapper",
				index,
			)
		}
		selector, key, err := canonicalProfileInvocationSelector(
			registration.ProfileID,
			registration.ProfileVersion,
			registration.ProfileExtensions,
			registration.Operation,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"profile invocation registration %d: %w",
				index,
				err,
			)
		}
		if _, duplicate := mappers[key]; duplicate {
			return nil, fmt.Errorf(
				"duplicate profile invocation registration for %s %s %s",
				selector.ProfileID,
				selector.ProfileVersion,
				selector.Operation,
			)
		}
		policy := registration.SuccessfulReceiptPolicy
		if !policy.valid {
			policy = FullSuccessfulReceiptPolicy()
		}
		if _, err := policy.chargedNanoTOS(0); err != nil {
			return nil, fmt.Errorf(
				"profile invocation registration %d has an invalid successful receipt policy: %w",
				index,
				err,
			)
		}
		mappers[key] = registration.Mapper
		successPolicies[key] = policy
	}
	return &ProfileInvocationRegistry{
		mappers: mappers, successPolicies: successPolicies,
	}, nil
}

func (r *ProfileInvocationRegistry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.mappers)
}

// Supports reports whether the immutable registry contains one exact profile
// selector. Invalid selectors return false. It does not perform wildcard,
// compatible-version, or extension-subset matching and cannot grow registry
// state. Production paid execution should use ProfileInvocationPlan so
// installed but undeclared selectors remain unreachable.
func (r *ProfileInvocationRegistry) Supports(
	profileID string,
	profileVersion string,
	profileExtensions []string,
	operation string,
) bool {
	if r == nil || len(r.mappers) == 0 {
		return false
	}
	_, key, err := canonicalProfileInvocationSelector(
		profileID,
		profileVersion,
		profileExtensions,
		operation,
	)
	if err != nil {
		return false
	}
	_, ok := r.mappers[key]
	return ok
}

// ValidateRequirements fails unless every bounded, unique requirement has an
// exact installed mapper. Registry tooling may use it for inspection; startup
// paid execution should use NewProfileInvocationPlan so validation and the
// callable selector set cannot drift apart. It never performs version fallback
// or extension-subset matching.
func (r *ProfileInvocationRegistry) ValidateRequirements(
	requirements []ProfileInvocationRequirement,
) error {
	_, err := r.validateRequirements(requirements)
	return err
}

func (r *ProfileInvocationRegistry) validateRequirements(
	requirements []ProfileInvocationRequirement,
) (map[string]struct{}, error) {
	if r == nil || len(r.mappers) == 0 {
		return nil, errors.New("invalid profile invocation registry")
	}
	if len(requirements) == 0 ||
		len(requirements) > MaxProfileInvocationRequirements {
		return nil, fmt.Errorf(
			"profile invocation requirements must contain 1..%d entries",
			MaxProfileInvocationRequirements,
		)
	}
	seen := make(map[string]struct{}, len(requirements))
	for index, requirement := range requirements {
		_, key, err := canonicalProfileInvocationSelector(
			requirement.ProfileID,
			requirement.ProfileVersion,
			requirement.ProfileExtensions,
			requirement.Operation,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"profile invocation requirement %d is invalid: %w",
				index,
				err,
			)
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf(
				"profile invocation requirement %d is a duplicate",
				index,
			)
		}
		seen[key] = struct{}{}
		if _, installed := r.mappers[key]; !installed {
			return nil, fmt.Errorf(
				"profile invocation requirement %d has no exact mapper",
				index,
			)
		}
	}
	return seen, nil
}

// NewProfileInvocationPlan constructs the registry and its complete callable
// selector set in one operation. Callers cannot forget a separate validation
// step before using the result.
func NewProfileInvocationPlan(
	registrations []ProfileInvocationRegistration,
	requirements []ProfileInvocationRequirement,
) (*ProfileInvocationPlan, error) {
	registry, err := NewProfileInvocationRegistry(registrations)
	if err != nil {
		return nil, err
	}
	enabled, err := registry.validateRequirements(requirements)
	if err != nil {
		return nil, err
	}
	return &ProfileInvocationPlan{registry: registry, enabled: enabled}, nil
}

func (p *ProfileInvocationPlan) Len() int {
	if p == nil {
		return 0
	}
	return len(p.enabled)
}

// Supports reports whether a selector is in the exact deployment allowlist,
// not merely whether code for it happened to be installed.
func (p *ProfileInvocationPlan) Supports(
	profileID string,
	profileVersion string,
	profileExtensions []string,
	operation string,
) bool {
	if p == nil || p.registry == nil || len(p.enabled) == 0 {
		return false
	}
	_, key, err := canonicalProfileInvocationSelector(
		profileID,
		profileVersion,
		profileExtensions,
		operation,
	)
	if err != nil {
		return false
	}
	_, ok := p.enabled[key]
	return ok
}

func (p *ProfileInvocationPlan) resolve(
	material authorization.ReceiptInvocationMaterial,
) (ProfileInvocationMapper, error) {
	if p == nil || p.registry == nil || len(p.enabled) == 0 {
		return nil, errors.New("invalid profile invocation plan")
	}
	_, key, err := canonicalProfileInvocationSelector(
		material.ProfileID,
		material.ProfileVersion,
		material.ProfileExtensions,
		material.Operation,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve planned profile invocation mapper: %w", err)
	}
	if _, allowed := p.enabled[key]; !allowed {
		return nil, errors.New(
			"profile invocation selector is not enabled by the deployment plan",
		)
	}
	return p.registry.resolve(material)
}

func (p *ProfileInvocationPlan) resolveSuccessfulReceiptPolicy(
	material authorization.ReceiptInvocationMaterial,
) (SuccessfulReceiptPolicy, error) {
	if p == nil || p.registry == nil || len(p.enabled) == 0 {
		return SuccessfulReceiptPolicy{}, errors.New(
			"invalid profile invocation plan",
		)
	}
	_, key, err := canonicalProfileInvocationSelector(
		material.ProfileID,
		material.ProfileVersion,
		material.ProfileExtensions,
		material.Operation,
	)
	if err != nil {
		return SuccessfulReceiptPolicy{}, fmt.Errorf(
			"resolve planned successful receipt policy: %w",
			err,
		)
	}
	if _, allowed := p.enabled[key]; !allowed {
		return SuccessfulReceiptPolicy{}, errors.New(
			"profile invocation selector is not enabled by the deployment plan",
		)
	}
	policy, ok := p.registry.successPolicies[key]
	if !ok {
		return SuccessfulReceiptPolicy{}, errors.New(
			"profile invocation selector has no successful receipt policy",
		)
	}
	return policy, nil
}

func (r *ProfileInvocationRegistry) resolve(
	material authorization.ReceiptInvocationMaterial,
) (ProfileInvocationMapper, error) {
	if r == nil || len(r.mappers) == 0 {
		return nil, errors.New("invalid profile invocation registry")
	}
	_, key, err := canonicalProfileInvocationSelector(
		material.ProfileID,
		material.ProfileVersion,
		material.ProfileExtensions,
		material.Operation,
	)
	if err != nil {
		return nil, fmt.Errorf("resolve profile invocation mapper: %w", err)
	}
	mapper, ok := r.mappers[key]
	if !ok {
		return nil, errors.New(
			"no exact profile invocation mapper registration",
		)
	}
	return mapper, nil
}

// MapAndClaimRegisteredPaidExecution selects only a mapper that is both
// installed and enabled by the immutable deployment plan, then enters the
// normal commitment and pre-claim Worker-policy boundary.
func (c *Core) MapAndClaimRegisteredPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
) (ClaimedInvocation, error) {
	if plan == nil {
		return ClaimedInvocation{}, errors.New("nil profile invocation plan")
	}
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf(
			"extract planned profile invocation binding: %w",
			err,
		)
	}
	mapper, err := plan.resolve(material)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	policy, err := plan.resolveSuccessfulReceiptPolicy(material)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	return c.mapAndClaimPaidExecution(
		ctx,
		scope,
		expectedRevision,
		paymentAuthorization,
		intent,
		mapper,
		policy,
		worker,
	)
}

// MapAndClaimRecoveredPaidExecution reconstructs only the exact paid
// authorization previously committed in the request journal, but only when
// its selector remains enabled by the startup deployment plan. It permits
// restart recovery after the quote acceptance window has elapsed, while the
// original execution deadline and request retention remain authoritative.
func (c *Core) MapAndClaimRecoveredPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	intent []byte,
	plan *ProfileInvocationPlan,
	worker *localrpc.WorkerClient,
) (ClaimedInvocation, error) {
	if plan == nil {
		return ClaimedInvocation{}, errors.New("nil profile invocation plan")
	}
	_, material, request, err := c.recoveredExecutionAuthorization(scope)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	if request.State != journal.StateAuthorized &&
		request.State != journal.StateRunning {
		return ClaimedInvocation{}, journal.ErrTransition
	}
	mapper, err := plan.resolve(material)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	policy, err := plan.resolveSuccessfulReceiptPolicy(material)
	if err != nil {
		return ClaimedInvocation{}, err
	}
	return c.mapAndClaimPaidExecutionMaterial(
		ctx,
		scope,
		request.Revision,
		material,
		intent,
		mapper,
		policy,
		worker,
	)
}

func canonicalProfileInvocationSelector(
	profileID string,
	profileVersion string,
	profileExtensions []string,
	operation string,
) (profileInvocationSelector, string, error) {
	negotiated, err := protocol.NegotiateProfile(
		protocol.ProfileRequest{
			ID: profileID, SupportedVersions: []string{profileVersion},
			SupportedExtensions: append([]string(nil), profileExtensions...),
		},
		protocol.ProfileOffer{
			ID: profileID, Versions: []string{profileVersion},
			CriticalExtensions: append([]string(nil), profileExtensions...),
		},
	)
	if err != nil {
		return profileInvocationSelector{}, "", err
	}
	if _, err := protocol.RequestIntentDigest(
		negotiated.ID,
		negotiated.Version,
		negotiated.Extensions,
		operation,
		nil,
	); err != nil {
		return profileInvocationSelector{}, "", err
	}
	selector := profileInvocationSelector{
		ProfileID: negotiated.ID, ProfileVersion: negotiated.Version,
		ProfileExtensions: append([]string(nil), negotiated.Extensions...),
		Operation:         operation,
	}
	encoded, err := codec.Marshal(selector)
	if err != nil {
		return profileInvocationSelector{}, "", err
	}
	return selector, string(encoded), nil
}

func nilProfileInvocationMapper(mapper ProfileInvocationMapper) bool {
	if mapper == nil {
		return true
	}
	value := reflect.ValueOf(mapper)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface,
		reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
