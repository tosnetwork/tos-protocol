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

const MaxProfileInvocationRegistrations = 128

// ProfileInvocationRegistration binds one mapper to an exact negotiated
// profile selector. Wildcards and fallback registrations are intentionally
// unsupported.
type ProfileInvocationRegistration struct {
	ProfileID         string
	ProfileVersion    string
	ProfileExtensions []string
	Operation         string
	Mapper            ProfileInvocationMapper
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
	mappers map[string]ProfileInvocationMapper
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
		mappers[key] = registration.Mapper
	}
	return &ProfileInvocationRegistry{mappers: mappers}, nil
}

func (r *ProfileInvocationRegistry) Len() int {
	if r == nil {
		return 0
	}
	return len(r.mappers)
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

// MapAndClaimRegisteredPaidExecution selects only the exact mapper registered
// for the authorized session's profile version, extension set, and operation,
// then enters the normal commitment and pre-claim Worker-policy boundary.
func (c *Core) MapAndClaimRegisteredPaidExecution(
	ctx context.Context,
	scope journal.Scope,
	expectedRevision uint64,
	paymentAuthorization authorization.AuthorizedPayment,
	intent []byte,
	registry *ProfileInvocationRegistry,
	worker *localrpc.WorkerClient,
) (ClaimedInvocation, error) {
	if registry == nil {
		return ClaimedInvocation{}, errors.New(
			"nil profile invocation registry",
		)
	}
	material, err := paymentAuthorization.ReceiptInvocationMaterial()
	if err != nil {
		return ClaimedInvocation{}, fmt.Errorf(
			"extract registered profile invocation binding: %w",
			err,
		)
	}
	mapper, err := registry.resolve(material)
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
