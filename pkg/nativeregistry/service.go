// Package nativeregistry implements the Phase 5B chain-authority boundary.
// It composes the frozen nativeprotocol state machine with a mutation-only
// publisher and a strictly read-only canonical resolver.
package nativeregistry

import (
	"context"
	"errors"
	"fmt"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
)

const MaxExecutionEnvelopeBytes = 48 << 10

var (
	ErrCanonicalNotFound = errors.New("canonical native registry action not found")
	ErrCanonicalPending  = errors.New("canonical native registry action anchor is pending")
	ErrPublisherNotFound = errors.New("enrolled publisher journal proves action absent")
	ErrPublisherPending  = errors.New("enrolled publisher journal has an exact pending action")
	ErrAmbiguous         = errors.New("native registry outcome is ambiguous")
)

type Submission struct {
	Version                   string                        `json:"version"`
	Action                    nativeprotocol.RegistryAction `json:"action"`
	AuthorityPolicyCBORBase64 string                        `json:"authority_policy_cbor_base64url"`
	AuthoritySignatures       []nativeprotocol.Signature    `json:"authority_signatures"`
	NewOwnerSignatures        []nativeprotocol.Signature    `json:"new_owner_signatures"`
	Execution                 nativeexecution.Execution     `json:"execution"`
}

type Result struct {
	ActionID    string                          `json:"action_id"`
	Action      nativeprotocol.RegistryAction   `json:"action"`
	Event       nativeprotocol.RegistryEvent    `json:"event"`
	State       nativeprotocol.RegistryState    `json:"state"`
	Observation nativeprotocol.EventObservation `json:"observation"`
}

type FinalizedHead struct {
	Network          nativeprotocol.NetworkDomain `json:"network"`
	Checkpoint       uint64                       `json:"checkpoint"`
	BlockUnixSeconds uint64                       `json:"block_unix_seconds"`
}

// Resolver has no mutation capability. ErrCanonicalNotFound is permitted only
// after complete strict-majority chain observation, never for a local miss.
type Resolver interface {
	CheckReady(context.Context) error
	Head(context.Context) (FinalizedHead, error)
	ResolveAction(context.Context, string) (Result, error)
	// ResolveState returns the current state when stateDigest is empty, or the
	// exact historical state when it is present.
	ResolveState(context.Context, string, string) (Result, error)
}

// Publisher is the enrolled durable journal boundary. Resolve never mutates.
// Publish persists intent before broadcast and is idempotent by Action ID.
type Publisher interface {
	CheckReady(context.Context) error
	Resolve(context.Context, Submission, string, string) error
	Publish(context.Context, Submission, string, string) error
}

// ContractLocator derives the unique object-contract identity from immutable
// Native IDs and pinned code. Caller-provided addresses are never selectors.
type ContractLocator interface {
	Locate(nativeprotocol.RegistryAction) (nativeexecution.ContractIdentity, error)
}

type Service struct {
	resolver  Resolver
	publisher Publisher
	locator   ContractLocator
}

func New(resolver Resolver, publisher Publisher, locator ContractLocator) (*Service, error) {
	if resolver == nil || publisher == nil || locator == nil {
		return nil, errors.New("native registry resolver, publisher and contract locator are required")
	}
	return &Service{resolver: resolver, publisher: publisher, locator: locator}, nil
}

func (s *Service) CheckReady(ctx context.Context) error {
	if err := s.resolver.CheckReady(ctx); err != nil {
		return fmt.Errorf("native registry resolver: %w", err)
	}
	if err := s.publisher.CheckReady(ctx); err != nil {
		return fmt.Errorf("native registry publisher: %w", err)
	}
	return nil
}

// Submit never treats an unavailable resolver or journal as absence. After a
// broadcast it returns only an independently observed finalized result.
func (s *Service) Submit(ctx context.Context, submission Submission) (Result, bool, error) {
	actionID, envelopeDigest, err := s.validateEnvelope(submission)
	if err != nil {
		return Result{}, false, err
	}
	if found, err := s.resolver.ResolveAction(ctx, actionID); err == nil {
		if err := validateResult(found, actionID, submission.Action); err != nil {
			return Result{}, false, err
		}
		return found, false, nil
	} else if !errors.Is(err, ErrCanonicalNotFound) && !errors.Is(err, ErrCanonicalPending) {
		return Result{}, false, fmt.Errorf("resolve canonical action before publish: %w", err)
	}
	if err := s.validateAuthority(ctx, submission); err != nil {
		return Result{}, false, err
	}
	if err := s.publisher.Resolve(ctx, submission, actionID, envelopeDigest); err != nil {
		if errors.Is(err, ErrPublisherNotFound) && !errors.Is(s.resolveActionStatus(ctx, actionID), ErrCanonicalNotFound) {
			return Result{}, false, fmt.Errorf("publisher absence conflicts with canonical pending action: %w", ErrAmbiguous)
		}
		if !errors.Is(err, ErrPublisherNotFound) && !errors.Is(err, ErrPublisherPending) {
			return Result{}, false, fmt.Errorf("resolve enrolled publisher journal: %w", err)
		}
		// Publish is authorized either by a versioned typed absence for a new
		// action, or by the publisher's own durable, semantically exact intent.
		// The latter resumes the same deterministic Action Anchor; an unrelated
		// cache miss or ambiguous network response can never reach this branch.
		if err := s.publisher.Publish(ctx, submission, actionID, envelopeDigest); err != nil {
			return Result{}, false, fmt.Errorf("publish native registry action: %w", errors.Join(ErrAmbiguous, err))
		}
	}
	found, err := s.resolver.ResolveAction(ctx, actionID)
	if err != nil {
		return Result{}, false, fmt.Errorf("observe published native registry action: %w", errors.Join(ErrAmbiguous, err))
	}
	if err := validateResult(found, actionID, submission.Action); err != nil {
		return Result{}, false, err
	}
	return found, true, nil
}

func (s *Service) resolveActionStatus(ctx context.Context, actionID string) error {
	_, err := s.resolver.ResolveAction(ctx, actionID)
	return err
}

func (s *Service) ResolveAction(ctx context.Context, actionID string, expected *nativeprotocol.RegistryAction) (Result, error) {
	found, err := s.resolver.ResolveAction(ctx, actionID)
	if err != nil {
		return Result{}, err
	}
	if expected != nil {
		if err := validateResult(found, actionID, *expected); err != nil {
			return Result{}, err
		}
	}
	return found, nil
}

func (s *Service) ResolveState(ctx context.Context, objectID, expectedDigest string) (Result, error) {
	found, err := s.resolver.ResolveState(ctx, objectID, expectedDigest)
	if err != nil {
		return Result{}, err
	}
	digest, err := nativeprotocol.StateDigest(found.State)
	if err != nil || (expectedDigest != "" && digest != expectedDigest) {
		return Result{}, &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePredecessorMismatch, Field: "expected_state_digest"}
	}
	return found, nil
}

func (s *Service) validateEnvelope(submission Submission) (string, string, error) {
	if submission.Version != nativeprotocol.Version {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeUnsupportedVersion, Field: "submission.version"}
	}
	actionID, err := nativeprotocol.ActionDigest(submission.Action)
	if err != nil {
		return "", "", err
	}
	if submission.Action.Kind != nativeprotocol.ActionTransferCapability && len(submission.NewOwnerSignatures) != 0 {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePurposeUnauthorized, Field: "new_owner_signatures"}
	}
	contract, err := s.locator.Locate(submission.Action)
	if err != nil {
		return "", "", err
	}
	if err := nativeexecution.Validate(submission.Execution, submission.Action, contract); err != nil {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCanonicalEncoding, Field: "submission.execution"}
	}
	semantic := submission
	// BOC graph ordering is a transport choice, not registry semantics. The
	// independently decoded ActionCellHash and all signatures bind the exact
	// TVM cell; excluding only the BOC carrier makes equivalent serializers
	// converge on one publisher idempotency identity.
	semantic.Execution.ActionCellBOCBase64 = ""
	raw, err := codec.Marshal(semantic)
	if err != nil {
		return "", "", err
	}
	if len(raw) > MaxExecutionEnvelopeBytes {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCanonicalEncoding, Field: "submission.size"}
	}
	digest, err := codec.DigestCanonical("tos.native.registry-execution-envelope.v1", raw)
	return actionID, digest, err
}

// ValidateForPublisher independently validates the complete immutable
// envelope and live canonical authority before a key-custody boundary spends
// fees. It exists so direct same-user socket callers cannot rely on the
// upstream gateway having performed these checks.
func ValidateForPublisher(ctx context.Context, resolver Resolver, locator ContractLocator, submission Submission) (string, string, error) {
	if resolver == nil || locator == nil {
		return "", "", errors.New("native registry publisher authority validation is unavailable")
	}
	service := &Service{resolver: resolver, locator: locator}
	actionID, digest, err := service.validateEnvelope(submission)
	if err != nil {
		return "", "", err
	}
	if err := service.validateAuthority(ctx, submission); err != nil {
		return "", "", err
	}
	return actionID, digest, nil
}

// ValidateSubmission exposes the frozen envelope validation to publisher and
// transport boundaries without granting either authority over its contents.
func ValidateSubmission(submission Submission) (actionID, envelopeDigest string, err error) {
	if submission.Version != nativeprotocol.Version {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeUnsupportedVersion, Field: "submission.version"}
	}
	actionID, err = nativeprotocol.ActionDigest(submission.Action)
	if err != nil {
		return "", "", err
	}
	semantic := submission
	semantic.Execution.ActionCellBOCBase64 = ""
	raw, err := codec.Marshal(semantic)
	if err != nil {
		return "", "", err
	}
	if len(raw) > MaxExecutionEnvelopeBytes {
		return "", "", &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCanonicalEncoding, Field: "submission.size"}
	}
	envelopeDigest, err = codec.DigestCanonical("tos.native.registry-execution-envelope.v1", raw)
	return actionID, envelopeDigest, err
}

func (s *Service) validateAuthority(ctx context.Context, submission Submission) error {
	action := submission.Action
	head, err := s.resolver.Head(ctx)
	if err != nil || head.Checkpoint == 0 || head.BlockUnixSeconds == 0 || head.Network != action.Network {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeFinalityUnavailable, Field: "finalized_head"}
	}
	var previous *nativeprotocol.RegistryState
	var expectedPolicyDigest string
	if action.PreviousStateDigest != "" {
		prior, err := s.resolver.ResolveState(ctx, objectID(action), action.PreviousStateDigest)
		if err != nil {
			return fmt.Errorf("resolve canonical predecessor: %w", err)
		}
		digest, err := nativeprotocol.StateDigest(prior.State)
		if err != nil || digest != action.PreviousStateDigest {
			return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePredecessorMismatch, Field: "previous_state_digest"}
		}
		copyState := prior.State
		previous = &copyState
		if copyState.ObjectKind == "agent" {
			expectedPolicyDigest = copyState.CurrentPolicyDigest
		} else {
			owner, err := s.resolver.ResolveState(ctx, copyState.OwnerAgentID, "")
			if err != nil || owner.State.ObjectKind != "agent" {
				return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePolicyUnauthorized, Field: "current_owner_policy"}
			}
			expectedPolicyDigest = owner.State.CurrentPolicyDigest
		}
	} else if action.Kind == nativeprotocol.ActionRegisterCapability {
		owner, err := s.resolver.ResolveState(ctx, action.AgentID, "")
		if err != nil || owner.State.ObjectKind != "agent" {
			return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePolicyUnauthorized, Field: "bootstrap_owner_policy"}
		}
		expectedPolicyDigest = owner.State.CurrentPolicyDigest
	}
	policy, err := nativeprotocol.DecodeControllerPolicy(submission.AuthorityPolicyCBORBase64, action.PolicyDigest)
	if err != nil {
		return err
	}
	var newPolicy nativeprotocol.ControllerPolicy
	if action.Kind == nativeprotocol.ActionTransferCapability {
		var payload nativeprotocol.TransferCapabilityPayload
		if err := nativeprotocol.DecodePayload(action, &payload); err != nil {
			return err
		}
		newPolicy, err = nativeprotocol.DecodeControllerPolicy(payload.NewOwnerPolicyCBORBase64, payload.NewOwnerPolicyDigest)
		if err != nil {
			return err
		}
		if err := nativeprotocol.VerifyTransferAuthorization(action, expectedPolicyDigest, policy, payload.NewOwnerPolicyDigest, newPolicy, submission.AuthoritySignatures, submission.NewOwnerSignatures); err != nil {
			return err
		}
	} else if err := nativeprotocol.VerifyAuthorization(action, expectedPolicyDigest, policy, submission.AuthoritySignatures); err != nil {
		return err
	}
	if action.Kind == nativeprotocol.ActionRecoverAgent {
		var payload nativeprotocol.RecoverAgentPayload
		if err := nativeprotocol.DecodePayload(action, &payload); err != nil {
			return err
		}
		initiation, err := s.resolver.ResolveAction(ctx, payload.InitiationActionDigest)
		if err != nil {
			return fmt.Errorf("resolve recovery initiation: %w", err)
		}
		if initiation.Observation.Reference != payload.InitiationReference {
			return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCrossDomainReplay, Field: "recovery.initiation_reference"}
		}
		preInitiation, err := s.resolver.ResolveState(ctx, action.AgentID, initiation.Action.PreviousStateDigest)
		if err != nil {
			return fmt.Errorf("resolve recovery pre-initiation state: %w", err)
		}
		if previous == nil {
			return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePredecessorMismatch, Field: "recovery.predecessor"}
		}
		if err := nativeprotocol.ValidateRecoveryTransition(preInitiation.State, *previous, action, initiation.Action, initiation.Event, initiation.Observation, head.BlockUnixSeconds); err != nil {
			return err
		}
	} else if _, err = nativeprotocol.DeriveNextState(previous, action, expectedPolicyDigest, head.BlockUnixSeconds); err != nil {
		return err
	}
	var newPolicyPointer *nativeprotocol.ControllerPolicy
	if action.Kind == nativeprotocol.ActionTransferCapability {
		newPolicyPointer = &newPolicy
	}
	contract, err := s.locator.Locate(action)
	if err != nil {
		return err
	}
	expected, err := nativeexecution.Build(previous, action, expectedPolicyDigest, policy, newPolicyPointer, head.BlockUnixSeconds, contract)
	if err != nil || !nativeexecution.SameUnsigned(expected.Execution, submission.Execution) {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCrossDomainReplay, Field: "submission.execution.semantics"}
	}
	if err := nativeexecution.VerifySet(policy, submission.AuthoritySignatures, submission.Execution.AuthoritySignatures, submission.Execution); err != nil {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePolicyUnauthorized, Field: "submission.execution.authority_signatures"}
	}
	if action.Kind == nativeprotocol.ActionTransferCapability {
		if err := nativeexecution.VerifySet(newPolicy, submission.NewOwnerSignatures, submission.Execution.NewOwnerSignatures, submission.Execution); err != nil {
			return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePolicyUnauthorized, Field: "submission.execution.new_owner_signatures"}
		}
	} else if len(submission.Execution.NewOwnerSignatures) != 0 {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodePurposeUnauthorized, Field: "submission.execution.new_owner_signatures"}
	}
	return nil
}

func validateResult(result Result, actionID string, expected nativeprotocol.RegistryAction) error {
	digest, err := nativeprotocol.ActionDigest(result.Action)
	if err != nil || digest != actionID || result.Action != expected || result.ActionID != actionID {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCrossDomainReplay, Field: "result.action"}
	}
	if result.Observation.FinalizedCheckpoint == 0 {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeFinalityUnavailable, Field: "result.observation.finalized_checkpoint"}
	}
	if err := nativeprotocol.ValidateEventForActionAndState(result.Action, result.State, result.Event); err != nil {
		return err
	}
	if err := result.Observation.Validate(); err != nil {
		return err
	}
	eventDigest, err := nativeprotocol.EventDigest(result.Event)
	if err != nil || result.Observation.EventDigest != eventDigest || result.Observation.Network != result.Action.Network {
		return &nativeprotocol.ProtocolError{Code: nativeprotocol.CodeCrossDomainReplay, Field: "result.observation"}
	}
	return nil
}

func objectID(action nativeprotocol.RegistryAction) string {
	if action.CapabilityID != "" {
		return action.CapabilityID
	}
	return action.AgentID
}
