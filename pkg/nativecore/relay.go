package nativecore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

// ContractCellSender is a fee-paying transport boundary. Implementations must
// not interpret or rewrite signed Native semantics.
type ContractCellSender interface {
	SendContractCell(context.Context, string, uint64, string, string) error
}

type RelayStateResolver interface {
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
}

const (
	MinimumRelayFundingNanoTOS uint64 = 200_000_000
	MaximumRelayFundingNanoTOS uint64 = 100_000_000_000
)

type Relayer struct {
	Locator        *Locator
	Sender         ContractCellSender
	FundingNanoTOS uint64
	Journal        RelayJournal
	Resolver       RelayStateResolver
}

func (r *Relayer) CheckReady(ctx context.Context) error {
	if r == nil || r.Locator == nil || r.Sender == nil || r.Journal == nil || r.Resolver == nil || r.FundingNanoTOS < MinimumRelayFundingNanoTOS || r.FundingNanoTOS > MaximumRelayFundingNanoTOS {
		return errors.New("simplified Native relayer is not configured")
	}
	if ready, ok := r.Sender.(interface{ CheckContractCellReady(context.Context) error }); ok {
		return ready.CheckContractCellReady(ctx)
	}
	return nil
}

func (r *Relayer) Submit(ctx context.Context, submission *nativev1.SignedNativeActionV1, queryID uint64) (string, error) {
	return r.submit(ctx, submission, queryID, "query:"+strconv.FormatUint(queryID, 10))
}

func (r *Relayer) SubmitIdempotent(ctx context.Context, submission *nativev1.SignedNativeActionV1, idempotencyKey string) (string, error) {
	digest := sha256.Sum256([]byte(idempotencyKey))
	queryID := binary.BigEndian.Uint64(digest[:8])
	if queryID == 0 {
		queryID = 1
	}
	return r.submit(ctx, submission, queryID, idempotencyKey)
}

func (r *Relayer) submit(ctx context.Context, submission *nativev1.SignedNativeActionV1, queryID uint64, idempotencyKey string) (string, error) {
	if r == nil || r.Locator == nil || r.Sender == nil || r.Journal == nil || r.Resolver == nil || r.FundingNanoTOS < MinimumRelayFundingNanoTOS || r.FundingNanoTOS > MaximumRelayFundingNanoTOS || ctx == nil || submission == nil || submission.Action == nil {
		return "", errors.New("simplified Native relayer is not configured")
	}
	built, err := BuildAction(submission.Action)
	if err != nil {
		return "", err
	}
	if submission.Action.TargetContractCodeHash != r.Locator.CodeHash {
		return "", nativeError(ErrWrongContract, "Native action is bound to a different contract code hash")
	}
	if queryID == 0 {
		return "", errors.New("Native relay query ID must be nonzero")
	}
	bodyBuilder := MessageBody
	destinationID := submission.Action.TargetObjectId
	stateInit := ""
	switch payload := submission.Action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		// Agent registration deploys the target directly.
	case *nativev1.NativeActionV1_RegisterCapability:
		destinationID = payload.RegisterCapability.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		destinationID = payload.AddCapabilityVersion.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_TransferCapability:
		destinationID = payload.TransferCapability.CurrentOwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_RevokeCapability:
		destinationID = payload.RevokeCapability.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	}
	body, err := bodyBuilder(built, submission.AuthoritySignatures, submission.CounterpartySignatures, queryID)
	if err != nil {
		return "", err
	}
	identity, err := r.Locator.Locate(destinationID)
	if err != nil {
		return "", err
	}
	if built.Kind == KindRegisterAgent {
		stateInit = identity.StateInitBOC
	}
	bodyRaw := body.ToBOC()
	stateInitRaw := []byte{}
	if stateInit != "" {
		stateInitRaw, err = base64.StdEncoding.DecodeString(stateInit)
		if err != nil {
			return "", errors.New("invalid Native relay StateInit encoding")
		}
	}
	intent := RelayIntent{
		ActionHash: built.HashString, Destination: identity.Address, QueryID: queryID,
		BodyHash: relayPayloadHash(bodyRaw), StateInitHash: relayPayloadHash(stateInitRaw),
		FundingNanoTOS: r.FundingNanoTOS,
	}
	found, complete, existing, err := r.Journal.Lookup(idempotencyKey, intent)
	if err != nil {
		return "", err
	}
	if found {
		return r.resolveRecordedIntent(ctx, submission.Action.TargetObjectId, idempotencyKey, intent, complete, existing)
	}
	if built.Kind == KindRegisterAgent {
		payload := submission.Action.GetRegisterAgent()
		if payload == nil {
			return "", nativeError(ErrBadAction, "missing Agent registration policy")
		}
		if err := VerifyPolicyPossession(payload.InitialPolicy, submission.AuthoritySignatures, built.Hash); err != nil {
			return "", err
		}
		if err := VerifySignatures(payload.InitialPolicy, submission.AuthoritySignatures, PurposeAgentControl, false, built.Hash); err != nil {
			return "", err
		}
	} else if err := r.verifyLiveAuthorization(ctx, submission, built); err != nil {
		return "", err
	}
	complete, existing, err = r.Journal.Begin(idempotencyKey, intent)
	if err != nil {
		return "", err
	}
	if complete {
		return existing, nil
	}
	if existing != "" {
		return r.resolveRecordedIntent(ctx, submission.Action.TargetObjectId, idempotencyKey, intent, false, existing)
	}
	if err := r.Sender.SendContractCell(ctx, identity.Address, r.FundingNanoTOS,
		base64.StdEncoding.EncodeToString(bodyRaw), stateInit); err != nil {
		return "", err
	}
	if err := r.Journal.Complete(idempotencyKey, intent); err != nil {
		return "", err
	}
	return built.HashString, nil
}

func relayPayloadHash(payload []byte) string {
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func (r *Relayer) resolveRecordedIntent(ctx context.Context, objectID, key string, intent RelayIntent, complete bool, existing string) (string, error) {
	if complete {
		return existing, nil
	}
	state, found, err := r.Resolver.ResolveState(ctx, objectID, "")
	if err == nil && found {
		last := ""
		if state.GetAgent() != nil {
			last = state.GetAgent().LastActionHash
		} else if state.GetCapability() != nil {
			last = state.GetCapability().LastActionHash
		}
		if last == intent.ActionHash {
			if err := r.Journal.Complete(key, intent); err != nil {
				return "", err
			}
			return intent.ActionHash, nil
		}
	}
	return "", errors.New("Native relay outcome is ambiguous; refusing to rebroadcast")
}

func (r *Relayer) verifyLiveAuthorization(ctx context.Context, submission *nativev1.SignedNativeActionV1, built BuiltAction) error {
	action := submission.Action
	authorityAgent := action.TargetObjectId
	expectedAuthorityState := action.PredecessorTvmStateHash
	purpose, recovery := uint32(PurposeAgentControl), false
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_DelegateAgent:
		purpose = PurposeDelegation
	case *nativev1.NativeActionV1_InitiateRecovery, *nativev1.NativeActionV1_CompleteRecovery:
		purpose, recovery = PurposeRecovery, true
	case *nativev1.NativeActionV1_RegisterCapability:
		authorityAgent, expectedAuthorityState, purpose = payload.RegisterCapability.OwnerAgentId, "", PurposeCapabilityControl
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		authorityAgent, expectedAuthorityState, purpose = payload.AddCapabilityVersion.OwnerAgentId, "", PurposeCapabilityControl
	case *nativev1.NativeActionV1_TransferCapability:
		authorityAgent, expectedAuthorityState, purpose = payload.TransferCapability.CurrentOwnerAgentId, "", PurposeCapabilityControl
	case *nativev1.NativeActionV1_RevokeCapability:
		authorityAgent, expectedAuthorityState, purpose = payload.RevokeCapability.OwnerAgentId, "", PurposeCapabilityControl
	}
	state, found, err := r.Resolver.ResolveState(ctx, authorityAgent, expectedAuthorityState)
	if err != nil || !found || state.GetAgent() == nil {
		return nativeError(ErrBadSignature, "live Native authority is unavailable")
	}
	if err := VerifySignatures(state.GetAgent().Policy, submission.AuthoritySignatures, purpose, recovery, built.Hash); err != nil {
		return err
	}
	switch payload := action.Payload.(type) {
	case *nativev1.NativeActionV1_UpdateAgentPolicy:
		return VerifyPolicyPossession(payload.UpdateAgentPolicy.NewPolicy, submission.CounterpartySignatures, built.Hash)
	case *nativev1.NativeActionV1_InitiateRecovery:
		return VerifyPolicyPossession(payload.InitiateRecovery.NewPolicy, submission.CounterpartySignatures, built.Hash)
	case *nativev1.NativeActionV1_TransferCapability:
		newState, found, err := r.Resolver.ResolveState(ctx, payload.TransferCapability.NewOwnerAgentId, "")
		if err != nil || !found || newState.GetAgent() == nil {
			return nativeError(ErrBadSignature, "new Capability owner authority is unavailable")
		}
		return VerifySignatures(newState.GetAgent().Policy, submission.CounterpartySignatures, PurposeCapabilityControl, false, built.Hash)
	}
	return nil
}
