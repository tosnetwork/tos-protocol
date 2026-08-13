package atosrpc

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

func (s *Server) SubmitNativeRegistryAction(ctx context.Context, req *connect.Request[atostosv1.SubmitNativeRegistryActionRequest]) (*connect.Response[atostosv1.SubmitNativeRegistryActionResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Submission == nil {
		return nil, invalid("INVALID_ARGUMENT", "native registry submission is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", "unknown Native registry fields are not supported")
	}
	if err := validateMutationContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if s.nativeRegistry == nil {
		return nil, failedPrecondition("TRUST_MODE_UNAVAILABLE", "Native registry is not configured")
	}
	submission, err := nativeSubmissionFromProto(req.Msg.Submission)
	if err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	result, created, err := s.nativeRegistry.Submit(ctx, submission)
	if err != nil {
		actionID, _ := nativeprotocol.ActionDigest(submission.Action)
		slog.Error("Native registry submission failed", "kind", submission.Action.Kind, "action_id", actionID, "error", err)
		return nil, nativeRegistryRPCError(err)
	}
	encoded, err := nativeResultToProto(result)
	if err != nil {
		return nil, rpcError(connect.CodeInternal, "INTERNAL_ERROR", "encode Native registry result")
	}
	return connect.NewResponse(&atostosv1.SubmitNativeRegistryActionResponse{Result: encoded, Created: created}), nil
}

func (s *Server) ResolveNativeRegistryAction(ctx context.Context, req *connect.Request[atostosv1.ResolveNativeRegistryActionRequest]) (*connect.Response[atostosv1.ResolveNativeRegistryActionResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", "unknown Native registry fields are not supported")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if s.nativeRegistry == nil || !strings.HasPrefix(req.Msg.ActionId, "sha256:") {
		return nil, failedPrecondition("TRUST_MODE_UNAVAILABLE", "Native registry is not configured or Action ID is invalid")
	}
	var expected *nativeprotocol.RegistryAction
	if req.Msg.ExpectedAction != nil {
		value, err := protoAs[nativeprotocol.RegistryAction](req.Msg.ExpectedAction)
		if err != nil {
			return nil, invalid("INVALID_ARGUMENT", "invalid expected Native action")
		}
		expected = &value
	}
	result, err := s.nativeRegistry.ResolveAction(ctx, req.Msg.ActionId, expected)
	if errors.Is(err, nativeregistry.ErrCanonicalNotFound) {
		return connect.NewResponse(&atostosv1.ResolveNativeRegistryActionResponse{Found: false}), nil
	}
	if err != nil {
		return nil, nativeRegistryRPCError(err)
	}
	encoded, err := nativeResultToProto(result)
	if err != nil {
		return nil, rpcError(connect.CodeInternal, "INTERNAL_ERROR", "encode Native registry result")
	}
	return connect.NewResponse(&atostosv1.ResolveNativeRegistryActionResponse{Found: true, Result: encoded}), nil
}

func (s *Server) ResolveNativeRegistryState(ctx context.Context, req *connect.Request[atostosv1.ResolveNativeRegistryStateRequest]) (*connect.Response[atostosv1.ResolveNativeRegistryStateResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", "unknown Native registry fields are not supported")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if s.nativeRegistry == nil || (req.Msg.AgentId == "") == (req.Msg.CapabilityId == "") {
		return nil, invalid("INVALID_ARGUMENT", "exactly one Native object ID is required")
	}
	objectID := req.Msg.AgentId
	if objectID == "" {
		objectID = req.Msg.CapabilityId
	}
	result, err := s.nativeRegistry.ResolveState(ctx, objectID, req.Msg.ExpectedStateDigest)
	if errors.Is(err, nativeregistry.ErrCanonicalNotFound) {
		return connect.NewResponse(&atostosv1.ResolveNativeRegistryStateResponse{Found: false}), nil
	}
	if err != nil {
		return nil, nativeRegistryRPCError(err)
	}
	if req.Msg.ExpectedObservation != nil {
		expected, mapErr := protoAs[nativeprotocol.EventObservation](req.Msg.ExpectedObservation)
		if mapErr != nil || expected != result.Observation {
			return nil, invalid("NATIVE_CROSS_DOMAIN_REPLAY", "expected observation does not match canonical state")
		}
	}
	encoded, err := nativeResultToProto(result)
	if err != nil {
		return nil, rpcError(connect.CodeInternal, "INTERNAL_ERROR", "encode Native registry result")
	}
	return connect.NewResponse(&atostosv1.ResolveNativeRegistryStateResponse{Found: true, Result: encoded}), nil
}

func nativeSubmissionFromProto(value *atostosv1.NativeRegistrySubmissionV1) (nativeregistry.Submission, error) {
	if value == nil || value.Action == nil || value.AuthoritySignatures == nil || value.Execution == nil {
		return nativeregistry.Submission{}, errors.New("complete Native registry action and authorization are required")
	}
	action, err := protoAs[nativeprotocol.RegistryAction](value.Action)
	if err != nil {
		return nativeregistry.Submission{}, err
	}
	convertSignatures := func(set *atostosv1.NativeAuthorizationSetV1) ([]nativeprotocol.Signature, error) {
		if set == nil {
			return nil, nil
		}
		output := make([]nativeprotocol.Signature, len(set.Signatures))
		for index, signature := range set.Signatures {
			if signature == nil {
				return nil, errors.New("nil Native semantic signature")
			}
			output[index] = nativeprotocol.Signature{Version: signature.Version, Algorithm: signature.Algorithm, KeyID: signature.KeyId, SignatureBase64: signature.SignatureBase64Url}
		}
		return output, nil
	}
	authority, err := convertSignatures(value.AuthoritySignatures)
	if err != nil {
		return nativeregistry.Submission{}, err
	}
	newOwner, err := convertSignatures(value.NewOwnerSignatures)
	if err != nil {
		return nativeregistry.Submission{}, err
	}
	convertExecutionSignatures := func(values []*atostosv1.NativeRegistryTVMSignatureV1) ([]nativeexecution.Signature, error) {
		output := make([]nativeexecution.Signature, len(values))
		for index, signature := range values {
			if signature == nil {
				return nil, errors.New("nil Native TVM signature")
			}
			output[index] = nativeexecution.Signature{Version: signature.Version, Algorithm: signature.Algorithm, KeyID: signature.KeyId, SignatureBase64: signature.SignatureBase64Url}
		}
		return output, nil
	}
	executionAuthority, err := convertExecutionSignatures(value.Execution.AuthoritySignatures)
	if err != nil {
		return nativeregistry.Submission{}, err
	}
	executionNewOwner, err := convertExecutionSignatures(value.Execution.NewOwnerSignatures)
	if err != nil {
		return nativeregistry.Submission{}, err
	}
	execution := nativeexecution.Execution{Version: value.Execution.Version, ContractAddress: value.Execution.ContractAddress, ActionAnchorAddress: value.Execution.ActionAnchorAddress, ContractCodeHash: value.Execution.ContractCodeHash, PortableActionDigest: value.Execution.PortableActionDigest, ActionCellBOCBase64: value.Execution.ActionCellBocBase64Url, ActionCellHash: value.Execution.ActionCellHash, AuthoritySignatures: executionAuthority, NewOwnerSignatures: executionNewOwner, PreviousTVMStateHash: value.Execution.PreviousTvmStateHash, ExpectedTVMStateHash: value.Execution.ExpectedTvmStateHash, ExpectedPortableStateDigest: value.Execution.ExpectedPortableStateDigest}
	return nativeregistry.Submission{Version: value.Version, Action: action, AuthorityPolicyCBORBase64: value.AuthorityPolicyCborBase64Url, AuthoritySignatures: authority, NewOwnerSignatures: newOwner, Execution: execution}, nil
}

func nativeResultToProto(value nativeregistry.Result) (*atostosv1.NativeRegistryResultV1, error) {
	network := func(value nativeprotocol.NetworkDomain) *atostosv1.NativeNetworkDomainV1 {
		return &atostosv1.NativeNetworkDomainV1{NetworkId: value.NetworkID, GenesisRootHash: value.GenesisRootHash, GenesisFileHash: value.GenesisFileHash}
	}
	reference := func(value nativeprotocol.ChainReference) *atostosv1.NativeChainReferenceV1 {
		return &atostosv1.NativeChainReferenceV1{Workchain: value.Workchain, Account: value.Account, LogicalTime: value.LogicalTime, TransactionHash: value.TransactionHash, ContractCodeHash: value.ContractCodeHash, EventIndex: value.EventIndex}
	}
	action := &atostosv1.NativeRegistryActionV1{Version: value.Action.Version, Kind: string(value.Action.Kind), Network: network(value.Action.Network), AgentId: value.Action.AgentID, CapabilityId: value.Action.CapabilityID, CapabilityVersion: value.Action.CapabilityVersion, Generation: value.Action.Generation, Sequence: value.Action.Sequence, PreviousStateDigest: value.Action.PreviousStateDigest, PolicyDigest: value.Action.PolicyDigest, PayloadDigest: value.Action.PayloadDigest, PayloadCborBase64Url: value.Action.PayloadCBORBase64, NonceBase64Url: value.Action.NonceBase64}
	event := &atostosv1.NativeRegistryEventV1{Version: value.Event.Version, Kind: string(value.Event.Kind), Network: network(value.Event.Network), ActionDigest: value.Event.ActionDigest, AgentId: value.Event.AgentID, CapabilityId: value.Event.CapabilityID, CapabilityVersion: value.Event.CapabilityVersion, Generation: value.Event.Generation, Sequence: value.Event.Sequence, PreviousStateDigest: value.Event.PreviousStateDigest, StateDigest: value.Event.StateDigest}
	state := &atostosv1.NativeRegistryStateV1{Version: value.State.Version, Network: network(value.State.Network), ObjectKind: value.State.ObjectKind, AgentId: value.State.AgentID, CapabilityId: value.State.CapabilityID, Generation: value.State.Generation, Sequence: value.State.Sequence, PredecessorStateDigest: value.State.PredecessorStateDigest, LastActionDigest: value.State.LastActionDigest, CurrentPolicyDigest: value.State.CurrentPolicyDigest, CurrentPolicyCborBase64Url: value.State.CurrentPolicyCBORBase64, OwnerAgentId: value.State.OwnerAgentID, CapabilityBootstrapOwnerAgentId: value.State.CapabilityBootstrapOwnerAgentID, CapabilityNonceBase64Url: value.State.CapabilityNonceBase64, DelegationActionDigests: append([]string(nil), value.State.DelegationActionDigests...), Tombstoned: value.State.Tombstoned, AgentNonceBase64Url: value.State.AgentNonceBase64, AgentBootstrapPolicyDigest: value.State.AgentBootstrapPolicyDigest}
	for _, item := range value.State.CapabilityVersions {
		state.CapabilityVersions = append(state.CapabilityVersions, &atostosv1.NativeCapabilityVersionStateV1{Version: item.Version, PayloadDigest: item.PayloadDigest, Revoked: item.Revoked})
	}
	state.PendingRecovery = &atostosv1.NativePendingRecoveryV1{InitiationActionDigest: value.State.PendingRecovery.InitiationActionDigest, NewPolicyDigest: value.State.PendingRecovery.NewPolicyDigest, NewPolicyCborBase64Url: value.State.PendingRecovery.NewPolicyCBORBase64, ExecuteAfterUnixSeconds: value.State.PendingRecovery.ExecuteAfterUnixSeconds}
	observation := &atostosv1.NativeEventObservationV1{Version: value.Observation.Version, Network: network(value.Observation.Network), EventDigest: value.Observation.EventDigest, Reference: reference(value.Observation.Reference), FinalizedCheckpoint: value.Observation.FinalizedCheckpoint, FinalizedRootHash: value.Observation.FinalizedRootHash, FinalizedFileHash: value.Observation.FinalizedFileHash, BlockUnixSeconds: value.Observation.BlockUnixSeconds, InclusionProofDigest: value.Observation.InclusionProofDigest}
	return &atostosv1.NativeRegistryResultV1{ActionId: value.ActionID, Action: action, Event: event, State: state, Observation: observation}, nil
}

func nativeResultFromProto(value *atostosv1.NativeRegistryResultV1) (nativeregistry.Result, error) {
	if value == nil || value.Action == nil || value.Event == nil || value.State == nil || value.Observation == nil || value.Action.Network == nil || value.Event.Network == nil || value.State.Network == nil || value.Observation.Network == nil || value.Observation.Reference == nil {
		return nativeregistry.Result{}, errors.New("incomplete Native registry result")
	}
	network := func(value *atostosv1.NativeNetworkDomainV1) nativeprotocol.NetworkDomain {
		return nativeprotocol.NetworkDomain{NetworkID: value.NetworkId, GenesisRootHash: value.GenesisRootHash, GenesisFileHash: value.GenesisFileHash}
	}
	a := value.Action
	e := value.Event
	s := value.State
	o := value.Observation
	result := nativeregistry.Result{ActionID: value.ActionId,
		Action:      nativeprotocol.RegistryAction{Version: a.Version, Kind: nativeprotocol.ActionKind(a.Kind), Network: network(a.Network), AgentID: a.AgentId, CapabilityID: a.CapabilityId, CapabilityVersion: a.CapabilityVersion, Generation: a.Generation, Sequence: a.Sequence, PreviousStateDigest: a.PreviousStateDigest, PolicyDigest: a.PolicyDigest, PayloadDigest: a.PayloadDigest, PayloadCBORBase64: a.PayloadCborBase64Url, NonceBase64: a.NonceBase64Url},
		Event:       nativeprotocol.RegistryEvent{Version: e.Version, Kind: nativeprotocol.ActionKind(e.Kind), Network: network(e.Network), ActionDigest: e.ActionDigest, AgentID: e.AgentId, CapabilityID: e.CapabilityId, CapabilityVersion: e.CapabilityVersion, Generation: e.Generation, Sequence: e.Sequence, PreviousStateDigest: e.PreviousStateDigest, StateDigest: e.StateDigest},
		State:       nativeprotocol.RegistryState{Version: s.Version, Network: network(s.Network), ObjectKind: s.ObjectKind, AgentID: s.AgentId, CapabilityID: s.CapabilityId, Generation: s.Generation, Sequence: s.Sequence, PredecessorStateDigest: s.PredecessorStateDigest, LastActionDigest: s.LastActionDigest, CurrentPolicyDigest: s.CurrentPolicyDigest, CurrentPolicyCBORBase64: s.CurrentPolicyCborBase64Url, OwnerAgentID: s.OwnerAgentId, CapabilityBootstrapOwnerAgentID: s.CapabilityBootstrapOwnerAgentId, CapabilityNonceBase64: s.CapabilityNonceBase64Url, CapabilityVersions: make([]nativeprotocol.CapabilityVersionState, 0, len(s.CapabilityVersions)), DelegationActionDigests: append(make([]string, 0, len(s.DelegationActionDigests)), s.DelegationActionDigests...), Tombstoned: s.Tombstoned, AgentNonceBase64: s.AgentNonceBase64Url, AgentBootstrapPolicyDigest: s.AgentBootstrapPolicyDigest},
		Observation: nativeprotocol.EventObservation{Version: o.Version, Network: network(o.Network), EventDigest: o.EventDigest, Reference: nativeprotocol.ChainReference{Workchain: o.Reference.Workchain, Account: o.Reference.Account, LogicalTime: o.Reference.LogicalTime, TransactionHash: o.Reference.TransactionHash, ContractCodeHash: o.Reference.ContractCodeHash, EventIndex: o.Reference.EventIndex}, FinalizedCheckpoint: o.FinalizedCheckpoint, FinalizedRootHash: o.FinalizedRootHash, FinalizedFileHash: o.FinalizedFileHash, BlockUnixSeconds: o.BlockUnixSeconds, InclusionProofDigest: o.InclusionProofDigest}}
	for _, item := range s.CapabilityVersions {
		if item == nil {
			return nativeregistry.Result{}, errors.New("nil Native capability version state")
		}
		result.State.CapabilityVersions = append(result.State.CapabilityVersions, nativeprotocol.CapabilityVersionState{Version: item.Version, PayloadDigest: item.PayloadDigest, Revoked: item.Revoked})
	}
	if s.PendingRecovery != nil {
		result.State.PendingRecovery = nativeprotocol.PendingRecovery{InitiationActionDigest: s.PendingRecovery.InitiationActionDigest, NewPolicyDigest: s.PendingRecovery.NewPolicyDigest, NewPolicyCBORBase64: s.PendingRecovery.NewPolicyCborBase64Url, ExecuteAfterUnixSeconds: s.PendingRecovery.ExecuteAfterUnixSeconds}
	}
	return result, nil
}

func protoAs[T any](value any) (T, error) {
	var output T
	raw, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(raw, &output)
	}
	return output, err
}

func nativeToProto[T any](value any) (*T, error) {
	output := new(T)
	raw, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(raw, output)
	}
	return output, err
}

func nativeRegistryRPCError(err error) error {
	var protocolErr *nativeprotocol.ProtocolError
	if errors.As(err, &protocolErr) {
		return invalid(string(protocolErr.Code), protocolErr.Field)
	}
	if errors.Is(err, nativeregistry.ErrAmbiguous) {
		return unavailable("NATIVE_FINALITY_UNAVAILABLE", "Native registry outcome is ambiguous")
	}
	return unavailable("NATIVE_FINALITY_UNAVAILABLE", "Native registry authority is unavailable")
}
