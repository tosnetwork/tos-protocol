package atosrpc

import (
	"context"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

func (s *Server) SubmitNativeAction(ctx context.Context, req *connect.Request[nativev1.SubmitNativeActionRequest]) (*connect.Response[nativev1.SubmitNativeActionResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Submission == nil || req.Msg.Submission.Action == nil {
		return nil, invalid("INVALID_ARGUMENT", "Native submission is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", "unknown Native v1 fields are not supported")
	}
	if err := validateNativeContext(req.Msg.Context, s.now(), true); err != nil {
		return nil, err
	}
	if s.nativeV1Relayer == nil {
		return nil, failedPrecondition("NATIVE_UNAVAILABLE", "atos_native_v1 relayer is not configured")
	}
	hash, err := s.nativeV1Relayer.Submit(ctx, req.Msg.Submission, 0)
	if err != nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "NATIVE_REJECTED", err.Error())
	}
	return connect.NewResponse(&nativev1.SubmitNativeActionResponse{ActionHash: hash, RelayAccepted: true}), nil
}

func (s *Server) ResolveNativeState(ctx context.Context, req *connect.Request[nativev1.ResolveNativeStateRequest]) (*connect.Response[nativev1.ResolveNativeStateResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "Native resolution request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", "unknown Native v1 fields are not supported")
	}
	if err := validateNativeContext(req.Msg.Context, s.now(), false); err != nil {
		return nil, err
	}
	if s.nativeV1Resolver == nil {
		return nil, failedPrecondition("NATIVE_UNAVAILABLE", "atos_native_v1 resolver is not configured")
	}
	state, found, err := s.nativeV1Resolver.ResolveState(ctx, req.Msg.ObjectId, req.Msg.ExpectedTvmStateHash)
	if err != nil {
		return nil, rpcError(connect.CodeFailedPrecondition, "NATIVE_RESOLUTION_FAILED", err.Error())
	}
	return connect.NewResponse(&nativev1.ResolveNativeStateResponse{Found: found, State: state}), nil
}

func validateNativeContext(value *nativev1.RequestContext, now time.Time, mutation bool) error {
	if value == nil || value.RequestId == "" || value.CallerId == "" {
		return invalid("INVALID_ARGUMENT", "complete Native request context is required")
	}
	if mutation && value.IdempotencyKey == "" {
		return invalid("INVALID_ARGUMENT", "Native mutation idempotency key is required")
	}
	if value.DeadlineUnixMillis <= 0 || !now.Before(time.UnixMilli(value.DeadlineUnixMillis)) {
		return rpcError(connect.CodeDeadlineExceeded, "DEADLINE_EXCEEDED", "Native request deadline expired")
	}
	return nil
}
