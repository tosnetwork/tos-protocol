package servicerpc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/publicerrors"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func (s *Server) SubmitNativeAction(ctx context.Context, req *connect.Request[nativev1.SubmitNativeActionRequest]) (*connect.Response[nativev1.SubmitNativeActionResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Submission == nil || req.Msg.Submission.Action == nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("Native submission is required"), 0)
	}
	if err := rejectUnknown(req.Msg); err != nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("unknown Native v1 fields are not supported"), 0)
	}
	if err := validateNativeContext(req.Msg.Context, s.now(), true); err != nil {
		return nil, err
	}
	if s.nativeV1Relayer == nil {
		return nil, publicerrors.New(publicerrors.DependencyUnavailable, errors.New("tos_service_v1 relayer is not configured"), time.Second)
	}
	var hash string
	var err error
	if relayer, ok := s.nativeV1Relayer.(interface {
		SubmitIdempotent(context.Context, *nativev1.SignedNativeActionV1, string) (string, error)
	}); ok {
		hash, err = relayer.SubmitIdempotent(ctx, req.Msg.Submission, req.Msg.Context.IdempotencyKey)
	} else {
		hash, err = s.nativeV1Relayer.Submit(ctx, req.Msg.Submission, 1)
	}
	if err != nil {
		return nil, nativeConnectError(connect.CodeFailedPrecondition, err, publicerrors.AmbiguousOutcome)
	}
	return connect.NewResponse(&nativev1.SubmitNativeActionResponse{ActionHash: hash, RelayAccepted: true}), nil
}

func nativeConnectError(connectCode connect.Code, cause error, fallback publicerrors.Kind) error {
	result := connect.NewError(connectCode, cause)
	code, ok := nativecore.ErrorCodeOf(cause)
	if !ok {
		retry := time.Duration(0)
		if fallback == publicerrors.DependencyUnavailable {
			retry = time.Second
		}
		return publicerrors.New(fallback, cause, retry)
	}
	detail, err := connect.NewErrorDetail(&nativev1.NativeErrorV1{
		Code: nativev1.NativeErrorCodeV1(code), Identifier: code.String(),
		RetryDisposition: nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER,
	})
	if err == nil {
		result.AddDetail(detail)
	}
	return result
}

func (s *Server) ResolveNativeState(ctx context.Context, req *connect.Request[nativev1.ResolveNativeStateRequest]) (*connect.Response[nativev1.ResolveNativeStateResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("Native resolution request is required"), 0)
	}
	if err := rejectUnknown(req.Msg); err != nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("unknown Native v1 fields are not supported"), 0)
	}
	if err := validateNativeContext(req.Msg.Context, s.now(), false); err != nil {
		return nil, err
	}
	if s.nativeV1Resolver == nil {
		return nil, publicerrors.New(publicerrors.DependencyUnavailable, errors.New("tos_service_v1 resolver is not configured"), time.Second)
	}
	state, found, err := s.nativeV1Resolver.ResolveState(ctx, req.Msg.ObjectId, req.Msg.ExpectedTvmStateHash)
	if err != nil {
		return nil, nativeConnectError(connect.CodeFailedPrecondition, err, publicerrors.DependencyUnavailable)
	}
	return connect.NewResponse(&nativev1.ResolveNativeStateResponse{Found: found, State: state}), nil
}

func (s *Server) ResolveDNSAlias(ctx context.Context, req *connect.Request[nativev1.ResolveDNSAliasRequest]) (*connect.Response[nativev1.ResolveDNSAliasResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("DNS alias resolution request is required"), 0)
	}
	if err := rejectUnknown(req.Msg); err != nil {
		return nil, publicerrors.New(publicerrors.BadRequest, errors.New("unknown DNS alias v1 fields are not supported"), 0)
	}
	if err := validateNativeContext(req.Msg.Context, s.now(), false); err != nil {
		return nil, err
	}
	if s.dnsAliasResolver == nil {
		return nil, publicerrors.New(publicerrors.DependencyUnavailable, errors.New("TOS DNS alias resolver is not configured"), time.Second)
	}
	result, err := s.dnsAliasResolver.ResolveDNSAlias(ctx, req.Msg)
	if err != nil {
		return nil, nativeConnectError(connect.CodeFailedPrecondition, err, publicerrors.DependencyUnavailable)
	}
	return connect.NewResponse(result), nil
}

func validateNativeContext(value *nativev1.RequestContext, now time.Time, mutation bool) error {
	if value == nil || value.RequestId == "" || value.CallerId == "" {
		return publicerrors.New(publicerrors.BadRequest, errors.New("complete Native request context is required"), 0)
	}
	if mutation && value.IdempotencyKey == "" {
		return publicerrors.New(publicerrors.BadRequest, errors.New("Native mutation idempotency key is required"), 0)
	}
	if value.DeadlineUnixMillis <= 0 || !now.Before(time.UnixMilli(value.DeadlineUnixMillis)) {
		return publicerrors.New(publicerrors.Deadline, errors.New("Native request deadline expired"), 0)
	}
	return nil
}

func rejectUnknown(message protoreflect.ProtoMessage) error {
	if message == nil {
		return errors.New("message is required")
	}
	return rejectMessage(message.ProtoReflect())
}

func rejectMessage(message protoreflect.Message) error {
	if len(message.GetUnknown()) != 0 {
		return errors.New("protobuf unknown fields are forbidden")
	}
	var found error
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Kind() != protoreflect.MessageKind {
			return true
		}
		if field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i++ {
				if err := rejectMessage(list.Get(i).Message()); err != nil {
					found = err
					return false
				}
			}
		} else if field.IsMap() && field.MapValue().Kind() == protoreflect.MessageKind {
			value.Map().Range(func(_ protoreflect.MapKey, item protoreflect.Value) bool {
				found = rejectMessage(item.Message())
				return found == nil
			})
		} else if message.Has(field) {
			found = rejectMessage(value.Message())
		}
		return found == nil
	})
	return found
}
