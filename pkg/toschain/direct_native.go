package toschain

import (
	"context"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

// NativeStateResolver is the authoritative typed-state surface required by a
// DirectNativeClient. SimplifiedNativeResolver implements it with finalized
// quorum reads from TOS nodes.
type NativeStateResolver interface {
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
}

// DirectNativeClient adapts a finalized Native state resolver to the SDK
// client interface without introducing a gateway or another authority layer.
type DirectNativeClient struct {
	resolver NativeStateResolver
	now      func() time.Time
}

func NewDirectNativeClient(resolver NativeStateResolver) (*DirectNativeClient, error) {
	if resolver == nil {
		return nil, errors.New("finalized Native state resolver is required")
	}
	return &DirectNativeClient{resolver: resolver, now: time.Now}, nil
}

func (c *DirectNativeClient) ResolveNativeState(ctx context.Context, request *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error) {
	if c == nil || c.resolver == nil || ctx == nil || request == nil || request.Context == nil ||
		request.Context.RequestId == "" || request.Context.CallerId == "" || request.ObjectId == "" {
		return nil, errors.New("complete direct Native resolution request is required")
	}
	if request.Context.DeadlineUnixMillis <= 0 || !c.now().Before(time.UnixMilli(request.Context.DeadlineUnixMillis)) {
		return nil, errors.New("direct Native resolution request deadline expired")
	}
	state, found, err := c.resolver.ResolveState(ctx, request.ObjectId, request.ExpectedTvmStateHash)
	if err != nil {
		return nil, err
	}
	return &nativev1.ResolveNativeStateResponse{Found: found, State: state}, nil
}
