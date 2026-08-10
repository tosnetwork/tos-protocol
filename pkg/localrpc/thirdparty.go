package localrpc

import (
	"context"
	"errors"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
)

// ThirdPartyWorkerClientConfig configures a ThirdPartyWorkerClient. It
// deliberately targets the same private Unix-socket boundary as
// WorkerClient (SocketPath) -- ThirdPartyExecutionService and WorkerService
// are two RPC services exposed by the same worker process, per
// tos.edge.v1.worker.proto's own doc comment.
type ThirdPartyWorkerClientConfig struct {
	SocketPath      string
	ControlTimeout  time.Duration
	MaxCallDuration time.Duration
	MaxMessageBytes int
}

func DefaultThirdPartyWorkerClientConfig(socketPath string) ThirdPartyWorkerClientConfig {
	return ThirdPartyWorkerClientConfig{
		SocketPath:      socketPath,
		ControlTimeout:  DefaultWorkerControlTimeout,
		MaxCallDuration: DefaultWorkerMaxInvocationDuration,
		MaxMessageBytes: DefaultWorkerMaxMessageBytes,
	}
}

// ThirdPartyWorkerClient is the Edge Core -> private ThirdPartyExecutionService
// client. Like WorkerClient, it performs no retries: Edge Core and the
// durable request journal own idempotency. Unlike WorkerClient's Invoke/
// GetTask/Cancel, responses are not wrapped in a validation type -- there is
// no model-digest/runtime-binding concept for a third-party endpoint to
// substitute; the caller (atosrpc) checks the returned request_id matches
// what it asked for, the same way provideradapter.ProviderAdapter's Go
// implementations were checked by their own callers.
type ThirdPartyWorkerClient struct {
	rpc             edgev1connect.ThirdPartyExecutionServiceClient
	controlTimeout  time.Duration
	maxCallDuration time.Duration
}

func NewThirdPartyWorkerClient(config ThirdPartyWorkerClientConfig) (*ThirdPartyWorkerClient, error) {
	if config.ControlTimeout <= 0 || config.ControlTimeout > maxWorkerControlTimeout ||
		config.MaxCallDuration <= 0 || config.MaxCallDuration > maxWorkerInvocationDuration ||
		config.MaxMessageBytes <= 0 || config.MaxMessageBytes > maxWorkerMessageBytes {
		return nil, errors.New("invalid third-party worker client configuration")
	}
	client, err := httpClient(config.SocketPath, config.ControlTimeout, config.MaxCallDuration)
	if err != nil {
		return nil, err
	}
	rpc := edgev1connect.NewThirdPartyExecutionServiceClient(
		client, "http://unix",
		connect.WithReadMaxBytes(config.MaxMessageBytes),
		connect.WithSendMaxBytes(config.MaxMessageBytes),
	)
	return &ThirdPartyWorkerClient{rpc: rpc, controlTimeout: config.ControlTimeout, maxCallDuration: config.MaxCallDuration}, nil
}

func (c *ThirdPartyWorkerClient) Health(ctx context.Context, req *edgev1.ThirdPartyHealthRequest) (*edgev1.ThirdPartyHealthResponse, error) {
	callContext, cancel := context.WithTimeout(ctx, c.controlTimeout)
	defer cancel()
	resp, err := c.rpc.Health(callContext, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *ThirdPartyWorkerClient) Invoke(ctx context.Context, req *edgev1.ThirdPartyInvokeRequest) (*edgev1.ThirdPartyInvokeResponse, error) {
	callContext, cancel := context.WithTimeout(ctx, c.maxCallDuration)
	defer cancel()
	resp, err := c.rpc.Invoke(callContext, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *ThirdPartyWorkerClient) Query(ctx context.Context, req *edgev1.ThirdPartyQueryRequest) (*edgev1.ThirdPartyQueryResponse, error) {
	callContext, cancel := context.WithTimeout(ctx, c.controlTimeout)
	defer cancel()
	resp, err := c.rpc.Query(callContext, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}

func (c *ThirdPartyWorkerClient) Cancel(ctx context.Context, req *edgev1.ThirdPartyCancelRequest) (*edgev1.ThirdPartyCancelResponse, error) {
	callContext, cancel := context.WithTimeout(ctx, c.controlTimeout)
	defer cancel()
	resp, err := c.rpc.Cancel(callContext, connect.NewRequest(req))
	if err != nil {
		return nil, err
	}
	return resp.Msg, nil
}
