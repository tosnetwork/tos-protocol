package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
)

type worker struct{}

var thirdPartyResults = map[string]*edgev1.ThirdPartyInvokeResponse{}

func (*worker) Health(context.Context, *connect.Request[edgev1.HealthRequest]) (*connect.Response[edgev1.HealthResponse], error) {
	components := make([]*edgev1.ReadinessComponent, 0, 6)
	for _, id := range []string{"worker", "admission", "resources", "runtimes", "model-binding", "task-store"} {
		components = append(components, &edgev1.ReadinessComponent{Id: id, Status: edgev1.ReadinessStatus_READINESS_STATUS_READY})
	}
	return connect.NewResponse(&edgev1.HealthResponse{Status: "ready", Version: "phase4b2-localnet", Readiness: components}), nil
}

func (*worker) GetCapabilities(context.Context, *connect.Request[edgev1.GetCapabilitiesRequest]) (*connect.Response[edgev1.GetCapabilitiesResponse], error) {
	now := time.Now().UTC()
	return connect.NewResponse(&edgev1.GetCapabilitiesResponse{CapacityRevision: "localnet-capacity-v1", TerminalRevision: "localnet-terminal-v1", CollectedUnixMillis: now.UnixMilli(), ExpiresUnixMillis: now.Add(time.Minute).UnixMilli()}), nil
}

func (*worker) Quote(_ context.Context, request *connect.Request[edgev1.QuoteRequest]) (*connect.Response[edgev1.QuoteResponse], error) {
	now := time.Now().UTC()
	return connect.NewResponse(&edgev1.QuoteResponse{QuoteId: "localnet-" + request.Msg.RequestId, RequestId: request.Msg.RequestId, ExpiresUnixMillis: now.Add(time.Minute).UnixMilli(), CapacityRevision: "localnet-capacity-v1", ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "localnet-runtime-v1"}), nil
}

func (*worker) Invoke(_ context.Context, request *connect.Request[edgev1.InvokeRequest]) (*connect.Response[edgev1.InvokeResponse], error) {
	now := time.Now().UTC()
	return connect.NewResponse(&edgev1.InvokeResponse{RequestId: request.Msg.RequestId, Output: append([]byte("localnet:"), request.Msg.Payload...), Usage: &edgev1.Usage{InputBytes: uint64(len(request.Msg.Payload)), OutputBytes: uint64(len(request.Msg.Payload) + 9)}, ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "localnet-runtime-v1", CompletedUnixMillis: now.UnixMilli()}), nil
}

func (*worker) GetTask(context.Context, *connect.Request[edgev1.GetTaskRequest]) (*connect.Response[edgev1.GetTaskResponse], error) {
	return nil, connect.NewError(connect.CodeNotFound, errors.New("task not found"))
}

func (*worker) Cancel(_ context.Context, request *connect.Request[edgev1.CancelRequest]) (*connect.Response[edgev1.CancelResponse], error) {
	return connect.NewResponse(&edgev1.CancelResponse{RequestId: request.Msg.RequestId, TaskId: request.Msg.TaskId, RequestDigest: request.Msg.RequestDigest, Accepted: true}), nil
}

func (*worker) HealthThirdParty(context.Context, *connect.Request[edgev1.ThirdPartyHealthRequest]) (*connect.Response[edgev1.ThirdPartyHealthResponse], error) {
	return connect.NewResponse(&edgev1.ThirdPartyHealthResponse{Healthy: true, DeepProbe: true, Evidence: map[string]string{"localnet": "true"}}), nil
}

type thirdPartyWorker struct{}

func (*thirdPartyWorker) Health(ctx context.Context, r *connect.Request[edgev1.ThirdPartyHealthRequest]) (*connect.Response[edgev1.ThirdPartyHealthResponse], error) {
	return (&worker{}).HealthThirdParty(ctx, r)
}
func (*thirdPartyWorker) Invoke(_ context.Context, r *connect.Request[edgev1.ThirdPartyInvokeRequest]) (*connect.Response[edgev1.ThirdPartyInvokeResponse], error) {
	if result := thirdPartyResults[r.Msg.RequestId]; result != nil {
		return connect.NewResponse(result), nil
	}
	result := &edgev1.ThirdPartyInvokeResponse{RequestId: r.Msg.RequestId, Status: edgev1.ThirdPartyInvokeStatus_THIRD_PARTY_INVOKE_STATUS_COMPLETED, Output: append([]byte("localnet:"), r.Msg.Input...), CompletedUnixMillis: time.Now().UTC().UnixMilli(), Usage: &edgev1.Usage{InputBytes: uint64(len(r.Msg.Input)), OutputBytes: uint64(len(r.Msg.Input) + 9)}}
	thirdPartyResults[r.Msg.RequestId] = result
	return connect.NewResponse(result), nil
}
func (*thirdPartyWorker) Query(_ context.Context, r *connect.Request[edgev1.ThirdPartyQueryRequest]) (*connect.Response[edgev1.ThirdPartyQueryResponse], error) {
	result := thirdPartyResults[r.Msg.RequestId]
	return connect.NewResponse(&edgev1.ThirdPartyQueryResponse{Found: result != nil, Result: result}), nil
}
func (*thirdPartyWorker) Cancel(context.Context, *connect.Request[edgev1.ThirdPartyCancelRequest]) (*connect.Response[edgev1.ThirdPartyCancelResponse], error) {
	return connect.NewResponse(&edgev1.ThirdPartyCancelResponse{Accepted: true}), nil
}

func main() {
	socket := flag.String("socket", "", "Unix socket path")
	flag.Parse()
	if *socket == "" {
		panic("-socket is required")
	}
	listener, err := net.Listen("unix", *socket)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	if err := os.Chmod(*socket, 0o600); err != nil {
		panic(err)
	}
	path, handler := edgev1connect.NewWorkerServiceHandler(&worker{})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	thirdPartyPath, thirdPartyHandler := edgev1connect.NewThirdPartyExecutionServiceHandler(&thirdPartyWorker{})
	mux.Handle(thirdPartyPath, thirdPartyHandler)
	if err := (&http.Server{Handler: mux}).Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		panic(err)
	}
}
