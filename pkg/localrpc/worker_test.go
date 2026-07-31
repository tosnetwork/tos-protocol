package localrpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
)

type testWorkerService struct {
	health       func(context.Context) (*edgev1.HealthResponse, error)
	capabilities func(context.Context) (*edgev1.GetCapabilitiesResponse, error)
	quote        func(context.Context, *edgev1.QuoteRequest) (*edgev1.QuoteResponse, error)
	invoke       func(context.Context, *edgev1.InvokeRequest) (*edgev1.InvokeResponse, error)
	cancel       func(context.Context, *edgev1.CancelRequest) (*edgev1.CancelResponse, error)
}

func (s *testWorkerService) Health(
	ctx context.Context,
	_ *connect.Request[edgev1.HealthRequest],
) (*connect.Response[edgev1.HealthResponse], error) {
	if s.health == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("Health"))
	}
	response, err := s.health(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *testWorkerService) GetCapabilities(
	ctx context.Context,
	_ *connect.Request[edgev1.GetCapabilitiesRequest],
) (*connect.Response[edgev1.GetCapabilitiesResponse], error) {
	if s.capabilities == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("GetCapabilities"))
	}
	response, err := s.capabilities(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *testWorkerService) Quote(
	ctx context.Context,
	request *connect.Request[edgev1.QuoteRequest],
) (*connect.Response[edgev1.QuoteResponse], error) {
	if s.quote == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("Quote"))
	}
	response, err := s.quote(ctx, request.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *testWorkerService) Invoke(
	ctx context.Context,
	request *connect.Request[edgev1.InvokeRequest],
) (*connect.Response[edgev1.InvokeResponse], error) {
	if s.invoke == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("Invoke"))
	}
	response, err := s.invoke(ctx, request.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *testWorkerService) Cancel(
	ctx context.Context,
	request *connect.Request[edgev1.CancelRequest],
) (*connect.Response[edgev1.CancelResponse], error) {
	if s.cancel == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, errors.New("Cancel"))
	}
	response, err := s.cancel(ctx, request.Msg)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func TestWorkerClientValidatesPrivateRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	service := &testWorkerService{
		health: func(context.Context) (*edgev1.HealthResponse, error) {
			return &edgev1.HealthResponse{Status: "ready", Version: "test-v1"}, nil
		},
		capabilities: func(context.Context) (*edgev1.GetCapabilitiesResponse, error) {
			return &edgev1.GetCapabilitiesResponse{
				CapacityRevision: "capacity-v1",
				Capabilities: []*edgev1.Capability{{
					ServiceId: "tos.ai.mock", Operation: "generate",
					Model:       "deterministic-echo",
					ModelDigest: "sha256:" + strings.Repeat("a", 64),
					Runtime:     "mock", RuntimeRevision: "mock-v1",
					MaxInputBytes: 1024, MaxOutputBytes: 1024,
					AcceptedPriorities: []edgev1.Priority{
						edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
					},
				}},
			}, nil
		},
		quote: func(
			_ context.Context,
			request *edgev1.QuoteRequest,
		) (*edgev1.QuoteResponse, error) {
			return &edgev1.QuoteResponse{
				QuoteId: "quote-0001", RequestId: request.RequestId,
				ExpiresUnixMillis: now.Add(time.Minute).UnixMilli(),
				CapacityRevision:  "capacity-v1",
				ModelRevision:     "sha256:" + strings.Repeat("a", 64),
				RuntimeRevision:   "mock-v1",
			}, nil
		},
		invoke: func(
			_ context.Context,
			request *edgev1.InvokeRequest,
		) (*edgev1.InvokeResponse, error) {
			output := append([]byte("echo:"), request.Payload...)
			return &edgev1.InvokeResponse{
				RequestId: request.RequestId, Output: output,
				Usage: &edgev1.Usage{
					InputBytes: uint64(len(request.Payload)), OutputBytes: uint64(len(output)),
				},
				ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "mock-v1",
			}, nil
		},
		cancel: func(
			context.Context,
			*edgev1.CancelRequest,
		) (*edgev1.CancelResponse, error) {
			return &edgev1.CancelResponse{Accepted: true}, nil
		},
	}
	client := startWorkerClient(t, service, DefaultWorkerMaxMessageBytes)

	if _, err := client.Health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetCapabilities(context.Background()); err != nil {
		t.Fatal(err)
	}
	quoteRequest := validQuoteRequest(now)
	quote, err := client.Quote(context.Background(), quoteRequest)
	if err != nil {
		t.Fatal(err)
	}
	invokeRequest := validInvokeRequest(now)
	invokeRequest.QuoteId = quote.QuoteId
	response, err := client.Invoke(context.Background(), invokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Output) != "echo:hello" {
		t.Fatalf("unexpected output %q", response.Output)
	}
	accepted, err := client.Cancel(context.Background(), invokeRequest.RequestId)
	if err != nil || !accepted {
		t.Fatalf("cancel accepted=%v err=%v", accepted, err)
	}
}

func TestWorkerClientRejectsPriorityEscalationBeforeRPC(t *testing.T) {
	var calls atomic.Int32
	service := &testWorkerService{
		quote: func(
			context.Context,
			*edgev1.QuoteRequest,
		) (*edgev1.QuoteResponse, error) {
			calls.Add(1)
			return nil, errors.New("unexpected call")
		},
	}
	client := startWorkerClient(t, service, DefaultWorkerMaxMessageBytes)
	request := validQuoteRequest(time.Now())
	request.Priority = edgev1.Priority_PRIORITY_CONTROL
	if _, err := client.Quote(context.Background(), request); err == nil {
		t.Fatal("priority escalation accepted")
	}
	if calls.Load() != 0 {
		t.Fatalf("rejected request reached worker %d times", calls.Load())
	}
}

func TestWorkerClientRejectsSubstitutedOrInconsistentResponses(t *testing.T) {
	now := time.Now().UTC()
	service := &testWorkerService{
		quote: func(
			context.Context,
			*edgev1.QuoteRequest,
		) (*edgev1.QuoteResponse, error) {
			return &edgev1.QuoteResponse{
				QuoteId: "quote-0001", RequestId: "request-other",
				ExpiresUnixMillis: now.Add(time.Minute).UnixMilli(),
				CapacityRevision:  "capacity-v1", ModelRevision: "model-v1",
				RuntimeRevision: "runtime-v1",
			}, nil
		},
		invoke: func(
			_ context.Context,
			request *edgev1.InvokeRequest,
		) (*edgev1.InvokeResponse, error) {
			return &edgev1.InvokeResponse{
				RequestId: request.RequestId, Output: []byte("too large"),
				Usage: &edgev1.Usage{
					InputBytes: uint64(len(request.Payload)), OutputBytes: 1,
				},
				ModelRevision: "model-v1", RuntimeRevision: "runtime-v1",
			}, nil
		},
	}
	client := startWorkerClient(t, service, DefaultWorkerMaxMessageBytes)
	if _, err := client.Quote(
		context.Background(), validQuoteRequest(now),
	); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("substituted Quote response accepted: %v", err)
	}
	if _, err := client.Invoke(
		context.Background(), validInvokeRequest(now),
	); err == nil || !strings.Contains(err.Error(), "accounting mismatch") {
		t.Fatalf("inconsistent Invoke response accepted: %v", err)
	}
}

func TestWorkerClientEnforcesMessageAndSocketSecurity(t *testing.T) {
	service := &testWorkerService{
		health: func(context.Context) (*edgev1.HealthResponse, error) {
			return &edgev1.HealthResponse{
				Status: strings.Repeat("x", 4096), Version: "test-v1",
			}, nil
		},
	}
	socketPath, stop := startWorkerServer(t, service)
	defer stop()
	config := DefaultWorkerClientConfig(socketPath)
	config.MaxMessageBytes = 1024
	client, err := NewWorkerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Health(context.Background()); err == nil {
		t.Fatal("oversized worker response accepted")
	}

	insecurePath, insecureStop := startWorkerServer(t, &testWorkerService{
		health: func(context.Context) (*edgev1.HealthResponse, error) {
			return &edgev1.HealthResponse{Status: "ready", Version: "test-v1"}, nil
		},
	})
	defer insecureStop()
	if err := os.Chmod(insecurePath, 0o660); err != nil {
		t.Fatal(err)
	}
	insecureClient, err := NewWorkerClient(DefaultWorkerClientConfig(insecurePath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := insecureClient.Health(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "private socket") {
		t.Fatalf("insecure socket accepted: %v", err)
	}
}

func TestWorkerClientBoundsControlTimeAndDoesNotRetry(t *testing.T) {
	var calls atomic.Int32
	service := &testWorkerService{
		health: func(ctx context.Context) (*edgev1.HealthResponse, error) {
			<-ctx.Done()
			return nil, connect.NewError(connect.CodeDeadlineExceeded, ctx.Err())
		},
		quote: func(
			context.Context,
			*edgev1.QuoteRequest,
		) (*edgev1.QuoteResponse, error) {
			calls.Add(1)
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("offline"))
		},
	}
	socketPath, stop := startWorkerServer(t, service)
	defer stop()
	config := DefaultWorkerClientConfig(socketPath)
	config.ControlTimeout = 50 * time.Millisecond
	client, err := NewWorkerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := client.Health(context.Background()); err == nil {
		t.Fatal("worker control timeout ignored")
	}
	if time.Since(started) > time.Second {
		t.Fatal("worker control timeout was not bounded")
	}
	if _, err := client.Quote(
		context.Background(), validQuoteRequest(time.Now()),
	); err == nil {
		t.Fatal("worker failure ignored")
	}
	if calls.Load() != 1 {
		t.Fatalf("worker call retried %d times", calls.Load())
	}
}

func startWorkerClient(
	t *testing.T,
	service edgev1connect.WorkerServiceHandler,
	maxMessageBytes int,
) *WorkerClient {
	t.Helper()
	socketPath, stop := startWorkerServer(t, service)
	t.Cleanup(stop)
	config := DefaultWorkerClientConfig(socketPath)
	config.MaxMessageBytes = maxMessageBytes
	client, err := NewWorkerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func startWorkerServer(
	t *testing.T,
	service edgev1connect.WorkerServiceHandler,
) (string, func()) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "worker.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		t.Fatal(err)
	}
	path, handler := edgev1connect.NewWorkerServiceHandler(
		service,
		connect.WithReadMaxBytes(DefaultWorkerMaxMessageBytes),
		connect.WithSendMaxBytes(DefaultWorkerMaxMessageBytes),
	)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := &http.Server{Handler: mux}
	go func() {
		_ = server.Serve(listener)
	}()
	var stopped atomic.Bool
	return socketPath, func() {
		if stopped.CompareAndSwap(false, true) {
			_ = server.Close()
			_ = listener.Close()
			_ = os.Remove(socketPath)
		}
	}
}

func validQuoteRequest(now time.Time) *edgev1.QuoteRequest {
	return &edgev1.QuoteRequest{
		RequestId: "request-0001", ServiceId: "tos.ai.mock",
		Operation: "generate", Model: "deterministic-echo",
		InputBytes: 5, MaxOutputBytes: 1024,
		DeadlineUnixMillis: now.Add(2 * time.Minute).UnixMilli(),
		Priority:           edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
}

func validInvokeRequest(now time.Time) *edgev1.InvokeRequest {
	return &edgev1.InvokeRequest{
		RequestId: "request-0001", QuoteId: "quote-0001",
		ServiceId: "tos.ai.mock", Operation: "generate",
		Model: "deterministic-echo", Payload: []byte("hello"),
		MaxOutputBytes:     1024,
		DeadlineUnixMillis: now.Add(2 * time.Minute).UnixMilli(),
		Priority:           edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
}
