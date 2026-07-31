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
	"google.golang.org/protobuf/proto"
)

type testWorkerService struct {
	health       func(context.Context) (*edgev1.HealthResponse, error)
	capabilities func(context.Context) (*edgev1.GetCapabilitiesResponse, error)
	quote        func(context.Context, *edgev1.QuoteRequest) (*edgev1.QuoteResponse, error)
	invoke       func(context.Context, *edgev1.InvokeRequest) (*edgev1.InvokeResponse, error)
	getTask      func(context.Context, *edgev1.GetTaskRequest) (*edgev1.GetTaskResponse, error)
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

func (s *testWorkerService) GetTask(
	ctx context.Context,
	request *connect.Request[edgev1.GetTaskRequest],
) (*connect.Response[edgev1.GetTaskResponse], error) {
	if s.getTask == nil {
		return nil, connect.NewError(
			connect.CodeUnimplemented,
			errors.New("GetTask"),
		)
	}
	response, err := s.getTask(ctx, request.Msg)
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
			if !workerDigestPattern.MatchString(request.RequestDigest) {
				return nil, connect.NewError(
					connect.CodeInvalidArgument,
					errors.New("missing request digest"),
				)
			}
			output := append([]byte("echo:"), request.Payload...)
			return &edgev1.InvokeResponse{
				RequestId: request.RequestId, Output: output,
				Usage: &edgev1.Usage{
					InputBytes: uint64(len(request.Payload)), OutputBytes: uint64(len(output)),
				},
				ModelRevision: "sha256:" + strings.Repeat("a", 64), RuntimeRevision: "mock-v1",
			}, nil
		},
		getTask: func(
			_ context.Context,
			request *edgev1.GetTaskRequest,
		) (*edgev1.GetTaskResponse, error) {
			output := []byte("echo:hello")
			return &edgev1.GetTaskResponse{
				RequestId: request.RequestId, TaskId: request.TaskId,
				RequestDigest: request.RequestDigest,
				Status:        edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
				Result: &edgev1.InvokeResponse{
					RequestId: request.RequestId, Output: output,
					Usage: &edgev1.Usage{
						InputBytes: 5, OutputBytes: uint64(len(output)),
					},
					ModelRevision:   "sha256:" + strings.Repeat("a", 64),
					RuntimeRevision: "mock-v1",
				},
				CompletedUnixMillis:   now.UnixMilli(),
				RetainUntilUnixMillis: request.RetainUntilUnixMillis,
			}, nil
		},
		cancel: func(
			_ context.Context,
			request *edgev1.CancelRequest,
		) (*edgev1.CancelResponse, error) {
			return &edgev1.CancelResponse{
				RequestId: request.RequestId, TaskId: request.TaskId,
				RequestDigest: request.RequestDigest, Accepted: true,
			}, nil
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
	validated, err := client.Invoke(context.Background(), invokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	response, err := validated.Completion(InvocationBinding{
		RequestID: invokeRequest.RequestId, QuoteID: invokeRequest.QuoteId,
		ServiceID: invokeRequest.ServiceId, Operation: invokeRequest.Operation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.Output) != "echo:hello" ||
		response.Usage.OutputBytes != uint64(len(response.Output)) ||
		response.TaskID != invokeRequest.TaskId {
		t.Fatalf("unexpected completion %#v", response)
	}
	expectedRequestDigest, err := InvocationRequestDigest(invokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	if response.RequestDigest != expectedRequestDigest {
		t.Fatalf(
			"request digest=%q want=%q",
			response.RequestDigest,
			expectedRequestDigest,
		)
	}
	changedRequest := proto.Clone(invokeRequest).(*edgev1.InvokeRequest)
	changedRequest.Payload = []byte("changed")
	changedDigest, err := InvocationRequestDigest(changedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if changedDigest == expectedRequestDigest {
		t.Fatal("different Worker invocation produced the same digest")
	}
	recovered, err := client.GetTask(context.Background(), invokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	recoveredCompletion, err := recovered.Completion(response.Binding)
	recoveredStatus, statusErr := recovered.Status()
	if err != nil || statusErr != nil ||
		recoveredStatus != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED ||
		string(recoveredCompletion.Output) != "echo:hello" ||
		recoveredCompletion.RequestDigest != expectedRequestDigest {
		t.Fatalf(
			"recovered=%#v completion=%#v err=%v",
			recovered,
			recoveredCompletion,
			err,
		)
	}
	response.Output[0] ^= 1
	again, err := validated.Completion(response.Binding)
	if err != nil || string(again.Output) != "echo:hello" {
		t.Fatalf("validated result was not defensive: %#v err=%v", again, err)
	}
	changed := response.Binding
	changed.RequestID = "request-other"
	if _, err := validated.Completion(changed); err == nil {
		t.Fatal("validated invocation reused for another request")
	}
	if _, err := (ValidatedInvocation{}).Completion(
		response.Binding,
	); err == nil {
		t.Fatal("zero validated invocation accepted")
	}
	accepted, err := client.Cancel(context.Background(), invokeRequest)
	if err != nil || !accepted {
		t.Fatalf("cancel accepted=%v err=%v", accepted, err)
	}
}

func TestInvocationRequestDigestVector(t *testing.T) {
	request := validInvokeRequest(time.UnixMilli(1_800_000_000_000).UTC())
	digest, err := InvocationRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "sha256:f33cec8bcad2c8ca69b30de82ae3e50f2549ae02951b36cf0a179a0cfac11ff4"
	if digest != expected {
		t.Fatalf("invocation digest=%q", digest)
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
		cancel: func(
			_ context.Context,
			request *edgev1.CancelRequest,
		) (*edgev1.CancelResponse, error) {
			return &edgev1.CancelResponse{
				RequestId: request.RequestId, TaskId: "task-substituted",
				RequestDigest: request.RequestDigest, Accepted: true,
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
	if _, err := client.Cancel(
		context.Background(), validInvokeRequest(now),
	); err == nil || !strings.Contains(err.Error(), "binding mismatch") {
		t.Fatalf("substituted Cancel response accepted: %v", err)
	}
}

func TestWorkerClientValidatesTaskRecoveryStates(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	invocation := validInvokeRequest(now.Add(-3 * time.Minute))
	var call int
	service := &testWorkerService{
		getTask: func(
			_ context.Context,
			request *edgev1.GetTaskRequest,
		) (*edgev1.GetTaskResponse, error) {
			call++
			response := &edgev1.GetTaskResponse{
				RequestId: request.RequestId, TaskId: request.TaskId,
				RequestDigest: request.RequestDigest,
			}
			switch call {
			case 1:
				response.Status = edgev1.TaskStatus_TASK_STATUS_NOT_FOUND
			case 2:
				response.Status = edgev1.TaskStatus_TASK_STATUS_ACCEPTED
				response.RetainUntilUnixMillis = request.RetainUntilUnixMillis
			case 3:
				response.Status = edgev1.TaskStatus_TASK_STATUS_RUNNING
				response.RetainUntilUnixMillis = request.RetainUntilUnixMillis
			case 4:
				response.Status = edgev1.TaskStatus_TASK_STATUS_FAILED
				response.ErrorCode = "RUNTIME_FAILED"
				response.CompletedUnixMillis = now.Add(-2 * time.Minute).UnixMilli()
				response.RetainUntilUnixMillis = request.RetainUntilUnixMillis
			case 5:
				response.Status = edgev1.TaskStatus_TASK_STATUS_CANCELED
				response.ErrorCode = "CANCELED"
				response.CompletedUnixMillis = now.Add(-time.Minute).UnixMilli()
				response.RetainUntilUnixMillis = request.RetainUntilUnixMillis
			case 6:
				response.Status = edgev1.TaskStatus_TASK_STATUS_TIMED_OUT
				response.ErrorCode = "DEADLINE_EXCEEDED"
				response.CompletedUnixMillis = invocation.DeadlineUnixMillis
				response.RetainUntilUnixMillis = request.RetainUntilUnixMillis
			default:
				return nil, errors.New("unexpected task lookup")
			}
			return response, nil
		},
	}
	client := startWorkerClient(t, service, DefaultWorkerMaxMessageBytes)
	for _, expected := range []edgev1.TaskStatus{
		edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
		edgev1.TaskStatus_TASK_STATUS_ACCEPTED,
		edgev1.TaskStatus_TASK_STATUS_RUNNING,
		edgev1.TaskStatus_TASK_STATUS_FAILED,
		edgev1.TaskStatus_TASK_STATUS_CANCELED,
		edgev1.TaskStatus_TASK_STATUS_TIMED_OUT,
	} {
		recovered, err := client.GetTask(context.Background(), invocation)
		if err != nil {
			t.Fatal(err)
		}
		status, err := recovered.Status()
		if err != nil || status != expected {
			t.Fatalf("task status=%v want=%v err=%v", status, expected, err)
		}
		errorCode, err := recovered.ErrorCode()
		if err != nil || errorCode != taskStatusErrorCode(expected) {
			t.Fatalf(
				"task error=%q want=%q err=%v",
				errorCode,
				taskStatusErrorCode(expected),
				err,
			)
		}
		retainUntil, err := recovered.RetainUntil()
		if err != nil {
			t.Fatal(err)
		}
		if expected == edgev1.TaskStatus_TASK_STATUS_NOT_FOUND {
			if !retainUntil.IsZero() {
				t.Fatalf("not-found task retained until %v", retainUntil)
			}
		} else if retainUntil.UnixMilli() != invocation.RetainUntilUnixMillis {
			t.Fatalf("task retention=%v", retainUntil)
		}
		if _, err := recovered.Invocation(); err == nil {
			t.Fatalf("non-success status %v exposed an invocation", expected)
		}
	}
	if call != 6 {
		t.Fatalf("task lookups=%d", call)
	}
	if _, err := (RecoveredTask{}).Status(); err == nil {
		t.Fatal("zero recovered task exposed a status")
	}
}

func TestWorkerClientRejectsInvalidTaskRecovery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	invocation := validInvokeRequest(now)
	tests := []struct {
		name     string
		response func(*edgev1.GetTaskRequest) *edgev1.GetTaskResponse
	}{
		{
			name: "binding substitution",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: "task-substituted",
					RequestDigest: request.RequestDigest,
					Status:        edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
				}
			},
		},
		{
			name: "success without result",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: request.TaskId,
					RequestDigest:         request.RequestDigest,
					Status:                edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
					CompletedUnixMillis:   now.UnixMilli(),
					RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
				}
			},
		},
		{
			name: "unbounded retention",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: request.TaskId,
					RequestDigest:         request.RequestDigest,
					Status:                edgev1.TaskStatus_TASK_STATUS_RUNNING,
					RetainUntilUnixMillis: now.Add(8 * 24 * time.Hour).UnixMilli(),
				}
			},
		},
		{
			name: "shortened retention",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: request.TaskId,
					RequestDigest:         request.RequestDigest,
					Status:                edgev1.TaskStatus_TASK_STATUS_RUNNING,
					RetainUntilUnixMillis: now.Add(10 * time.Minute).UnixMilli(),
				}
			},
		},
		{
			name: "early timeout",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: request.TaskId,
					RequestDigest:         request.RequestDigest,
					Status:                edgev1.TaskStatus_TASK_STATUS_TIMED_OUT,
					ErrorCode:             "DEADLINE_EXCEEDED",
					CompletedUnixMillis:   now.UnixMilli(),
					RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
				}
			},
		},
		{
			name: "status error substitution",
			response: func(request *edgev1.GetTaskRequest) *edgev1.GetTaskResponse {
				return &edgev1.GetTaskResponse{
					RequestId: request.RequestId, TaskId: request.TaskId,
					RequestDigest:         request.RequestDigest,
					Status:                edgev1.TaskStatus_TASK_STATUS_FAILED,
					ErrorCode:             "CANCELED",
					CompletedUnixMillis:   now.UnixMilli(),
					RetainUntilUnixMillis: request.RetainUntilUnixMillis,
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &testWorkerService{
				getTask: func(
					_ context.Context,
					request *edgev1.GetTaskRequest,
				) (*edgev1.GetTaskResponse, error) {
					return test.response(request), nil
				},
			}
			client := startWorkerClient(
				t,
				service,
				DefaultWorkerMaxMessageBytes,
			)
			if _, err := client.GetTask(
				context.Background(), invocation,
			); err == nil {
				t.Fatal("invalid Worker task recovery accepted")
			}
		})
	}

	var calls atomic.Int32
	service := &testWorkerService{
		getTask: func(
			context.Context,
			*edgev1.GetTaskRequest,
		) (*edgev1.GetTaskResponse, error) {
			calls.Add(1)
			return nil, errors.New("unexpected call")
		},
	}
	client := startWorkerClient(t, service, DefaultWorkerMaxMessageBytes)
	changedDigest := validInvokeRequest(now)
	changedDigest.RequestDigest = "sha256:" + strings.Repeat("0", 64)
	if _, err := client.GetTask(
		context.Background(), changedDigest,
	); err == nil || calls.Load() != 0 {
		t.Fatalf("changed digest err=%v calls=%d", err, calls.Load())
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
	invalidRetention := config
	invalidRetention.MaxTaskRetention = MaximumWorkerTaskRetention + time.Second
	if _, err := NewWorkerClient(invalidRetention); err == nil {
		t.Fatal("unbounded Worker task retention accepted")
	}
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
		TaskId:    "task-request-0001",
		ServiceId: "tos.ai.mock", Operation: "generate",
		Model: "deterministic-echo", Payload: []byte("hello"),
		MaxOutputBytes:        1024,
		DeadlineUnixMillis:    now.Add(2 * time.Minute).UnixMilli(),
		RetainUntilUnixMillis: now.Add(time.Hour).UnixMilli(),
		Priority:              edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
}
