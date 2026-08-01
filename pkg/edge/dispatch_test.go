package edge

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type dispatchWorker struct {
	edgev1connect.UnimplementedWorkerServiceHandler
	invokeCalls atomic.Int32
	getCalls    atomic.Int32
	cancelCalls atomic.Int32
	invokeError bool
	cancelError bool
	cancel      bool
	getStatus   edgev1.TaskStatus
	output      []byte
	completedAt atomic.Int64
	healthError atomic.Bool
}

func (w *dispatchWorker) Health(
	context.Context,
	*connect.Request[edgev1.HealthRequest],
) (*connect.Response[edgev1.HealthResponse], error) {
	if w.healthError.Load() {
		return nil, connect.NewError(
			connect.CodeUnavailable, errors.New("simulated Worker degradation"),
		)
	}
	return connect.NewResponse(&edgev1.HealthResponse{
		Status: "ready", Version: "test-v1",
		Readiness: dispatchReadyComponents(),
	}), nil
}

func dispatchReadyComponents() []*edgev1.ReadinessComponent {
	components := make([]*edgev1.ReadinessComponent, 0, 6)
	for _, id := range []string{
		"worker", "admission", "resources", "runtimes", "model-binding",
		"task-store",
	} {
		components = append(components, &edgev1.ReadinessComponent{
			Id: id, Status: edgev1.ReadinessStatus_READINESS_STATUS_READY,
		})
	}
	return components
}

func (w *dispatchWorker) Invoke(
	_ context.Context,
	request *connect.Request[edgev1.InvokeRequest],
) (*connect.Response[edgev1.InvokeResponse], error) {
	w.invokeCalls.Add(1)
	if w.invokeError {
		return nil, connect.NewError(
			connect.CodeUnavailable,
			errors.New("simulated ambiguous worker failure"),
		)
	}
	completedAt := time.Now().UTC().Truncate(time.Millisecond).UnixMilli()
	w.completedAt.CompareAndSwap(0, completedAt)
	response := dispatchInvokeResponse(request.Msg, w.output)
	response.CompletedUnixMillis = w.completedAt.Load()
	return connect.NewResponse(response), nil
}

func (w *dispatchWorker) GetTask(
	_ context.Context,
	request *connect.Request[edgev1.GetTaskRequest],
) (*connect.Response[edgev1.GetTaskResponse], error) {
	w.getCalls.Add(1)
	response := &edgev1.GetTaskResponse{
		RequestId: request.Msg.RequestId, TaskId: request.Msg.TaskId,
		RequestDigest: request.Msg.RequestDigest, Status: w.getStatus,
	}
	switch w.getStatus {
	case edgev1.TaskStatus_TASK_STATUS_NOT_FOUND:
	case edgev1.TaskStatus_TASK_STATUS_ACCEPTED,
		edgev1.TaskStatus_TASK_STATUS_RUNNING:
		response.RetainUntilUnixMillis = request.Msg.RetainUntilUnixMillis
	case edgev1.TaskStatus_TASK_STATUS_SUCCEEDED:
		response.Result = dispatchInvokeResponse(
			&edgev1.InvokeRequest{
				RequestId: request.Msg.RequestId, Payload: []byte("input"),
			},
			w.output,
		)
		response.CompletedUnixMillis = w.completedAt.Load()
		if response.CompletedUnixMillis == 0 {
			response.CompletedUnixMillis = time.Now().UTC().Truncate(
				time.Millisecond,
			).UnixMilli()
		}
		response.Result.CompletedUnixMillis = response.CompletedUnixMillis
		response.RetainUntilUnixMillis = request.Msg.RetainUntilUnixMillis
	case edgev1.TaskStatus_TASK_STATUS_FAILED,
		edgev1.TaskStatus_TASK_STATUS_CANCELED:
		if w.getStatus == edgev1.TaskStatus_TASK_STATUS_FAILED {
			response.ErrorCode = string(protocol.ErrorRuntimeFailed)
		} else {
			response.ErrorCode = string(protocol.ErrorCanceled)
		}
		response.CompletedUnixMillis = time.Now().UTC().Truncate(
			time.Millisecond,
		).UnixMilli()
		response.RetainUntilUnixMillis = request.Msg.RetainUntilUnixMillis
	default:
		return nil, connect.NewError(
			connect.CodeInternal,
			errors.New("unsupported dispatch test status"),
		)
	}
	return connect.NewResponse(response), nil
}

func (w *dispatchWorker) Cancel(
	_ context.Context,
	request *connect.Request[edgev1.CancelRequest],
) (*connect.Response[edgev1.CancelResponse], error) {
	w.cancelCalls.Add(1)
	if w.cancelError {
		return nil, connect.NewError(
			connect.CodeUnavailable,
			errors.New("ambiguous cancellation failure"),
		)
	}
	return connect.NewResponse(&edgev1.CancelResponse{
		RequestId: request.Msg.RequestId, TaskId: request.Msg.TaskId,
		RequestDigest: request.Msg.RequestDigest, Accepted: w.cancel,
	}), nil
}

func dispatchInvokeResponse(
	request *edgev1.InvokeRequest,
	output []byte,
) *edgev1.InvokeResponse {
	return &edgev1.InvokeResponse{
		RequestId: request.RequestId,
		Output:    append([]byte(nil), output...),
		Usage: &edgev1.Usage{
			InputBytes: uint64(len(request.Payload)), OutputBytes: uint64(len(output)),
			InputTokens: 1, OutputTokens: 2, ExecutionMillis: 3,
		},
		ModelRevision:   "dispatch-model-revision-1",
		RuntimeRevision: "dispatch-runtime-revision-1",
	}
}

func TestCoreDispatchesNewClaimAndOnlyQueriesReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, _ := prepareDispatchRequest(
		t, now, "dispatch-success-0001",
	)
	defer core.Close()
	server := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("result"),
	}
	worker := startDispatchWorkerClient(t, server)
	first, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := first.Disposition()
	if err != nil || disposition != ExecutionDispatchInvoked {
		t.Fatalf("first disposition = %q, err = %v", disposition, err)
	}
	claim, err := first.Claim()
	if err != nil {
		t.Fatal(err)
	}
	if claim.Disposition != journal.ExecutionClaimed ||
		server.invokeCalls.Load() != 1 || server.getCalls.Load() != 0 {
		t.Fatalf(
			"claim = %#v, invokes = %d, gets = %d",
			claim,
			server.invokeCalls.Load(),
			server.getCalls.Load(),
		)
	}
	invocation, err := first.Invocation()
	if err != nil {
		t.Fatal(err)
	}
	completion, err := invocation.Completion(localrpc.InvocationBinding{
		RequestID: scope.RequestID, QuoteID: "quote-" + scope.RequestID,
		ServiceID: scope.ServiceID, Operation: scope.Operation,
	})
	if err != nil || string(completion.Output) != "result" {
		t.Fatalf("completion = %#v, err = %v", completion, err)
	}
	claim.Request.Payload[0] ^= 1
	unchanged, err := first.Claim()
	if err != nil || string(unchanged.Request.Payload) != "input" {
		t.Fatalf("dispatch claim aliases caller: %#v, err = %v", unchanged, err)
	}
	second, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err = second.Disposition()
	if err != nil || disposition != ExecutionDispatchRecovered ||
		server.invokeCalls.Load() != 1 || server.getCalls.Load() != 1 {
		t.Fatalf(
			"second disposition = %q, invokes = %d, gets = %d, err = %v",
			disposition,
			server.invokeCalls.Load(),
			server.getCalls.Load(),
			err,
		)
	}
	if _, err := second.Invocation(); err == nil {
		t.Fatal("recovery dispatch exposed a direct invocation")
	}
	recovered, err := second.RecoveredTask()
	if err != nil {
		t.Fatal(err)
	}
	status, err := recovered.Status()
	if err != nil || status != edgev1.TaskStatus_TASK_STATUS_SUCCEEDED {
		t.Fatalf("recovered status = %s, err = %v", status, err)
	}
	if _, err := recovered.Invocation(); err != nil {
		t.Fatalf("recovered success has no invocation: %v", err)
	}
}

func TestCoreNeverRetriesAmbiguousClaimedInvocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, _ := prepareDispatchRequest(
		t, now, "dispatch-ambiguous-0001",
	)
	defer core.Close()
	server := &dispatchWorker{
		invokeError: true,
		getStatus:   edgev1.TaskStatus_TASK_STATUS_RUNNING,
		output:      []byte("unused"),
	}
	worker := startDispatchWorkerClient(t, server)
	uncertain, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err == nil {
		t.Fatal("ambiguous Worker error was hidden")
	}
	disposition, dispositionErr := uncertain.Disposition()
	if dispositionErr != nil || disposition != ExecutionDispatchUncertain {
		t.Fatalf(
			"uncertain disposition = %q, error = %v",
			disposition,
			dispositionErr,
		)
	}
	claim, claimErr := uncertain.Claim()
	if claimErr != nil || claim.Disposition != journal.ExecutionClaimed {
		t.Fatalf("uncertain claim = %#v, error = %v", claim, claimErr)
	}
	if _, err := uncertain.Invocation(); err == nil {
		t.Fatal("uncertain dispatch exposed an invocation")
	}
	if _, err := uncertain.RecoveredTask(); err == nil {
		t.Fatal("uncertain dispatch exposed a recovered task")
	}
	server.invokeError = false
	recovered, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err = recovered.Disposition()
	if err != nil || disposition != ExecutionDispatchRecovered ||
		server.invokeCalls.Load() != 1 || server.getCalls.Load() != 1 {
		t.Fatalf(
			"disposition = %q, invokes = %d, gets = %d, err = %v",
			disposition,
			server.invokeCalls.Load(),
			server.getCalls.Load(),
			err,
		)
	}
	task, err := recovered.RecoveredTask()
	if err != nil {
		t.Fatal(err)
	}
	status, err := task.Status()
	if err != nil || status != edgev1.TaskStatus_TASK_STATUS_RUNNING {
		t.Fatalf("recovered status = %s, err = %v", status, err)
	}
}

func TestCoreTreatsRecoveredNotFoundAsObservationNotRetryPermission(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, _ := prepareDispatchRequest(
		t, now, "dispatch-not-found-0001",
	)
	defer core.Close()
	claimed, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, mappingWorkerClient(t, now),
	)
	if err != nil || claimed.Disposition != journal.ExecutionClaimed {
		t.Fatalf("pre-crash claim = %#v, err = %v", claimed, err)
	}
	server := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
	}
	worker := startDispatchWorkerClient(t, server)
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := dispatch.Disposition()
	if err != nil || disposition != ExecutionDispatchRecovered ||
		server.invokeCalls.Load() != 0 || server.getCalls.Load() != 1 {
		t.Fatalf(
			"disposition = %q, invokes = %d, gets = %d, err = %v",
			disposition,
			server.invokeCalls.Load(),
			server.getCalls.Load(),
			err,
		)
	}
	task, err := dispatch.RecoveredTask()
	if err != nil {
		t.Fatal(err)
	}
	status, err := task.Status()
	if err != nil || status != edgev1.TaskStatus_TASK_STATUS_NOT_FOUND {
		t.Fatalf("recovered status = %s, err = %v", status, err)
	}
}

func TestCoreRetainsReplayClaimWhenRecoveryPolicyRejectsLookup(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, _ := prepareDispatchRequest(
		t, now, "dispatch-policy-rejection-0001",
	)
	defer core.Close()
	claimed, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, mappingWorkerClient(t, now),
	)
	if err != nil || claimed.Disposition != journal.ExecutionClaimed {
		t.Fatalf("pre-crash claim = %#v, err = %v", claimed, err)
	}
	server := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_RUNNING,
	}
	worker := startDispatchWorkerClient(
		t,
		server,
		func(config *localrpc.WorkerClientConfig) {
			config.MaxTaskRetention = 10 * time.Minute
		},
	)
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err == nil {
		t.Fatal("recovery policy rejection was hidden")
	}
	disposition, dispositionErr := dispatch.Disposition()
	claim, claimErr := dispatch.Claim()
	if dispositionErr != nil || disposition != ExecutionDispatchUncertain ||
		claimErr != nil || claim.Disposition != journal.ExecutionReplay ||
		server.invokeCalls.Load() != 0 || server.getCalls.Load() != 0 {
		t.Fatalf(
			"disposition = %q, claim = %#v, invokes = %d, gets = %d, errors = %v/%v",
			disposition,
			claim,
			server.invokeCalls.Load(),
			server.getCalls.Load(),
			dispositionErr,
			claimErr,
		)
	}
}

func TestInvalidExecutionDispatchExposesNothing(t *testing.T) {
	var dispatch ExecutionDispatch
	if _, err := dispatch.Disposition(); err == nil {
		t.Fatal("zero dispatch exposed a disposition")
	}
	if _, err := dispatch.Claim(); err == nil {
		t.Fatal("zero dispatch exposed a claim")
	}
	if _, err := dispatch.Invocation(); err == nil {
		t.Fatal("zero dispatch exposed an invocation")
	}
	if _, err := dispatch.RecoveredTask(); err == nil {
		t.Fatal("zero dispatch exposed a recovered task")
	}
}

func prepareDispatchRequest(
	t *testing.T,
	now time.Time,
	requestID string,
) (
	*Core,
	journal.Scope,
	authorization.AuthorizedPayment,
	journal.Record,
	*ProfileInvocationPlan,
	coreSessionFixture,
) {
	t.Helper()
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCoreSessionFixture(t, now)
	intent := []byte("dispatch-intent")
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		core.Close()
		t.Fatal(err)
	}
	scope, authorized := fixture.authorizePaymentWithIntentDigest(
		t, requestID, digest,
	)
	request := applyAuthorizedPaymentForCompletion(
		t, core, scope, authorized, now,
	)
	plan, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
			Mapper: ProfileInvocationMapperFunc(func(
				context.Context,
				ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				return ProfileInvocationOutput{
					Model: "dispatch-model", Payload: []byte("input"),
				}, nil
			}),
		}},
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
		}},
	)
	if err != nil {
		core.Close()
		t.Fatal(err)
	}
	return core, scope, authorized, request, plan, fixture
}

func startDispatchWorkerClient(
	t *testing.T,
	worker *dispatchWorker,
	configure ...func(*localrpc.WorkerClientConfig),
) *localrpc.WorkerClient {
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
	path, handler := edgev1connect.NewWorkerServiceHandler(worker)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	config := localrpc.DefaultWorkerClientConfig(socketPath)
	for _, apply := range configure {
		apply(&config)
	}
	client, err := localrpc.NewWorkerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
