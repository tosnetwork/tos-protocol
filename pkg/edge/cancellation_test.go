package edge

import (
	"context"
	"errors"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
)

func TestCoreCancelsOnlyExactRunningDispatch(t *testing.T) {
	tests := []struct {
		name     string
		accepted bool
		expected ExecutionCancellationDisposition
	}{
		{
			name: "accepted", accepted: true,
			expected: ExecutionCancellationAccepted,
		},
		{
			name: "rejected", accepted: false,
			expected: ExecutionCancellationRejected,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			core, scope, authorized, request, registry, _ := prepareDispatchRequest(
				t, now, "cancellation-"+test.name+"-0001",
			)
			defer core.Close()
			if _, err := core.MapAndClaimRegisteredPaidExecution(
				context.Background(), scope, request.Revision, authorized,
				[]byte("dispatch-intent"), registry, mappingWorkerClient(t, now),
			); err != nil {
				t.Fatal(err)
			}
			server := &dispatchWorker{
				getStatus: edgev1.TaskStatus_TASK_STATUS_RUNNING,
				cancel:    test.accepted,
			}
			worker := startDispatchWorkerClient(t, server)
			dispatch, err := core.DispatchRegisteredPaidExecution(
				context.Background(), scope, request.Revision, authorized,
				[]byte("dispatch-intent"), registry, worker,
			)
			if err != nil {
				t.Fatal(err)
			}
			canceled, err := core.CancelExecutionDispatch(
				context.Background(), dispatch, worker,
			)
			if err != nil {
				t.Fatal(err)
			}
			disposition, err := canceled.Disposition()
			claim, claimErr := canceled.Claim()
			if err != nil || claimErr != nil || disposition != test.expected ||
				claim.Execution.TaskID == "" || server.cancelCalls.Load() != 1 {
				t.Fatalf(
					"disposition=%q claim=%#v calls=%d errors=%v/%v",
					disposition, claim, server.cancelCalls.Load(), err, claimErr,
				)
			}
			claim.Request.Payload[0] ^= 1
			unchanged, err := canceled.Claim()
			if err != nil || string(unchanged.Request.Payload) != "input" {
				t.Fatalf("cancellation claim aliases caller: %#v, err=%v", unchanged, err)
			}
			state, err := core.Request(scope)
			if err != nil || state.State != journal.StateRunning {
				t.Fatalf("cancellation changed journal: %#v, err=%v", state, err)
			}
			if _, err := core.Receipt(scope); !errors.Is(err, journal.ErrNotFound) {
				t.Fatalf("cancellation created receipt: %v", err)
			}
		})
	}
}

func TestCoreRetainsClaimWhenCancellationIsUncertain(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, _ := prepareDispatchRequest(
		t, now, "cancellation-uncertain-0001",
	)
	defer core.Close()
	server := &dispatchWorker{invokeError: true, cancelError: true}
	worker := startDispatchWorkerClient(t, server)
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err == nil {
		t.Fatal("ambiguous invocation did not fail")
	}
	canceled, err := core.CancelExecutionDispatch(
		context.Background(), dispatch, worker,
	)
	if err == nil {
		t.Fatal("ambiguous cancellation did not fail")
	}
	disposition, dispositionErr := canceled.Disposition()
	claim, claimErr := canceled.Claim()
	if dispositionErr != nil || claimErr != nil ||
		disposition != ExecutionCancellationUncertain ||
		claim.Execution.TaskID == "" || server.cancelCalls.Load() != 1 {
		t.Fatalf(
			"disposition=%q claim=%#v calls=%d errors=%v/%v/%v",
			disposition, claim, server.cancelCalls.Load(),
			err, dispositionErr, claimErr,
		)
	}
}

func TestCoreRejectsCancellationOfTerminalOrStaleDispatch(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, fixture := prepareDispatchRequest(
		t, now, "cancellation-terminal-0001",
	)
	defer core.Close()
	server := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("done"), cancel: true,
	}
	worker := startDispatchWorkerClient(t, server)
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.CancelExecutionDispatch(
		context.Background(), dispatch, worker,
	); err == nil {
		t.Fatal("directly completed dispatch was canceled")
	}
	if server.cancelCalls.Load() != 0 {
		t.Fatal("rejected cancellation reached Worker")
	}
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	if _, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		registry, signer, time.Minute,
	); err != nil {
		t.Fatal(err)
	}
	uncertain := dispatch
	uncertain.disposition = ExecutionDispatchUncertain
	if _, err := core.CancelExecutionDispatch(
		context.Background(), uncertain, worker,
	); !errors.Is(err, journal.ErrTransition) {
		t.Fatalf("terminal request cancellation error = %v", err)
	}
	if server.cancelCalls.Load() != 0 {
		t.Fatal("stale cancellation reached Worker")
	}
}

func TestInvalidExecutionCancellationExposesNothing(t *testing.T) {
	var cancellation ExecutionCancellation
	if _, err := cancellation.Disposition(); err == nil {
		t.Fatal("zero cancellation exposed disposition")
	}
	if _, err := cancellation.Claim(); err == nil {
		t.Fatal("zero cancellation exposed claim")
	}
	if _, err := (&Core{}).CancelExecutionDispatch(
		context.Background(), ExecutionDispatch{}, nil,
	); err == nil {
		t.Fatal("invalid cancellation input succeeded")
	}
	var core *Core
	if _, err := core.CancelExecutionDispatch(
		context.Background(), ExecutionDispatch{}, nil,
	); err == nil {
		t.Fatal("nil Core canceled dispatch")
	}
	if _, err := (&Core{}).CancelExecutionDispatch(
		nil, ExecutionDispatch{}, nil,
	); err == nil {
		t.Fatal("nil cancellation context succeeded")
	}
}
