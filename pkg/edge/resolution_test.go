package edge

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestCoreResolvesDirectSuccessWithDeterministicReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, fixture := prepareDispatchRequest(
		t, now, "resolution-success-0001",
	)
	defer core.Close()
	worker := startDispatchWorkerClient(t, &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("resolved-output"),
	})
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	resolved, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		registry, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := resolved.Disposition()
	if err != nil || disposition != ExecutionResolutionSucceeded {
		t.Fatalf("resolution disposition = %q, err = %v", disposition, err)
	}
	completed, err := resolved.CompletedInvocation()
	if err != nil {
		t.Fatal(err)
	}
	claim, err := dispatch.Claim()
	if err != nil {
		t.Fatal(err)
	}
	expectedReceiptID, err := executionReceiptID(claim)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Request.State != journal.StateSucceeded ||
		completed.Disposition != journal.ReceiptApplied ||
		completed.Receipt.ReceiptID != expectedReceiptID ||
		!strings.HasPrefix(completed.Receipt.ReceiptID, "receipt-") ||
		len(completed.Receipt.ReceiptID) != len("receipt-")+64 ||
		string(completed.Output) != "resolved-output" ||
		signer.calls.Load() != 1 {
		t.Fatalf("unexpected successful resolution: %#v", completed)
	}
	if _, err := resolved.TerminatedInvocation(); err == nil {
		t.Fatal("successful resolution exposed a termination")
	}
	completed.Output[0] ^= 1
	completed.Receipt.Usage[0].Quantity++
	completed.Receipt.Envelope.Payload[0] ^= 1
	unchanged, err := resolved.CompletedInvocation()
	if err != nil || string(unchanged.Output) != "resolved-output" ||
		unchanged.Receipt.Usage[0].Quantity == completed.Receipt.Usage[0].Quantity ||
		string(unchanged.Receipt.Envelope.Payload) == string(completed.Receipt.Envelope.Payload) {
		t.Fatalf("resolution aliases caller result: %#v, err = %v", unchanged, err)
	}
	replayed, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		registry, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := replayed.CompletedInvocation()
	if err != nil || replayedCompletion.Disposition != journal.ReceiptReplay ||
		replayedCompletion.Receipt.ReceiptID != expectedReceiptID ||
		signer.calls.Load() != 1 {
		t.Fatalf(
			"replayed completion = %#v, signer calls = %d, err = %v",
			replayedCompletion,
			signer.calls.Load(),
			err,
		)
	}
}

func TestCoreResolvesPlannedSuccessWithProportionalCharge(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, _, fixture := prepareDispatchRequest(
		t, now, "resolution-policy-0001",
	)
	defer core.Close()
	plan := successfulReceiptTestPlan(t, 5_000)
	worker := startDispatchWorkerClient(t, &dispatchWorker{
		output: []byte("policy-output"),
	})
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	resolved, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		plan, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := resolved.CompletedInvocation()
	if err != nil || completed.Receipt.ChargedNanoTOS != 2 ||
		completed.Disposition != journal.ReceiptApplied {
		t.Fatalf("planned completion = %#v, err = %v", completed, err)
	}
	replayed, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		plan, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := replayed.CompletedInvocation()
	if err != nil || replayedCompletion.Disposition != journal.ReceiptReplay ||
		replayedCompletion.Receipt.ChargedNanoTOS != 2 ||
		signer.calls.Load() != 1 {
		t.Fatalf(
			"planned replay = %#v, calls = %d, err = %v",
			replayedCompletion, signer.calls.Load(), err,
		)
	}
	if _, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		successfulReceiptTestPlan(t, 10_000), signer, time.Minute,
	); !errors.Is(err, journal.ErrConflict) {
		t.Fatalf("changed policy replay error = %v", err)
	}
}

func TestCoreResolvesRecoveredPolicySuccessDeterministically(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, _, fixture := prepareDispatchRequest(
		t, now, "resolution-recovered-policy-0001",
	)
	defer core.Close()
	plan := successfulReceiptTestPlan(t, 5_000)
	claimed, err := core.MapAndClaimRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), plan, mappingWorkerClient(t, now),
	)
	if err != nil || claimed.Disposition != journal.ExecutionClaimed {
		t.Fatalf("initial claim = %#v, err = %v", claimed, err)
	}
	if !strings.HasPrefix(claimed.Execution.TaskID, "task-policy-") {
		t.Fatalf("partial policy task ID = %q", claimed.Execution.TaskID)
	}
	if _, err := core.MapAndClaimRecoveredPaidExecution(
		context.Background(), scope, []byte("dispatch-intent"),
		successfulReceiptTestPlan(t, 10_000), mappingWorkerClient(t, now),
	); !errors.Is(err, journal.ErrConflict) {
		t.Fatalf("pre-receipt policy drift error = %v", err)
	}
	dispatch, err := core.DispatchRecoveredPaidExecution(
		context.Background(), scope, []byte("dispatch-intent"),
		successfulReceiptTestPlan(t, 5_000),
		startDispatchWorkerClient(t, &dispatchWorker{
			getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
			output:    []byte("recovered-policy-output"),
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := core.ResolveRecoveredExecutionDispatch(
		context.Background(), dispatch, fixture.manifest,
		successfulReceiptTestPlan(t, 5_000),
		&edgeReceiptSigner{
			privateKey: fixture.runtimePrivate,
			keyID:      "runtime-auth-key",
		},
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := resolved.CompletedInvocation()
	if err != nil || completed.Disposition != journal.ReceiptApplied ||
		completed.Receipt.ChargedNanoTOS != 2 ||
		string(completed.Output) != "recovered-policy-output" {
		t.Fatalf("recovered planned completion = %#v, err = %v", completed, err)
	}
}

func successfulReceiptTestPlan(
	t *testing.T,
	basisPoints uint16,
) *ProfileInvocationPlan {
	t.Helper()
	policy, err := NewProportionalSuccessfulReceiptPolicy(basisPoints)
	if err != nil {
		t.Fatal(err)
	}
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
			SuccessfulReceiptPolicy: policy,
		}},
		[]ProfileInvocationRequirement{{
			ProfileID: "tos.ai.inference", ProfileVersion: "0.1.0",
			Operation: "invoke",
		}},
	)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestCoreResolvesRecoveredSuccessWithoutReinvocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	core, scope, authorized, request, registry, fixture := prepareDispatchRequest(
		t, now, "resolution-recovered-success-0001",
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
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("recovered-output"),
	}
	dispatch, err := core.DispatchRegisteredPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		[]byte("dispatch-intent"), registry,
		startDispatchWorkerClient(t, server),
	)
	if err != nil {
		t.Fatal(err)
	}
	if server.invokeCalls.Load() != 0 || server.getCalls.Load() != 1 {
		t.Fatalf(
			"recovery invoked=%d queried=%d",
			server.invokeCalls.Load(), server.getCalls.Load(),
		)
	}
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	resolved, err := core.ResolveExecutionDispatch(
		context.Background(), dispatch, fixture.manifest, authorized,
		registry, signer, time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := resolved.Disposition()
	completed, completionErr := resolved.CompletedInvocation()
	if err != nil || completionErr != nil ||
		disposition != ExecutionResolutionSucceeded ||
		completed.Disposition != journal.ReceiptApplied ||
		completed.Request.State != journal.StateSucceeded ||
		string(completed.Output) != "recovered-output" ||
		signer.calls.Load() != 1 {
		t.Fatalf(
			"disposition=%q completion=%#v calls=%d errors=%v/%v",
			disposition, completed, signer.calls.Load(), err, completionErr,
		)
	}
}

func TestCoreResolvesRecoveredFailureAndCancellation(t *testing.T) {
	tests := []struct {
		name       string
		worker     edgev1.TaskStatus
		resolution ExecutionResolutionDisposition
		request    journal.State
		errorCode  string
	}{
		{
			name: "failed", worker: edgev1.TaskStatus_TASK_STATUS_FAILED,
			resolution: ExecutionResolutionFailed, request: journal.StateFailed,
			errorCode: string(protocol.ErrorRuntimeFailed),
		},
		{
			name: "canceled", worker: edgev1.TaskStatus_TASK_STATUS_CANCELED,
			resolution: ExecutionResolutionCanceled, request: journal.StateCanceled,
			errorCode: string(protocol.ErrorCanceled),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			core, scope, authorized, request, _, fixture := prepareDispatchRequest(
				t, now, "resolution-"+test.name+"-0001",
			)
			defer core.Close()
			plan := successfulReceiptTestPlan(t, 5_000)
			claimed, err := core.MapAndClaimRegisteredPaidExecution(
				context.Background(), scope, request.Revision, authorized,
				[]byte("dispatch-intent"), plan, mappingWorkerClient(t, now),
			)
			if err != nil || claimed.Disposition != journal.ExecutionClaimed {
				t.Fatalf("pre-crash claim = %#v, err = %v", claimed, err)
			}
			dispatch, err := core.DispatchRegisteredPaidExecution(
				context.Background(), scope, request.Revision, authorized,
				[]byte("dispatch-intent"), plan,
				startDispatchWorkerClient(t, &dispatchWorker{getStatus: test.worker}),
			)
			if err != nil {
				t.Fatal(err)
			}
			signer := &edgeReceiptSigner{
				privateKey: fixture.runtimePrivate,
				keyID:      "runtime-auth-key",
			}
			resolved, err := core.ResolveExecutionDispatch(
				context.Background(), dispatch, fixture.manifest, authorized,
				plan, signer, time.Minute,
			)
			if err != nil {
				t.Fatal(err)
			}
			disposition, err := resolved.Disposition()
			terminated, terminalErr := resolved.TerminatedInvocation()
			if err != nil || terminalErr != nil || disposition != test.resolution ||
				terminated.Request.State != test.request ||
				terminated.Receipt.ErrorCode != test.errorCode ||
				terminated.Receipt.ChargedNanoTOS != 0 ||
				len(terminated.Receipt.Usage) != 0 || signer.calls.Load() != 1 {
				t.Fatalf(
					"disposition = %q, termination = %#v, calls = %d, errors = %v/%v",
					disposition,
					terminated,
					signer.calls.Load(),
					err,
					terminalErr,
				)
			}
			if _, err := resolved.CompletedInvocation(); err == nil {
				t.Fatal("failure resolution exposed successful completion")
			}
			replayed, err := core.ResolveExecutionDispatch(
				context.Background(), dispatch, fixture.manifest, authorized,
				plan, signer, time.Minute,
			)
			if err != nil {
				t.Fatal(err)
			}
			replayedTermination, err := replayed.TerminatedInvocation()
			if err != nil || replayedTermination.Disposition != journal.ReceiptReplay ||
				signer.calls.Load() != 1 {
				t.Fatalf(
					"replayed termination = %#v, calls = %d, err = %v",
					replayedTermination,
					signer.calls.Load(),
					err,
				)
			}
		})
	}
}

func TestCoreLeavesNonterminalDispatchWithoutReceipt(t *testing.T) {
	tests := []struct {
		name      string
		worker    edgev1.TaskStatus
		expected  ExecutionResolutionDisposition
		uncertain bool
	}{
		{
			name: "not-found", worker: edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
			expected: ExecutionResolutionNotFound,
		},
		{
			name: "accepted", worker: edgev1.TaskStatus_TASK_STATUS_ACCEPTED,
			expected: ExecutionResolutionAccepted,
		},
		{
			name: "running", worker: edgev1.TaskStatus_TASK_STATUS_RUNNING,
			expected: ExecutionResolutionRunning,
		},
		{
			name: "uncertain", worker: edgev1.TaskStatus_TASK_STATUS_RUNNING,
			expected: ExecutionResolutionUncertain, uncertain: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			now := time.Now().UTC().Truncate(time.Millisecond)
			core, scope, authorized, request, registry, _ := prepareDispatchRequest(
				t, now, "resolution-"+test.name+"-0001",
			)
			defer core.Close()
			server := &dispatchWorker{
				getStatus: test.worker, invokeError: test.uncertain,
			}
			worker := startDispatchWorkerClient(t, server)
			var dispatch ExecutionDispatch
			var err error
			if test.uncertain {
				dispatch, err = core.DispatchRegisteredPaidExecution(
					context.Background(), scope, request.Revision, authorized,
					[]byte("dispatch-intent"), registry, worker,
				)
				if err == nil {
					t.Fatal("uncertain dispatch did not return its RPC error")
				}
			} else {
				if _, err := core.MapAndClaimRegisteredPaidExecution(
					context.Background(), scope, request.Revision, authorized,
					[]byte("dispatch-intent"), registry, mappingWorkerClient(t, now),
				); err != nil {
					t.Fatal(err)
				}
				dispatch, err = core.DispatchRegisteredPaidExecution(
					context.Background(), scope, request.Revision, authorized,
					[]byte("dispatch-intent"), registry, worker,
				)
				if err != nil {
					t.Fatal(err)
				}
			}
			resolved, err := core.ResolveExecutionDispatch(
				context.Background(), dispatch, nil, authorized, registry, nil, 0,
			)
			if err != nil {
				t.Fatal(err)
			}
			disposition, err := resolved.Disposition()
			if err != nil || disposition != test.expected {
				t.Fatalf("disposition = %q, err = %v", disposition, err)
			}
			if _, err := resolved.CompletedInvocation(); err == nil {
				t.Fatal("nonterminal resolution exposed completion")
			}
			if _, err := resolved.TerminatedInvocation(); err == nil {
				t.Fatal("nonterminal resolution exposed termination")
			}
			if _, err := core.Receipt(scope); !errors.Is(err, journal.ErrNotFound) {
				t.Fatalf("nonterminal resolution persisted receipt: %v", err)
			}
		})
	}
}

func TestInvalidExecutionResolutionExposesNothing(t *testing.T) {
	var resolution ExecutionResolution
	if _, err := resolution.Disposition(); err == nil {
		t.Fatal("zero resolution exposed disposition")
	}
	if _, err := resolution.Claim(); err == nil {
		t.Fatal("zero resolution exposed claim")
	}
	if _, err := resolution.CompletedInvocation(); err == nil {
		t.Fatal("zero resolution exposed completion")
	}
	if _, err := resolution.TerminatedInvocation(); err == nil {
		t.Fatal("zero resolution exposed termination")
	}
	if _, err := (&Core{}).ResolveExecutionDispatch(
		context.Background(), ExecutionDispatch{}, nil,
		authorization.AuthorizedPayment{}, nil, nil, 0,
	); err == nil {
		t.Fatal("invalid dispatch was resolved")
	}
	var core *Core
	if _, err := core.ResolveExecutionDispatch(
		context.Background(), ExecutionDispatch{}, nil,
		authorization.AuthorizedPayment{}, nil, nil, 0,
	); err == nil {
		t.Fatal("nil Core resolved a dispatch")
	}
}
