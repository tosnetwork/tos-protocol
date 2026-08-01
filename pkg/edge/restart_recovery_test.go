package edge

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestPaidExecutionRecoversAfterRestartAndQuoteExpiry(t *testing.T) {
	acceptedAt := time.Now().UTC().Truncate(time.Millisecond)
	current := acceptedAt
	path := filepath.Join(t.TempDir(), "requests.db")
	config := DefaultCoreConfig(path)
	config.CleanupInterval = time.Hour
	first, err := openCore(config, func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCoreSessionFixture(t, acceptedAt)
	intent := []byte("restart-recovery-intent")
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference",
		"0.1.0",
		nil,
		"invoke",
		intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, authorized := fixture.authorizePaymentWithIntentDigest(
		t,
		"restart-recovery-0001",
		digest,
	)
	paid := applyAuthorizedPaymentForCompletion(
		t,
		first,
		scope,
		authorized,
		acceptedAt,
	)
	registry := restartRecoveryRegistry(t)
	claimed, err := first.MapAndClaimRegisteredPaidExecution(
		context.Background(),
		scope,
		paid.Revision,
		authorized,
		intent,
		registry,
		mappingWorkerClient(t, acceptedAt),
	)
	if err != nil || claimed.Disposition != journal.ExecutionClaimed ||
		claimed.State.State != journal.StateRunning {
		t.Fatalf("initial claim = %#v, err = %v", claimed, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	current = acceptedAt.Add(2 * time.Minute)
	if _, err := authorized.ObservationMaterial(current); err == nil {
		t.Fatal("expired live authorization remained observable")
	}
	second, err := openCore(config, func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	workerServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_SUCCEEDED,
		output:    []byte("recovered-after-restart"),
	}
	worker := startDispatchWorkerClient(t, workerServer)
	if _, err := second.DispatchRecoveredPaidExecution(
		context.Background(),
		scope,
		[]byte("changed-restart-recovery-intent"),
		registry,
		worker,
	); err == nil || workerServer.invokeCalls.Load() != 0 ||
		workerServer.getCalls.Load() != 0 {
		t.Fatalf(
			"changed intent recovery: invokes=%d gets=%d err=%v",
			workerServer.invokeCalls.Load(),
			workerServer.getCalls.Load(),
			err,
		)
	}
	dispatch, err := second.DispatchRecoveredPaidExecution(
		context.Background(),
		scope,
		intent,
		registry,
		worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	disposition, err := dispatch.Disposition()
	if err != nil || disposition != ExecutionDispatchRecovered ||
		workerServer.invokeCalls.Load() != 0 ||
		workerServer.getCalls.Load() != 1 {
		t.Fatalf(
			"dispatch=%q invokes=%d gets=%d err=%v",
			disposition,
			workerServer.invokeCalls.Load(),
			workerServer.getCalls.Load(),
			err,
		)
	}
	manifest := fixture.refreshManifest(t, current)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	resolved, err := second.ResolveRecoveredExecutionDispatch(
		context.Background(),
		dispatch,
		manifest,
		signer,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	resolution, err := resolved.Disposition()
	completed, completionErr := resolved.CompletedInvocation()
	if err != nil || completionErr != nil ||
		resolution != ExecutionResolutionSucceeded ||
		completed.Request.State != journal.StateSucceeded ||
		completed.Disposition != journal.ReceiptApplied ||
		string(completed.Output) != "recovered-after-restart" ||
		signer.calls.Load() != 1 {
		t.Fatalf(
			"resolution=%q completion=%#v signer=%d errors=%v/%v",
			resolution,
			completed,
			signer.calls.Load(),
			err,
			completionErr,
		)
	}
	stored, err := second.Receipt(scope)
	if err != nil || stored.ReceiptID != completed.Receipt.ReceiptID ||
		!strings.HasPrefix(stored.ReceiptID, "receipt-") {
		t.Fatalf("stored receipt = %#v, err = %v", stored, err)
	}
	replayed, err := second.ResolveRecoveredExecutionDispatch(
		context.Background(),
		dispatch,
		manifest,
		signer,
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedCompletion, err := replayed.CompletedInvocation()
	if err != nil || replayedCompletion.Disposition != journal.ReceiptReplay ||
		replayedCompletion.Receipt.ReceiptID != stored.ReceiptID ||
		signer.calls.Load() != 1 {
		t.Fatalf(
			"receipt replay = %#v, signer=%d, err=%v",
			replayedCompletion,
			signer.calls.Load(),
			err,
		)
	}
}

func TestRecoveredExecutionRejectsReorganizedPayment(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	path := filepath.Join(t.TempDir(), "requests.db")
	config := DefaultCoreConfig(path)
	config.CleanupInterval = time.Hour
	first, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCoreSessionFixture(t, now)
	intent := []byte("restart-recovery-intent")
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, authorized := fixture.authorizePaymentWithIntentDigest(
		t, "restart-recovery-reorg-0001", digest,
	)
	applyAuthorizedPaymentForCompletion(
		t, first, scope, authorized, now,
	)
	paid, err := first.Payment(scope)
	if err != nil {
		t.Fatal(err)
	}
	if _, disposition, err := first.requests.MarkPaymentReorganized(
		journal.PaymentReorganization{
			Scope: scope, AuthorizationID: paid.AuthorizationID,
			QuoteID: paid.QuoteID, Reference: paid.Reference,
			ObservedMasterSeqno: paid.ObservedMasterSeqno + 1,
			ObservedAt:          now,
		},
		now,
	); err != nil || disposition != journal.PaymentReorganized {
		t.Fatalf("mark payment reorganized: disposition=%q err=%v", disposition, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := openCore(config, func() time.Time { return now.Add(time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	workerServer := &dispatchWorker{
		getStatus: edgev1.TaskStatus_TASK_STATUS_NOT_FOUND,
	}
	if _, err := second.DispatchRecoveredPaidExecution(
		context.Background(),
		scope,
		intent,
		restartRecoveryRegistry(t),
		startDispatchWorkerClient(t, workerServer),
	); !errors.Is(err, journal.ErrPaymentReorganized) ||
		workerServer.invokeCalls.Load() != 0 ||
		workerServer.getCalls.Load() != 0 {
		t.Fatalf(
			"reorganized recovery: invokes=%d gets=%d err=%v",
			workerServer.invokeCalls.Load(),
			workerServer.getCalls.Load(),
			err,
		)
	}
}

func restartRecoveryRegistry(t *testing.T) *ProfileInvocationPlan {
	t.Helper()
	plan, err := NewProfileInvocationPlan(
		[]ProfileInvocationRegistration{{
			ProfileID:      "tos.ai.inference",
			ProfileVersion: "0.1.0",
			Operation:      "invoke",
			Mapper: ProfileInvocationMapperFunc(func(
				_ context.Context,
				input ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				if string(input.Intent) != "restart-recovery-intent" {
					return ProfileInvocationOutput{}, errors.New(
						"unexpected recovery intent",
					)
				}
				return ProfileInvocationOutput{
					Model:   "dispatch-model",
					Payload: []byte("input"),
				}, nil
			}),
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
