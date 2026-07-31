package edge

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestCoreMapsPaidProfileIntentDeterministicallyAcrossRestart(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	journalPath := filepath.Join(t.TempDir(), "requests.db")
	config := DefaultCoreConfig(journalPath)
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	fixture := newCoreSessionFixture(t, now)
	intent := []byte(`{"model":"qwen3","prompt":"hello"}`)
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	scope, authorized := fixture.authorizePaymentWithIntentDigest(
		t,
		"mapped-execution-0001",
		digest,
	)
	request := applyAuthorizedPaymentForCompletion(
		t,
		core,
		scope,
		authorized,
		now,
	)
	worker := mappingWorkerClient(t, now)
	mappedPayload := []byte("worker-input")
	mapperCalls := 0
	mapper := ProfileInvocationMapperFunc(func(
		_ context.Context,
		input ProfileInvocationInput,
	) (ProfileInvocationOutput, error) {
		mapperCalls++
		if input.ProfileID != "tos.ai.inference" ||
			input.ProfileVersion != "0.1.0" ||
			input.Operation != scope.Operation ||
			input.IntentDigest != digest ||
			string(input.Intent) != string(intent) ||
			input.MaxInputBytes != 1_024 ||
			input.MaxOutputBytes != 2_048 {
			t.Fatalf("unexpected mapper input: %#v", input)
		}
		input.Intent[0] ^= 1
		return ProfileInvocationOutput{
			Model: "qwen3-8b-int4", Payload: mappedPayload,
		}, nil
	})
	wrongIntent := append([]byte(nil), intent...)
	wrongIntent[len(wrongIntent)-1] ^= 1
	if _, err := core.mapAndClaimPaidExecution(
		context.Background(), scope, request.Revision,
		authorized, wrongIntent, mapper, worker,
	); err == nil {
		t.Fatal("changed public intent was claimed")
	}
	if mapperCalls != 0 {
		t.Fatal("mapper ran before intent commitment verification")
	}
	if _, err := core.Execution(scope); !errors.Is(err, journal.ErrNotFound) {
		t.Fatalf("rejected mapping persisted execution: %v", err)
	}
	claimed, err := core.mapAndClaimPaidExecution(
		context.Background(), scope, request.Revision,
		authorized, intent, mapper, worker,
	)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Disposition != journal.ExecutionClaimed ||
		claimed.State.State != journal.StateRunning ||
		!strings.HasPrefix(claimed.Request.TaskId, "task-") ||
		len(claimed.Request.TaskId) != len("task-")+64 ||
		claimed.Request.RequestId != scope.RequestID ||
		claimed.Request.QuoteId != "quote-"+scope.RequestID ||
		claimed.Request.ServiceId != scope.ServiceID ||
		claimed.Request.Operation != scope.Operation ||
		claimed.Request.Model != "qwen3-8b-int4" ||
		string(claimed.Request.Payload) != "worker-input" ||
		claimed.Request.MaxOutputBytes != 2_048 ||
		claimed.Request.DeadlineUnixMillis != now.Add(5*time.Minute).UnixMilli() ||
		claimed.Request.Priority != edgev1.Priority_PRIORITY_EXTERNAL_SERVICE ||
		claimed.Request.RequestDigest != claimed.Execution.RequestDigest {
		t.Fatalf("unexpected mapped claim: %#v", claimed)
	}
	mappedPayload[0] ^= 1
	intent[0] ^= 1
	if string(claimed.Request.Payload) != "worker-input" {
		t.Fatal("claim aliases mapper output")
	}
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	core, err = openCore(config, func() time.Time { return now.Add(time.Second) })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	replayIntent := []byte(`{"model":"qwen3","prompt":"hello"}`)
	replay, err := core.mapAndClaimPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		replayIntent,
		ProfileInvocationMapperFunc(func(
			context.Context,
			ProfileInvocationInput,
		) (ProfileInvocationOutput, error) {
			return ProfileInvocationOutput{
				Model: "qwen3-8b-int4", Payload: []byte("worker-input"),
			}, nil
		}),
		worker,
	)
	if err != nil || replay.Disposition != journal.ExecutionReplay ||
		replay.Execution != claimed.Execution {
		t.Fatalf("restart replay = %#v, err = %v", replay, err)
	}
	if _, err := core.mapAndClaimPaidExecution(
		context.Background(), scope, request.Revision, authorized,
		replayIntent,
		ProfileInvocationMapperFunc(func(
			context.Context,
			ProfileInvocationInput,
		) (ProfileInvocationOutput, error) {
			return ProfileInvocationOutput{
				Model: "changed-model", Payload: []byte("worker-input"),
			}, nil
		}),
		worker,
	); !errors.Is(err, journal.ErrConflict) {
		t.Fatalf("changed restart mapping error = %v", err)
	}
}

func TestCoreRejectsInvalidProfileMapperBeforeExecutionClaim(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	intent := []byte("intent")
	digest, err := protocol.RequestIntentDigest(
		"tos.ai.inference", "0.1.0", nil, "invoke", intent,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mapper ProfileInvocationMapper
	}{
		{
			name: "panic",
			mapper: ProfileInvocationMapperFunc(func(
				context.Context,
				ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				panic("untrusted intent parser bug")
			}),
		},
		{
			name: "invalid model",
			mapper: ProfileInvocationMapperFunc(func(
				context.Context,
				ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				return ProfileInvocationOutput{Payload: []byte("payload")}, nil
			}),
		},
		{
			name: "error",
			mapper: ProfileInvocationMapperFunc(func(
				context.Context,
				ProfileInvocationInput,
			) (ProfileInvocationOutput, error) {
				return ProfileInvocationOutput{}, errors.New("invalid profile intent")
			}),
		},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
			config.CleanupInterval = time.Hour
			core, err := openCore(config, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			defer core.Close()
			fixture := newCoreSessionFixture(t, now)
			worker := mappingWorkerClient(t, now)
			requestID := "mapping-rejection-000" + string(rune('1'+index))
			scope, authorized := fixture.authorizePaymentWithIntentDigest(
				t,
				requestID,
				digest,
			)
			request := applyAuthorizedPaymentForCompletion(
				t,
				core,
				scope,
				authorized,
				now,
			)
			if _, err := core.mapAndClaimPaidExecution(
				context.Background(), scope, request.Revision,
				authorized, intent, test.mapper, worker,
			); err == nil {
				t.Fatal("invalid mapper was claimed")
			}
			stored, err := core.Request(scope)
			if err != nil {
				t.Fatal(err)
			}
			if stored.State != journal.StateAuthorized || stored.Revision != request.Revision {
				t.Fatalf("rejected mapper mutated request: %#v", stored)
			}
			if _, err := core.Execution(scope); !errors.Is(err, journal.ErrNotFound) {
				t.Fatalf("rejected mapper persisted execution: %v", err)
			}
		})
	}
}

func applyAuthorizedPaymentForCompletion(
	t *testing.T,
	core *Core,
	scope journal.Scope,
	authorized authorization.AuthorizedPayment,
	now time.Time,
) journal.Record {
	t.Helper()
	material, err := authorized.ObservationMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.AdmitAuthorizedPayment(
		scope,
		material.IntentDigest,
		authorized,
		now.Add(30*time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{state: chain.PaymentState{
			Network: material.Network, AuthorizationID: material.AuthorizationID,
			QuoteID: material.QuoteID, RequestID: material.RequestID,
			Reference: material.Reference, Confirmed: true, Finalized: true,
			AmountNanoTOS: material.PriceNanoTOS,
			Payer:         material.Payer, Payee: material.Payee,
			ObservedMasterSeqno: 101, ObservedAt: now,
		}},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := observer.Observe(
		context.Background(), authorized, 100, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	request, _, _, err := core.ApplyVerifiedPayment(
		scope,
		material.IntentDigest,
		authorized,
		observed,
		101,
	)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mappingWorkerClient(t *testing.T, _ time.Time) *localrpc.WorkerClient {
	t.Helper()
	config := localrpc.DefaultWorkerClientConfig(
		filepath.Join(t.TempDir(), "worker.sock"),
	)
	client, err := localrpc.NewWorkerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
