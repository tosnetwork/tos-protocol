package edge

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/gen/tos/edge/v1/edgev1connect"
	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type completionWorker struct {
	edgev1connect.UnimplementedWorkerServiceHandler
	output []byte
}

func (w completionWorker) Invoke(
	_ context.Context,
	request *connect.Request[edgev1.InvokeRequest],
) (*connect.Response[edgev1.InvokeResponse], error) {
	return connect.NewResponse(&edgev1.InvokeResponse{
		RequestId: request.Msg.RequestId,
		Output:    append([]byte(nil), w.output...),
		Usage: &edgev1.Usage{
			InputBytes:      uint64(len(request.Msg.Payload)),
			OutputBytes:     uint64(len(w.output)),
			InputTokens:     2,
			OutputTokens:    3,
			ExecutionMillis: 4,
		},
		ModelRevision:   "model-revision-1",
		RuntimeRevision: "runtime-revision-1",
	}), nil
}

type edgeReceiptSigner struct {
	privateKey ed25519.PrivateKey
	keyID      string
	calls      atomic.Int32
	beforeSign func(int32)
}

func (s *edgeReceiptSigner) SignReceipt(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	call := s.calls.Add(1)
	if s.beforeSign != nil {
		s.beforeSign(call)
	}
	if err := ctx.Err(); err != nil {
		return identity.Envelope{}, err
	}
	return identity.Sign(
		s.privateKey,
		protocol.ReceiptDomain,
		s.keyID,
		payload,
		issuedAt,
		expiresAt,
	)
}

func TestCoreCompletesValidatedWorkerInvocationAndReplays(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	clock := now
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	scope, authorized, running := prepareCompletionRequest(
		t,
		core,
		fixture,
		"completion-request-0001",
		now,
	)
	worker := startCompletionWorkerClient(t, []byte("worker-result"))
	validated, err := worker.Invoke(
		context.Background(),
		completionInvokeRequest(scope, now),
	)
	if err != nil {
		t.Fatal(err)
	}
	clock = time.Now().UTC().Truncate(time.Millisecond)
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
	}
	expandedRequest := completionInvokeRequest(scope, now)
	expandedRequest.MaxOutputBytes++
	expanded, err := worker.Invoke(context.Background(), expandedRequest)
	if err != nil {
		t.Fatal(err)
	}
	clock = time.Now().UTC().Truncate(time.Millisecond)
	if _, err := core.CompleteSuccessfulInvocation(
		context.Background(), scope, running.Revision,
		fixture.manifest, authorized, expanded, signer,
		"receipt-completion-0001", time.Minute,
	); err == nil || signer.calls.Load() != 0 {
		t.Fatalf(
			"expanded Worker invocation err=%v signerCalls=%d",
			err,
			signer.calls.Load(),
		)
	}
	if _, err := core.CompleteSuccessfulInvocation(
		context.Background(), scope, running.Revision,
		fixture.manifest, authorized, localrpc.ValidatedInvocation{},
		signer, "receipt-completion-0001", time.Minute,
	); err == nil {
		t.Fatal("zero validated Worker result accepted")
	}
	completed, err := core.CompleteSuccessfulInvocation(
		context.Background(), scope, running.Revision,
		fixture.manifest, authorized, validated, signer,
		"receipt-completion-0001", time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	if completed.Disposition != journal.ReceiptApplied ||
		completed.Request.State != journal.StateSucceeded ||
		completed.Receipt.ResultDigest != digestInvocationOutput(
			[]byte("worker-result"),
		) ||
		len(completed.Receipt.Usage) != 5 ||
		signer.calls.Load() != 1 {
		t.Fatalf("unexpected completion: %#v", completed)
	}
	completed.Output[0] ^= 1
	replayed, err := core.CompleteSuccessfulInvocation(
		context.Background(), scope, running.Revision,
		fixture.manifest, authorized, validated, signer,
		"receipt-completion-0001", time.Minute,
	)
	if err != nil || replayed.Disposition != journal.ReceiptReplay ||
		string(replayed.Output) != "worker-result" || signer.calls.Load() != 1 {
		t.Fatalf(
			"completion replay=%#v calls=%d err=%v",
			replayed,
			signer.calls.Load(),
			err,
		)
	}
	if _, err := core.CompleteSuccessfulInvocation(
		context.Background(), scope, running.Revision,
		fixture.manifest, authorized, validated, signer,
		"receipt-completion-other", time.Minute,
	); !errors.Is(err, journal.ErrConflict) || signer.calls.Load() != 1 {
		t.Fatalf("different receipt replay err=%v calls=%d", err, signer.calls.Load())
	}
}

func TestCoreConcurrentCompletionHasOneDurableReceipt(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	clock := now
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	scope, authorized, running := prepareCompletionRequest(
		t,
		core,
		fixture,
		"completion-concurrent-0001",
		now,
	)
	worker := startCompletionWorkerClient(t, []byte("concurrent-result"))
	validated, err := worker.Invoke(
		context.Background(),
		completionInvokeRequest(scope, now),
	)
	if err != nil {
		t.Fatal(err)
	}
	clock = time.Now().UTC().Truncate(time.Millisecond)
	const attempts = 16
	release := make(chan struct{})
	signer := &edgeReceiptSigner{
		privateKey: fixture.runtimePrivate,
		keyID:      "runtime-auth-key",
		beforeSign: func(call int32) {
			if call == attempts {
				close(release)
			}
			<-release
		},
	}
	var applied atomic.Int32
	var replayed atomic.Int32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, attempts)
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := core.CompleteSuccessfulInvocation(
				context.Background(), scope, running.Revision,
				fixture.manifest, authorized, validated, signer,
				"receipt-concurrent-0001", time.Minute,
			)
			if err != nil {
				errorsSeen <- err
				return
			}
			switch result.Disposition {
			case journal.ReceiptApplied:
				applied.Add(1)
			case journal.ReceiptReplay:
				replayed.Add(1)
			default:
				errorsSeen <- errors.New("unexpected receipt disposition")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if applied.Load() != 1 || replayed.Load() != attempts-1 ||
		signer.calls.Load() != attempts || health.ReceiptRecords != 1 {
		t.Fatalf(
			"applied=%d replayed=%d signed=%d health=%#v",
			applied.Load(), replayed.Load(), signer.calls.Load(), health,
		)
	}
}

func prepareCompletionRequest(
	t *testing.T,
	core *Core,
	fixture coreSessionFixture,
	requestID string,
	now time.Time,
) (journal.Scope, authorization.AuthorizedPayment, journal.Record) {
	t.Helper()
	scope, authorized := fixture.authorizePayment(t, requestID)
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
	running, err := core.TransitionRequest(
		scope,
		request.Revision,
		journal.StateRunning,
		"",
		"",
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope, authorized, running
}

func completionInvokeRequest(
	scope journal.Scope,
	now time.Time,
) *edgev1.InvokeRequest {
	return &edgev1.InvokeRequest{
		RequestId:          scope.RequestID,
		QuoteId:            "quote-" + scope.RequestID,
		TaskId:             "task-" + scope.RequestID,
		ServiceId:          scope.ServiceID,
		Operation:          scope.Operation,
		Model:              "test-model",
		Payload:            []byte("input"),
		MaxOutputBytes:     2_048,
		DeadlineUnixMillis: now.Add(5 * time.Minute).UnixMilli(),
		Priority:           edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
	}
}

func startCompletionWorkerClient(
	t *testing.T,
	output []byte,
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
	path, handler := edgev1connect.NewWorkerServiceHandler(
		completionWorker{output: output},
	)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		_ = server.Close()
		_ = listener.Close()
		_ = os.Remove(socketPath)
	})
	client, err := localrpc.NewWorkerClient(
		localrpc.DefaultWorkerClientConfig(socketPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	return client
}
