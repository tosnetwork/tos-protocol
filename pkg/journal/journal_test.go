package journal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func testScope(requestID string) Scope {
	return Scope{
		Network: "testnet", Authority: "runtime-key-1",
		ServiceID: "edge.example.ai", SessionID: "session-0001",
		Operation: "invoke", RequestID: requestID,
	}
}

func testNonce(seed byte) string {
	value := make([]byte, 16)
	for index := range value {
		value[index] = seed
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func testAdmission(scope Scope, nonce string, now time.Time) Admission {
	return Admission{
		Scope: scope, IntentDigest: "sha256:" + strings.Repeat("a", 64),
		EnvelopeDigest: "sha256:" + strings.Repeat("b", 64),
		Domain:         "tos.action.v1", Nonce: nonce,
		EnvelopeExpiresAt: now.Add(time.Minute),
		RetainUntil:       now.Add(time.Hour),
	}
}

func testSessionAdmission(
	scope Scope,
	nonce string,
	now time.Time,
	charge uint64,
) SessionAdmission {
	admission := testAdmission(scope, nonce, now)
	admission.RetainUntil = now.Add(time.Hour)
	return SessionAdmission{
		Admission: admission,
		ClientID:  "client-key-1", SessionExpiresAt: now.Add(time.Hour),
		ChargeNanoTOS: charge,
		Budgets: []UsageBudget{
			{
				Kind: "session", ID: scope.SessionID,
				GrantDigest: "sha256:" + strings.Repeat("c", 64),
				MaxActions:  2, MaxNanoTOS: 10,
			},
			{
				Kind: "delegation", ID: "delegation-0001",
				GrantDigest: "sha256:" + strings.Repeat("d", 64),
				MaxActions:  2, MaxNanoTOS: 10,
			},
		},
	}
}

func testPaymentAdmission(
	scope Scope,
	now time.Time,
	observedMasterSeqno uint64,
) PaymentAdmission {
	return PaymentAdmission{
		Scope:                 scope,
		IntentDigest:          "sha256:" + strings.Repeat("a", 64),
		AuthorizationID:       "authorization-0001",
		QuoteID:               "quote-0001",
		Reference:             "payment-reference-0001",
		Payer:                 "payer-wallet",
		Payee:                 "service-wallet",
		AmountNanoTOS:         5,
		QuoteEnvelopeDigest:   "sha256:" + strings.Repeat("e", 64),
		PaymentEnvelopeDigest: "sha256:" + strings.Repeat("f", 64),
		ObservedMasterSeqno:   observedMasterSeqno,
		ObservedAt:            now,
	}
}

func testReceiptAdmission(
	scope Scope,
	now time.Time,
	status State,
) ReceiptAdmission {
	admission := ReceiptAdmission{
		Scope: scope, IntentDigest: "sha256:" + strings.Repeat("a", 64),
		ReceiptID:       "receipt-0001",
		RuntimeKeyID:    "runtime-receipt-key-1",
		AuthorizationID: "authorization-0001",
		QuoteID:         "quote-0001",
		Status:          status,
		Usage: []ReceiptUsage{
			{Unit: "output_tokens", Quantity: 10},
		},
		ChargedNanoTOS:   5,
		ServiceRevision:  "manifest-revision-1",
		ResourceRevision: "resource-revision-1",
		CompletedAt:      now,
	}
	switch status {
	case StateSucceeded:
		admission.ResultDigest = "sha256:" + strings.Repeat("8", 64)
	case StateFailed:
		admission.ErrorCode = string(protocol.ErrorRuntimeFailed)
	case StateTimedOut:
		admission.ErrorCode = string(protocol.ErrorDeadlineExceeded)
	case StateCanceled:
		admission.ErrorCode = string(protocol.ErrorCanceled)
	}
	signed := protocol.Receipt{
		Version:   protocol.BaseEnvelopeVersion,
		ReceiptID: admission.ReceiptID, RequestID: scope.RequestID,
		QuoteID:         admission.QuoteID,
		AuthorizationID: admission.AuthorizationID,
		ServiceID:       scope.ServiceID,
		Status:          receiptStatusString(admission.Status),
		Usage: []protocol.UsageItem{
			{Unit: "output_tokens", Quantity: 10},
		},
		ChargedNanoTOS:   admission.ChargedNanoTOS,
		ResultDigest:     admission.ResultDigest,
		ServiceRevision:  admission.ServiceRevision,
		ResourceRevision: admission.ResourceRevision,
		CompletedAt:      admission.CompletedAt,
	}
	payload, err := codec.Marshal(signed)
	if err != nil {
		panic(err)
	}
	admission.Envelope = identity.Envelope{
		Version: identity.Version, Domain: protocol.ReceiptDomain,
		KeyID:    admission.RuntimeKeyID,
		IssuedAt: now.UnixMilli(), ExpiresAt: now.Add(time.Minute).UnixMilli(),
		Nonce: testNonce(77), Payload: payload,
		Signature: base64.RawURLEncoding.EncodeToString(
			make([]byte, 64),
		),
	}
	admission.ReceiptEnvelopeDigest, err = admission.Envelope.Fingerprint()
	if err != nil {
		panic(err)
	}
	return admission
}

func refreshReceiptEnvelope(
	admission *ReceiptAdmission,
	issuedAt time.Time,
) {
	signed := protocol.Receipt{
		Version:          protocol.BaseEnvelopeVersion,
		ReceiptID:        admission.ReceiptID,
		RequestID:        admission.Scope.RequestID,
		QuoteID:          admission.QuoteID,
		AuthorizationID:  admission.AuthorizationID,
		ServiceID:        admission.Scope.ServiceID,
		Status:           receiptStatusString(admission.Status),
		Usage:            make([]protocol.UsageItem, len(admission.Usage)),
		ChargedNanoTOS:   admission.ChargedNanoTOS,
		ResultDigest:     admission.ResultDigest,
		ServiceRevision:  admission.ServiceRevision,
		ResourceRevision: admission.ResourceRevision,
		CompletedAt:      admission.CompletedAt,
	}
	for index, item := range admission.Usage {
		signed.Usage[index] = protocol.UsageItem{
			Unit: item.Unit, Quantity: item.Quantity,
		}
	}
	payload, err := codec.Marshal(signed)
	if err != nil {
		panic(err)
	}
	admission.Envelope = identity.Envelope{
		Version: identity.Version, Domain: protocol.ReceiptDomain,
		KeyID:     admission.RuntimeKeyID,
		IssuedAt:  issuedAt.UnixMilli(),
		ExpiresAt: issuedAt.Add(time.Minute).UnixMilli(),
		Nonce:     testNonce(77), Payload: payload,
		Signature: base64.RawURLEncoding.EncodeToString(
			make([]byte, 64),
		),
	}
	admission.ReceiptEnvelopeDigest, err =
		admission.Envelope.Fingerprint()
	if err != nil {
		panic(err)
	}
}

func preparePaidRunningRequest(
	t *testing.T,
	store *Store,
	scope Scope,
	now time.Time,
) (Record, PaymentAdmission) {
	t.Helper()
	paymentAdmission := testPaymentAdmission(scope, now, 101)
	if _, _, err := store.Begin(
		scope, paymentAdmission.IntentDigest, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	authorized, _, _, err := store.ApplyPayment(paymentAdmission, now)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.Transition(
		scope, authorized.Revision, StateRunning, "", "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return running, paymentAdmission
}

func sameReceiptRecord(left, right ReceiptRecord) bool {
	return reflect.DeepEqual(left, right)
}

func testNonceClaim(scope Scope, nonce string, expiresAt time.Time) NonceClaim {
	return NonceClaim{
		Network: scope.Network, Authority: scope.Authority,
		ServiceID: scope.ServiceID, SessionID: scope.SessionID,
		Operation: scope.Operation, RequestID: scope.RequestID,
		Domain: "tos.action.v1", Nonce: nonce,
		EnvelopeDigest: "sha256:" + strings.Repeat("b", 64),
		ExpiresAt:      expiresAt,
	}
}

func testLimits(maxRecords uint64) Limits {
	limits := DefaultLimits()
	limits.MaxRecords = maxRecords
	limits.MaxPrunePerWrite = min(16, int(maxRecords))
	return limits
}

func openTestStore(t *testing.T, limits Limits) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "requests.db")
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

func TestBeginReplayConflictAndTransitions(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-0001")
	intent := "sha256:" + strings.Repeat("a", 64)

	record, disposition, err := store.Begin(scope, intent, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginCreated || record.State != StatePending || record.Revision != 1 {
		t.Fatalf("unexpected initial record: %#v, %q", record, disposition)
	}
	replayed, disposition, err := store.Begin(scope, intent, now.Add(time.Second), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginReplay || replayed != record {
		t.Fatalf("replay changed record: %#v, %q", replayed, disposition)
	}
	if _, _, err := store.Begin(
		scope, "sha256:"+strings.Repeat("b", 64), now, now.Add(time.Hour),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("intent substitution error = %v", err)
	}

	authorized, err := store.Transition(scope, 1, StateAuthorized, "", "", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Revision != 2 || authorized.State != StateAuthorized {
		t.Fatalf("unexpected authorized record: %#v", authorized)
	}
	if _, err := store.Transition(scope, 1, StateRunning, "", "", now.Add(2*time.Second)); !errors.Is(err, ErrRevision) {
		t.Fatalf("stale revision error = %v", err)
	}
	if _, err := store.Transition(
		scope, 2, StateSucceeded, "sha256:"+strings.Repeat("c", 64), "", now.Add(2*time.Second),
	); !errors.Is(err, ErrTransition) {
		t.Fatalf("illegal transition error = %v", err)
	}
	running, err := store.Transition(scope, 2, StateRunning, "", "", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	succeeded, err := store.Transition(
		scope, running.Revision, StateSucceeded,
		"sha256:"+strings.Repeat("c", 64), "", now.Add(3*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !succeeded.State.Terminal() || succeeded.Revision != 4 {
		t.Fatalf("unexpected terminal record: %#v", succeeded)
	}
	if _, err := store.Transition(
		scope, succeeded.Revision, StateFailed, "", "FAILED", now.Add(4*time.Second),
	); !errors.Is(err, ErrTransition) {
		t.Fatalf("terminal transition error = %v", err)
	}
}

func TestAdmitAtomicallyBindsNonceAndIdempotentRequest(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testAdmission(testScope("request-admit"), testNonce(1), now)

	record, disposition, err := store.Admit(admission, now)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginCreated {
		t.Fatalf("disposition = %q", disposition)
	}
	replayed, disposition, err := store.Admit(admission, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginReplay || replayed != record {
		t.Fatalf("exact replay changed request: %#v, %q", replayed, disposition)
	}

	resigned := admission
	resigned.Nonce = testNonce(2)
	replayed, disposition, err = store.Admit(resigned, now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginReplay || replayed != record {
		t.Fatalf("re-signed replay changed request: %#v, %q", replayed, disposition)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Nonces != 2 {
		t.Fatalf("unexpected admission stats: %#v", stats)
	}
}

func TestAdmitSessionAtomicallyConsumesBudgetsOnce(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	first := testSessionAdmission(
		testScope("session-request-1"), testNonce(20), now, 4,
	)
	record, disposition, err := store.AdmitSession(first, now)
	if err != nil || disposition != BeginCreated {
		t.Fatalf("first session admission: record=%#v disposition=%q err=%v", record, disposition, err)
	}
	replayed, disposition, err := store.AdmitSession(first, now.Add(time.Second))
	if err != nil || disposition != BeginReplay || replayed != record {
		t.Fatalf("exact session replay: record=%#v disposition=%q err=%v", replayed, disposition, err)
	}
	freshNonceReplay := first
	freshNonceReplay.Nonce = testNonce(21)
	if _, disposition, err := store.AdmitSession(
		freshNonceReplay, now.Add(2*time.Second),
	); err != nil || disposition != BeginReplay {
		t.Fatalf("fresh-nonce replay: disposition=%q err=%v", disposition, err)
	}
	if _, _, err := store.Admit(
		first.Admission, now.Add(2*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("session admission downgraded to unbudgeted admission: %v", err)
	}

	second := testSessionAdmission(
		testScope("session-request-2"), testNonce(22), now, 6,
	)
	if _, disposition, err := store.AdmitSession(
		second, now.Add(3*time.Second),
	); err != nil || disposition != BeginCreated {
		t.Fatalf("second session admission: disposition=%q err=%v", disposition, err)
	}
	exhausted := testSessionAdmission(
		testScope("session-request-3"), testNonce(23), now, 0,
	)
	if _, _, err := store.AdmitSession(
		exhausted, now.Add(4*time.Second),
	); !errors.Is(err, ErrBudgetLimit) {
		t.Fatalf("exhausted session error = %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 2 || stats.Nonces != 3 || stats.BudgetUsages != 2 {
		t.Fatalf("unexpected session stats: %#v", stats)
	}
}

func TestApplyPaymentAtomicallyAuthorizesAndReplays(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("payment-request-1")
	admission := testSessionAdmission(scope, testNonce(40), now, 5)
	if _, disposition, err := store.AdmitSession(admission, now); err != nil ||
		disposition != BeginCreated {
		t.Fatalf("admit payment request: disposition=%q err=%v", disposition, err)
	}
	paymentAdmission := testPaymentAdmission(scope, now, 101)
	record, payment, disposition, err := store.ApplyPayment(paymentAdmission, now)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PaymentApplied ||
		record.State != StateAuthorized || record.Revision != 2 ||
		payment.Status != PaymentStatusApplied || payment.Revision != 1 {
		t.Fatalf(
			"unexpected payment application: record=%#v payment=%#v disposition=%q",
			record, payment, disposition,
		)
	}

	replayedRecord, replayedPayment, disposition, err := store.ApplyPayment(
		paymentAdmission, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PaymentReplay ||
		replayedRecord != record || replayedPayment != payment {
		t.Fatalf(
			"payment replay changed state: record=%#v payment=%#v disposition=%q",
			replayedRecord, replayedPayment, disposition,
		)
	}
	stored, err := store.GetPayment(scope, now)
	if err != nil || stored != payment {
		t.Fatalf("stored payment=%#v err=%v", stored, err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Payments != 1 {
		t.Fatalf("unexpected payment stats: %#v", stats)
	}
	running, err := store.Transition(
		scope, record.Revision, StateRunning, "", "", now.Add(2*time.Second),
	)
	if err != nil || running.State != StateRunning {
		t.Fatalf("run paid request: record=%#v err=%v", running, err)
	}
}

func TestApplyPaymentRefreshRejectsRollbackAndConflict(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("payment-refresh")
	if _, _, err := store.AdmitSession(
		testSessionAdmission(scope, testNonce(41), now, 5), now,
	); err != nil {
		t.Fatal(err)
	}
	admission := testPaymentAdmission(scope, now, 101)
	record, _, _, err := store.ApplyPayment(admission, now)
	if err != nil {
		t.Fatal(err)
	}

	refreshed := admission
	refreshed.ObservedMasterSeqno = 102
	refreshed.ObservedAt = now.Add(time.Second)
	refreshedRecord, payment, disposition, err := store.ApplyPayment(
		refreshed, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PaymentRefreshed ||
		refreshedRecord != record || payment.Revision != 2 ||
		payment.ObservedMasterSeqno != 102 {
		t.Fatalf(
			"unexpected refresh: record=%#v payment=%#v disposition=%q",
			refreshedRecord, payment, disposition,
		)
	}
	rollback := admission
	rollback.ObservedMasterSeqno = 100
	if _, _, _, err := store.ApplyPayment(
		rollback, now.Add(2*time.Second),
	); !errors.Is(err, ErrPaymentRollback) {
		t.Fatalf("payment rollback error=%v", err)
	}
	conflict := refreshed
	conflict.ObservedAt = now.Add(2 * time.Second)
	if _, _, _, err := store.ApplyPayment(
		conflict, now.Add(2*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-position conflict error=%v", err)
	}
}

func TestApplyPaymentRejectsCrossRequestReplay(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	firstScope := testScope("payment-first-request")
	secondScope := testScope("payment-second-request")
	for index, scope := range []Scope{firstScope, secondScope} {
		if _, _, err := store.AdmitSession(
			testSessionAdmission(scope, testNonce(byte(42+index)), now, 5), now,
		); err != nil {
			t.Fatal(err)
		}
	}
	paymentAdmission := testPaymentAdmission(firstScope, now, 101)
	if _, _, _, err := store.ApplyPayment(paymentAdmission, now); err != nil {
		t.Fatal(err)
	}
	paymentAdmission.Scope = secondScope
	if _, _, _, err := store.ApplyPayment(
		paymentAdmission, now,
	); !errors.Is(err, ErrPaymentReplay) {
		t.Fatalf("cross-request payment replay error=%v", err)
	}
	second, err := store.Get(secondScope, now)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != StatePending || second.Revision != 1 {
		t.Fatalf("cross-request replay mutated request: %#v", second)
	}
}

func TestApplyPaymentConcurrentReplayHasOneWinner(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("payment-concurrent")
	if _, _, err := store.AdmitSession(
		testSessionAdmission(scope, testNonce(44), now, 5), now,
	); err != nil {
		t.Fatal(err)
	}
	admission := testPaymentAdmission(scope, now, 101)
	const attempts = 32
	var applied atomic.Int32
	var replayed atomic.Int32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, attempts)
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, disposition, err := store.ApplyPayment(admission, now)
			switch {
			case err != nil:
				errorsSeen <- err
			case disposition == PaymentApplied:
				applied.Add(1)
			case disposition == PaymentReplay:
				replayed.Add(1)
			default:
				errorsSeen <- fmt.Errorf("unexpected disposition %q", disposition)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	record, err := store.Get(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if applied.Load() != 1 || replayed.Load() != attempts-1 ||
		record.State != StateAuthorized || record.Revision != 2 ||
		stats.Payments != 1 {
		t.Fatalf(
			"applied=%d replayed=%d record=%#v stats=%#v",
			applied.Load(), replayed.Load(), record, stats,
		)
	}
}

func TestPaymentReorganizationBlocksPaidDispatch(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("payment-reorganized")
	if _, _, err := store.AdmitSession(
		testSessionAdmission(scope, testNonce(45), now, 5), now,
	); err != nil {
		t.Fatal(err)
	}
	admission := testPaymentAdmission(scope, now, 101)
	record, _, _, err := store.ApplyPayment(admission, now)
	if err != nil {
		t.Fatal(err)
	}
	reorganization := PaymentReorganization{
		Scope: scope, AuthorizationID: admission.AuthorizationID,
		QuoteID: admission.QuoteID, Reference: admission.Reference,
		ObservedMasterSeqno: 102, ObservedAt: now.Add(time.Second),
	}
	payment, disposition, err := store.MarkPaymentReorganized(
		reorganization, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PaymentReorganized ||
		payment.Status != PaymentStatusReorganized || payment.Revision != 2 {
		t.Fatalf("unexpected reorganization: %#v, %q", payment, disposition)
	}
	replayed, disposition, err := store.MarkPaymentReorganized(
		reorganization, now.Add(2*time.Second),
	)
	if err != nil || disposition != PaymentReplay || replayed != payment {
		t.Fatalf(
			"reorganization replay: payment=%#v disposition=%q err=%v",
			replayed, disposition, err,
		)
	}
	if _, _, _, err := store.ApplyPayment(
		admission, now.Add(2*time.Second),
	); !errors.Is(err, ErrPaymentReorganized) {
		t.Fatalf("reorganized payment application error=%v", err)
	}
	if _, err := store.Transition(
		scope, record.Revision, StateRunning, "", "", now.Add(2*time.Second),
	); !errors.Is(err, ErrPaymentReorganized) {
		t.Fatalf("reorganized paid dispatch error=%v", err)
	}
	rollback := reorganization
	rollback.ObservedMasterSeqno = 101
	rollback.ObservedAt = now
	if _, _, err := store.MarkPaymentReorganized(
		rollback, now.Add(2*time.Second),
	); !errors.Is(err, ErrPaymentRollback) {
		t.Fatalf("reorganization rollback error=%v", err)
	}
}

func TestPaymentStateSurvivesRestartAndExpiresWithRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := testLimits(100)
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("payment-restart")
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	admission := testPaymentAdmission(scope, now, 101)
	if _, _, err := store.Begin(
		scope, admission.IntentDigest, now, now.Add(time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ApplyPayment(admission, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	record, payment, disposition, err := reopened.ApplyPayment(
		admission, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != PaymentReplay ||
		record.State != StateAuthorized || payment.Status != PaymentStatusApplied {
		t.Fatalf(
			"restarted payment: record=%#v payment=%#v disposition=%q",
			record, payment, disposition,
		)
	}
	deleted, more, err := reopened.PruneExpired(now.Add(2*time.Millisecond), 1)
	if err != nil || deleted != 1 || more {
		t.Fatalf("prune payment request: deleted=%d more=%v err=%v", deleted, more, err)
	}
	stats, err := reopened.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 0 || stats.Payments != 0 {
		t.Fatalf("expired payment was retained: %#v", stats)
	}
	if _, err := reopened.GetPayment(
		scope, now.Add(2*time.Millisecond),
	); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired payment lookup error=%v", err)
	}
}

func TestPaymentScanCursorIsBoundedDurableAndCASProtected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := testLimits(100)
	limits.MaxPrunePerWrite = 2
	now := time.Unix(1_800_000_000, 0).UTC()
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 3 {
		scope := testScope(fmt.Sprintf("payment-scan-%d", index))
		admission := testPaymentAdmission(scope, now, 101)
		admission.AuthorizationID = fmt.Sprintf("authorization-scan-%d", index)
		admission.QuoteID = fmt.Sprintf("quote-scan-%d", index)
		admission.Reference = fmt.Sprintf("payment-reference-scan-%d", index)
		if _, _, err := store.Begin(
			scope, admission.IntentDigest, now, now.Add(time.Hour),
		); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.ApplyPayment(admission, now); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ScanPayments(now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Cursor != "" || first.NextCursor == "" ||
		first.Scanned != 2 || len(first.Payments) != 2 ||
		!first.HasMore || first.Wrapped {
		t.Fatalf("unexpected first payment scan: %#v", first)
	}
	replayed, err := store.ScanPayments(now, 2)
	if err != nil || replayed.Cursor != first.Cursor ||
		replayed.NextCursor != first.NextCursor {
		t.Fatalf("uncommitted scan was not replayed: %#v err=%v", replayed, err)
	}
	if err := store.AdvancePaymentScanCursor(
		first.Cursor, first.NextCursor,
	); err != nil {
		t.Fatal(err)
	}
	if err := store.AdvancePaymentScanCursor(
		first.Cursor, first.NextCursor,
	); !errors.Is(err, ErrPaymentScanCursor) {
		t.Fatalf("stale payment cursor advance error=%v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	second, err := reopened.ScanPayments(now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.Cursor != first.NextCursor ||
		second.NextCursor == "" || second.Scanned != 1 ||
		len(second.Payments) != 1 || second.HasMore || second.Wrapped {
		t.Fatalf("unexpected resumed payment scan: %#v", second)
	}
	if err := reopened.AdvancePaymentScanCursor(
		second.Cursor, second.NextCursor,
	); err != nil {
		t.Fatal(err)
	}
	wrapped, err := reopened.ScanPayments(now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !wrapped.Wrapped || wrapped.Scanned != 2 ||
		len(wrapped.Payments) != 2 || !wrapped.HasMore {
		t.Fatalf("unexpected wrapped payment scan: %#v", wrapped)
	}
}

func TestPaymentScanCountsExpiredEntriesTowardBound(t *testing.T) {
	limits := testLimits(100)
	limits.MaxPrunePerWrite = 2
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	for index, retention := range []time.Duration{time.Millisecond, time.Hour} {
		scope := testScope(fmt.Sprintf("payment-scan-expiry-%d", index))
		admission := testPaymentAdmission(scope, now, 101)
		admission.AuthorizationID = fmt.Sprintf("authorization-expiry-%d", index)
		admission.QuoteID = fmt.Sprintf("quote-expiry-%d", index)
		admission.Reference = fmt.Sprintf("payment-reference-expiry-%d", index)
		if _, _, err := store.Begin(
			scope, admission.IntentDigest, now, now.Add(retention),
		); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := store.ApplyPayment(admission, now); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := store.ScanPayments(now.Add(2*time.Millisecond), 2)
	if err != nil {
		t.Fatal(err)
	}
	if scan.Scanned != 2 || len(scan.Payments) != 1 {
		t.Fatalf("expired scan bypassed batch bound: %#v", scan)
	}
}

func TestApplyReceiptAtomicallyTerminatesPaidRequestAndReplays(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("receipt-request-0001")
	running, _ := preparePaidRunningRequest(t, store, scope, now)
	admission := testReceiptAdmission(scope, now.Add(time.Second), StateSucceeded)
	if _, err := store.Transition(
		scope, running.Revision, StateSucceeded,
		admission.ResultDigest, "", now.Add(time.Second),
	); err == nil || !strings.Contains(err.Error(), "requires a receipt") {
		t.Fatalf("paid request bypassed receipt application: %v", err)
	}
	record, receipt, disposition, err := store.ApplyReceipt(
		admission, running.Revision, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != ReceiptApplied ||
		record.State != StateSucceeded ||
		record.Revision != running.Revision+1 ||
		record.ResultDigest != admission.ResultDigest ||
		receipt.Status != StateSucceeded ||
		receipt.Revision != 1 {
		t.Fatalf(
			"unexpected receipt application: record=%#v receipt=%#v disposition=%q",
			record, receipt, disposition,
		)
	}
	replayedRecord, replayedReceipt, disposition, err := store.ApplyReceipt(
		admission, running.Revision, now.Add(2*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != ReceiptReplay ||
		replayedRecord != record ||
		!sameReceiptRecord(replayedReceipt, receipt) {
		t.Fatalf(
			"receipt replay changed state: record=%#v receipt=%#v disposition=%q",
			replayedRecord, replayedReceipt, disposition,
		)
	}
	receipt.Usage[0].Quantity = 999
	receipt.Envelope.Payload[0] ^= 1
	stored, err := store.GetReceipt(scope, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if stored.Usage[0].Quantity != 10 {
		t.Fatal("returned receipt aliased durable usage")
	}
	fingerprint, err := stored.Envelope.Fingerprint()
	if err != nil || fingerprint != stored.ReceiptEnvelopeDigest {
		t.Fatalf("stored signed receipt envelope: digest=%q err=%v", fingerprint, err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Payments != 1 || stats.Receipts != 1 {
		t.Fatalf("unexpected receipt stats: %#v", stats)
	}
}

func TestApplyReceiptConcurrentReplayHasOneWinner(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("receipt-concurrent-request")
	running, _ := preparePaidRunningRequest(t, store, scope, now)
	admission := testReceiptAdmission(
		scope,
		now.Add(time.Second),
		StateSucceeded,
	)
	const attempts = 32
	var applied atomic.Int32
	var replayed atomic.Int32
	var wait sync.WaitGroup
	errorsSeen := make(chan error, attempts)
	for range attempts {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, disposition, err := store.ApplyReceipt(
				admission,
				running.Revision,
				now.Add(time.Second),
			)
			switch {
			case err != nil:
				errorsSeen <- err
			case disposition == ReceiptApplied:
				applied.Add(1)
			case disposition == ReceiptReplay:
				replayed.Add(1)
			default:
				errorsSeen <- fmt.Errorf(
					"unexpected disposition %q",
					disposition,
				)
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	record, err := store.Get(scope, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if applied.Load() != 1 ||
		replayed.Load() != attempts-1 ||
		record.State != StateSucceeded ||
		record.Revision != running.Revision+1 ||
		stats.Receipts != 1 {
		t.Fatalf(
			"applied=%d replayed=%d record=%#v stats=%#v",
			applied.Load(),
			replayed.Load(),
			record,
			stats,
		)
	}
}

func TestApplyReceiptRejectsReplayChargeAndReorganization(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	firstScope := testScope("receipt-first-request")
	firstRunning, _ := preparePaidRunningRequest(
		t, store, firstScope, now,
	)
	firstReceipt := testReceiptAdmission(
		firstScope, now.Add(time.Second), StateSucceeded,
	)
	if _, _, _, err := store.ApplyReceipt(
		firstReceipt, firstRunning.Revision, now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}

	secondScope := testScope("receipt-second-request")
	secondPayment := testPaymentAdmission(secondScope, now, 101)
	secondPayment.AuthorizationID = "authorization-0002"
	secondPayment.QuoteID = "quote-0002"
	secondPayment.Reference = "payment-reference-0002"
	if _, _, err := store.Begin(
		secondScope, secondPayment.IntentDigest, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	secondAuthorized, _, _, err := store.ApplyPayment(secondPayment, now)
	if err != nil {
		t.Fatal(err)
	}
	secondRunning, err := store.Transition(
		secondScope, secondAuthorized.Revision, StateRunning, "", "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	replayedReceipt := testReceiptAdmission(
		secondScope, now.Add(time.Second), StateSucceeded,
	)
	replayedReceipt.AuthorizationID = secondPayment.AuthorizationID
	replayedReceipt.QuoteID = secondPayment.QuoteID
	refreshReceiptEnvelope(&replayedReceipt, now.Add(time.Second))
	if _, _, _, err := store.ApplyReceipt(
		replayedReceipt, secondRunning.Revision, now.Add(time.Second),
	); !errors.Is(err, ErrReceiptReplay) {
		t.Fatalf("cross-request receipt replay error=%v", err)
	}
	overcharged := replayedReceipt
	overcharged.ReceiptID = "receipt-0002"
	overcharged.ChargedNanoTOS = secondPayment.AmountNanoTOS + 1
	refreshReceiptEnvelope(&overcharged, now.Add(time.Second))
	if _, _, _, err := store.ApplyReceipt(
		overcharged, secondRunning.Revision, now.Add(time.Second),
	); err == nil {
		t.Fatal("receipt charge above applied payment accepted")
	}
	second, err := store.Get(secondScope, now)
	if err != nil {
		t.Fatal(err)
	}
	if second.State != StateRunning || second.Revision != secondRunning.Revision {
		t.Fatalf("rejected receipt mutated request: %#v", second)
	}

	reorganization := PaymentReorganization{
		Scope:               secondScope,
		AuthorizationID:     secondPayment.AuthorizationID,
		QuoteID:             secondPayment.QuoteID,
		Reference:           secondPayment.Reference,
		ObservedMasterSeqno: 102,
		ObservedAt:          now.Add(time.Second),
	}
	if _, _, err := store.MarkPaymentReorganized(
		reorganization, now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	valid := replayedReceipt
	valid.ReceiptID = "receipt-0003"
	refreshReceiptEnvelope(&valid, now.Add(time.Second))
	if _, _, _, err := store.ApplyReceipt(
		valid, secondRunning.Revision, now.Add(time.Second),
	); !errors.Is(err, ErrPaymentReorganized) {
		t.Fatalf("receipt after payment reorganization error=%v", err)
	}
}

func TestApplyReceiptRejectsSecondReceiptIDAsConflict(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("receipt-second-id-request")
	running, _ := preparePaidRunningRequest(t, store, scope, now)
	first := testReceiptAdmission(
		scope,
		now.Add(time.Second),
		StateSucceeded,
	)
	if _, _, _, err := store.ApplyReceipt(
		first,
		running.Revision,
		now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	second := first
	second.ReceiptID = "receipt-0002"
	refreshReceiptEnvelope(&second, now.Add(time.Second))
	if _, _, _, err := store.ApplyReceipt(
		second,
		running.Revision,
		now.Add(2*time.Second),
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("second receipt ID error=%v", err)
	}
}

func TestApplyReceiptAllowsAuthorizedTerminalFailure(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("receipt-authorized-failure")
	payment := testPaymentAdmission(scope, now, 101)
	if _, _, err := store.Begin(
		scope, payment.IntentDigest, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	authorized, _, _, err := store.ApplyPayment(payment, now)
	if err != nil {
		t.Fatal(err)
	}
	admission := testReceiptAdmission(
		scope, now.Add(time.Second), StateFailed,
	)
	record, receipt, disposition, err := store.ApplyReceipt(
		admission, authorized.Revision, now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != ReceiptApplied ||
		record.State != StateFailed ||
		record.ErrorCode != admission.ErrorCode ||
		receipt.Status != StateFailed {
		t.Fatalf(
			"authorized failure receipt: record=%#v receipt=%#v disposition=%q",
			record, receipt, disposition,
		)
	}
}

func TestReceiptSurvivesRestartAndExpiresWithRequest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := testLimits(100)
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("receipt-restart")
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	payment := testPaymentAdmission(scope, now, 101)
	if _, _, err := store.Begin(
		scope, payment.IntentDigest, now, now.Add(5*time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	authorized, _, _, err := store.ApplyPayment(payment, now)
	if err != nil {
		t.Fatal(err)
	}
	running, err := store.Transition(
		scope, authorized.Revision, StateRunning, "", "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	admission := testReceiptAdmission(
		scope, now.Add(time.Millisecond), StateSucceeded,
	)
	if _, _, _, err := store.ApplyReceipt(
		admission, running.Revision, now.Add(time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.GetReceipt(
		scope, now.Add(2*time.Millisecond),
	); err != nil {
		t.Fatal(err)
	}
	deleted, more, err := reopened.PruneExpired(
		now.Add(6*time.Millisecond), 1,
	)
	if err != nil || deleted != 1 || more {
		t.Fatalf(
			"prune receipted request: deleted=%d more=%v err=%v",
			deleted, more, err,
		)
	}
	stats, err := reopened.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 0 || stats.Payments != 0 || stats.Receipts != 0 {
		t.Fatalf("expired receipt state retained: %#v", stats)
	}
}

func TestAdmitSessionConcurrentBudgetLimit(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	const attempts = 32
	var admitted atomic.Int32
	var rejected atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < attempts; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			admission := testSessionAdmission(
				testScope(fmt.Sprintf("session-concurrent-%02d", index)),
				testNonce(byte(50+index)), now, 1,
			)
			for budgetIndex := range admission.Budgets {
				admission.Budgets[budgetIndex].MaxActions = 10
				admission.Budgets[budgetIndex].MaxNanoTOS = 10
			}
			_, _, err := store.AdmitSession(admission, now)
			switch {
			case err == nil:
				admitted.Add(1)
			case errors.Is(err, ErrBudgetLimit):
				rejected.Add(1)
			default:
				t.Errorf("admission %d: %v", index, err)
			}
		}(index)
	}
	wait.Wait()
	if admitted.Load() != 10 || rejected.Load() != attempts-10 {
		t.Fatalf("admitted=%d rejected=%d", admitted.Load(), rejected.Load())
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 10 || stats.Nonces != 10 || stats.BudgetUsages != 2 {
		t.Fatalf("unexpected concurrent session stats: %#v", stats)
	}
}

func TestSessionBudgetsPruneWithRetainedRequests(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testSessionAdmission(
		testScope("session-prune-1"), testNonce(90), now, 1,
	)
	if _, _, err := store.AdmitSession(admission, now); err != nil {
		t.Fatal(err)
	}
	pruneAt := admission.SessionExpiresAt.Add(time.Nanosecond)
	if _, _, err := store.PruneExpired(pruneAt, 16); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.PruneNonces(pruneAt, 16); err != nil {
		t.Fatal(err)
	}
	if deleted, more, err := store.PruneBudgets(
		pruneAt, 16,
	); err != nil || deleted != 2 || more {
		t.Fatalf("budget prune deleted=%d more=%v err=%v", deleted, more, err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 0 || stats.Nonces != 0 || stats.BudgetUsages != 0 {
		t.Fatalf("session state survived expiry: %#v", stats)
	}
}

func TestSessionBudgetSurvivesRestart(t *testing.T) {
	limits := testLimits(100)
	path := filepath.Join(t.TempDir(), "session-restart.db")
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	first := testSessionAdmission(
		testScope("session-restart-1"), testNonce(100), now, 5,
	)
	for index := range first.Budgets {
		first.Budgets[index].MaxActions = 1
		first.Budgets[index].MaxNanoTOS = 5
	}
	if _, _, err := store.AdmitSession(first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	second := testSessionAdmission(
		testScope("session-restart-2"), testNonce(101), now, 0,
	)
	for index := range second.Budgets {
		second.Budgets[index].MaxActions = 1
		second.Budgets[index].MaxNanoTOS = 5
	}
	if _, _, err := store.AdmitSession(
		second, now.Add(time.Second),
	); !errors.Is(err, ErrBudgetLimit) {
		t.Fatalf("restart lost cumulative budget: %v", err)
	}
}

func TestAdmitRejectsNonceReuseAcrossRequestsAndRollsBack(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	nonce := testNonce(3)
	first := testAdmission(testScope("request-first"), nonce, now)
	if _, _, err := store.Admit(first, now); err != nil {
		t.Fatal(err)
	}

	second := testAdmission(testScope("request-second"), nonce, now)
	if _, _, err := store.Admit(second, now); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("nonce reuse error = %v", err)
	}
	if _, err := store.Get(second.Scope, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("rejected request was persisted: %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Nonces != 1 {
		t.Fatalf("nonce rejection was not atomic: %#v", stats)
	}
}

func TestAdmitRejectsSameNonceWithDifferentEnvelopeFingerprint(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testAdmission(testScope("request-envelope-reuse"), testNonce(14), now)
	if _, disposition, err := store.Admit(admission, now); err != nil ||
		disposition != BeginCreated {
		t.Fatalf("initial admission disposition=%q error=%v", disposition, err)
	}
	changedEnvelope := admission
	changedEnvelope.EnvelopeDigest = "sha256:" + strings.Repeat("c", 64)
	if _, _, err := store.Admit(changedEnvelope, now); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("changed signed envelope reuse error = %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Nonces != 1 {
		t.Fatalf("rejected envelope changed durable state: %#v", stats)
	}
}

func TestAdmitRollsBackNewNonceOnIntentConflictOrCapacity(t *testing.T) {
	limits := testLimits(1)
	limits.MaxNonces = 10
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	first := testAdmission(testScope("request-first"), testNonce(4), now)
	if _, _, err := store.Admit(first, now); err != nil {
		t.Fatal(err)
	}

	conflict := first
	conflict.Nonce = testNonce(5)
	conflict.IntentDigest = "sha256:" + strings.Repeat("b", 64)
	if _, _, err := store.Admit(conflict, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("intent conflict error = %v", err)
	}
	overflow := testAdmission(testScope("request-overflow"), testNonce(6), now)
	if _, _, err := store.Admit(overflow, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 || stats.Nonces != 1 {
		t.Fatalf("failed admission leaked nonce state: %#v", stats)
	}
}

func TestStandaloneNonceClaimRejectsReplayAndPrunesByCapacity(t *testing.T) {
	limits := testLimits(10)
	limits.MaxNonces = 2
	limits.MaxPrunePerWrite = 1
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	firstScope := testScope("request-nonce-1")
	first := testNonceClaim(firstScope, testNonce(7), now.Add(time.Second))
	if err := store.ClaimNonce(first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.ClaimNonce(first, now); !errors.Is(err, ErrNonceReplay) {
		t.Fatalf("duplicate nonce claim error = %v", err)
	}
	secondScope := testScope("request-nonce-2")
	if err := store.ClaimNonce(
		testNonceClaim(secondScope, testNonce(8), now.Add(2*time.Second)), now,
	); err != nil {
		t.Fatal(err)
	}
	thirdScope := testScope("request-nonce-3")
	third := testNonceClaim(thirdScope, testNonce(9), now.Add(time.Hour))
	if err := store.ClaimNonce(third, now); !errors.Is(err, ErrCapacity) {
		t.Fatalf("nonce capacity error = %v", err)
	}
	later := now.Add(3 * time.Second)
	third.ExpiresAt = later.Add(time.Hour)
	if err := store.ClaimNonce(third, later); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nonces != 2 {
		t.Fatalf("nonce count = %d", stats.Nonces)
	}
	deleted, more, err := store.PruneNonces(later, 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || more {
		t.Fatalf("nonce prune deleted = %d, more = %v", deleted, more)
	}
}

func TestAdmissionRetentionMustCoverEnvelope(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testAdmission(testScope("request-short-retention"), testNonce(10), now)
	admission.RetainUntil = now.Add(30 * time.Second)
	if _, _, err := store.Admit(admission, now); err == nil {
		t.Fatal("request retention shorter than envelope accepted")
	}
}

func TestJournalPersistsAcrossRestartAndRestrictsPermissions(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "requests.db")
	limits := testLimits(100)
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-0002")
	intent := "sha256:" + strings.Repeat("d", 64)

	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := store.Begin(scope, intent, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(scope, record.Revision, StateAuthorized, "", "", now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("journal permissions = %o", info.Mode().Perm())
	}

	reopened, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	recovered, err := reopened.Get(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != StateAuthorized || recovered.Revision != 2 {
		t.Fatalf("unexpected recovered record: %#v", recovered)
	}
}

func TestJournalCapacityAndBoundedExpiryPruning(t *testing.T) {
	limits := testLimits(2)
	limits.MaxPrunePerWrite = 1
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	intent := "sha256:" + strings.Repeat("e", 64)

	if _, _, err := store.Begin(testScope("request-0001"), intent, now, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(testScope("request-0002"), intent, now, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(
		testScope("request-0003"), intent, now, now.Add(time.Hour),
	); !errors.Is(err, ErrCapacity) {
		t.Fatalf("capacity error = %v", err)
	}
	later := now.Add(3 * time.Second)
	if _, _, err := store.Begin(
		testScope("request-0003"), intent, later, later.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 2 {
		t.Fatalf("record count = %d", stats.Records)
	}
	deleted, more, err := store.PruneExpired(later, 1)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || more {
		t.Fatalf("deleted = %d, more = %v", deleted, more)
	}
}

func TestBeginCanReplaceExpiredRecordBeyondAutomaticPruneBatch(t *testing.T) {
	limits := testLimits(3)
	limits.MaxPrunePerWrite = 1
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	for index, requestID := range []string{"request-0001", "request-0002", "request-target"} {
		if _, _, err := store.Begin(
			testScope(requestID),
			"sha256:"+strings.Repeat(string(rune('a'+index)), 64),
			now, now.Add(time.Duration(index+1)*time.Second),
		); err != nil {
			t.Fatal(err)
		}
	}
	later := now.Add(4 * time.Second)
	record, disposition, err := store.Begin(
		testScope("request-target"),
		"sha256:"+strings.Repeat("f", 64),
		later, later.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != BeginCreated || record.IntentDigest != "sha256:"+strings.Repeat("f", 64) {
		t.Fatalf("expired ID was not safely rebound: %#v, %q", record, disposition)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 2 {
		t.Fatalf("record count = %d", stats.Records)
	}
}

func TestPruneReportsMoreWithoutCorruptingCount(t *testing.T) {
	limits := testLimits(3)
	limits.MaxPrunePerWrite = 2
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	intent := "sha256:" + strings.Repeat("f", 64)
	for index := 1; index <= 3; index++ {
		requestID := "request-000" + string(rune('0'+index))
		if _, _, err := store.Begin(testScope(requestID), intent, now, now.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	deleted, more, err := store.PruneExpired(now.Add(time.Second), 2)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 2 || !more {
		t.Fatalf("deleted = %d, more = %v", deleted, more)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 1 {
		t.Fatalf("record count after first prune = %d", stats.Records)
	}
	deleted, more, err = store.PruneExpired(now.Add(time.Second), 2)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || more {
		t.Fatalf("second prune deleted = %d, more = %v", deleted, more)
	}
}

func TestPrunePreservesFutureRecordWithinSameMillisecond(t *testing.T) {
	store, _ := openTestStore(t, testLimits(10))
	now := time.Unix(1_800_000_000, 100_000).UTC()
	retainUntil := now.Add(500 * time.Microsecond)
	if _, _, err := store.Begin(
		testScope("request-submillisecond"),
		"sha256:"+strings.Repeat("0", 64),
		now, retainUntil,
	); err != nil {
		t.Fatal(err)
	}
	deleted, more, err := store.PruneExpired(now.Add(250*time.Microsecond), 10)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 0 || more {
		t.Fatalf("future record pruned: deleted = %d, more = %v", deleted, more)
	}
	if _, err := store.Get(testScope("request-submillisecond"), now); err != nil {
		t.Fatal(err)
	}
	deleted, more, err = store.PruneExpired(retainUntil, 10)
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 || more {
		t.Fatalf("expired record retained: deleted = %d, more = %v", deleted, more)
	}
}

func TestConcurrentBeginCreatesExactlyOneRecord(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-concurrent")
	intent := "sha256:" + strings.Repeat("1", 64)
	var created atomic.Int64
	var replayed atomic.Int64
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 64)

	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, disposition, err := store.Begin(scope, intent, now, now.Add(time.Hour))
			if err != nil {
				errorsSeen <- err
				return
			}
			switch disposition {
			case BeginCreated:
				created.Add(1)
			case BeginReplay:
				replayed.Add(1)
			default:
				errorsSeen <- errors.New("unexpected begin disposition")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	if created.Load() != 1 || replayed.Load() != 63 {
		t.Fatalf("created = %d, replayed = %d", created.Load(), replayed.Load())
	}
}

func TestConcurrentAdmitCreatesOneNonceAndRequest(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testAdmission(testScope("request-concurrent-admit"), testNonce(11), now)
	var created atomic.Int64
	var replayed atomic.Int64
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 64)

	for index := 0; index < 64; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, disposition, err := store.Admit(admission, now)
			if err != nil {
				errorsSeen <- err
				return
			}
			switch disposition {
			case BeginCreated:
				created.Add(1)
			case BeginReplay:
				replayed.Add(1)
			default:
				errorsSeen <- errors.New("unexpected admission disposition")
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if created.Load() != 1 || replayed.Load() != 63 ||
		stats.Records != 1 || stats.Nonces != 1 {
		t.Fatalf(
			"created=%d replayed=%d records=%d nonces=%d",
			created.Load(), replayed.Load(), stats.Records, stats.Nonces,
		)
	}
}

func TestConcurrentTransitionAllowsOneWinner(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-transition")
	record, _, err := store.Begin(
		scope, "sha256:"+strings.Repeat("4", 64), now, now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err = store.Transition(scope, record.Revision, StateAuthorized, "", "", now)
	if err != nil {
		t.Fatal(err)
	}

	var succeeded atomic.Int64
	var stale atomic.Int64
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, transitionErr := store.Transition(
				scope, record.Revision, StateRunning, "", "", now,
			)
			switch {
			case transitionErr == nil:
				succeeded.Add(1)
			case errors.Is(transitionErr, ErrRevision):
				stale.Add(1)
			default:
				errorsSeen <- transitionErr
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for transitionErr := range errorsSeen {
		t.Error(transitionErr)
	}
	if succeeded.Load() != 1 || stale.Load() != 31 {
		t.Fatalf("succeeded = %d, stale = %d", succeeded.Load(), stale.Load())
	}
}

func TestJournalRecoversCommittedStateAfterAbruptExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	command := exec.Command(os.Args[0], "-test.run=^TestJournalCrashWriter$")
	command.Env = append(os.Environ(), "TOS_JOURNAL_CRASH_TEST_PATH="+path)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("crash writer failed: %v\n%s", err, output)
	}

	store, err := Open(path, testLimits(100))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	record, err := store.Get(
		testScope("request-crash"), time.Unix(1_800_000_000, 0).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if record.State != StateAuthorized || record.Revision != 2 {
		t.Fatalf("unexpected recovered crash record: %#v", record)
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nonces != 1 {
		t.Fatalf("recovered nonce count = %d", stats.Nonces)
	}
}

func TestJournalCrashWriter(t *testing.T) {
	path := os.Getenv("TOS_JOURNAL_CRASH_TEST_PATH")
	if path == "" {
		return
	}
	store, err := Open(path, testLimits(100))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	admission := testAdmission(testScope("request-crash"), testNonce(12), now)
	admission.IntentDigest = "sha256:" + strings.Repeat("5", 64)
	record, _, err := store.Admit(
		admission, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Transition(
		record.Scope, record.Revision, StateAuthorized, "", "", now,
	); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestJournalFailsClosedOnCorruptRecord(t *testing.T) {
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-corrupt")
	intent := "sha256:" + strings.Repeat("2", 64)
	if _, _, err := store.Begin(scope, intent, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	key := scopeKey(scope)
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		return transaction.Bucket(recordsBucket).Put(
			key[:], []byte(`{"version":"1","version":"2"}`),
		)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(scope, now); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corrupt record error = %v", err)
	}
}

func TestJournalFailsClosedOnMissingNonceExpiryIndexAtOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := testLimits(100)
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	claim := testNonceClaim(
		testScope("request-corrupt-nonce"), testNonce(13), now.Add(time.Hour),
	)
	if err := store.ClaimNonce(claim, now); err != nil {
		t.Fatal(err)
	}
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		cursor := transaction.Bucket(nonceExpiryBucket).Cursor()
		key, _ := cursor.First()
		if key == nil {
			return errors.New("missing test nonce expiry")
		}
		return cursor.Delete()
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, limits)
	if err == nil {
		reopened.Close()
		t.Fatal("journal with a missing nonce expiry index reopened")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing nonce expiry error = %v", err)
	}
}

func TestJournalFailsClosedOnMissingReceiptIndexAtOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := testLimits(100)
	store, err := Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := testScope("request-corrupt-receipt")
	running, _ := preparePaidRunningRequest(t, store, scope, now)
	admission := testReceiptAdmission(
		scope, now.Add(time.Second), StateSucceeded,
	)
	if _, _, _, err := store.ApplyReceipt(
		admission, running.Revision, now.Add(time.Second),
	); err != nil {
		t.Fatal(err)
	}
	key := scopeKey(scope)
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		return transaction.Bucket(requestReceiptsBucket).Delete(
			key[:],
		)
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, limits)
	if err == nil {
		reopened.Close()
		t.Fatal("journal with a missing receipt index reopened")
	}
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("missing receipt index error=%v", err)
	}
}

func TestOpenAndRetentionLimits(t *testing.T) {
	if _, err := Open("relative.db", DefaultLimits()); err == nil {
		t.Fatal("relative journal path accepted")
	}
	oversizedBatch := DefaultLimits()
	oversizedBatch.MaxRecords = maxConfiguredBatch + 1
	oversizedBatch.MaxPrunePerWrite = maxConfiguredBatch + 1
	if _, err := Open(
		filepath.Join(t.TempDir(), "oversized-batch.db"),
		oversizedBatch,
	); err == nil {
		t.Fatal("excessive journal batch size accepted")
	}
	store, _ := openTestStore(t, testLimits(100))
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, _, err := store.Begin(
		testScope("request-retention"),
		"sha256:"+strings.Repeat("3", 64),
		now, now.Add(store.limits.MaxRetention+time.Second),
	); err == nil {
		t.Fatal("excessive retention accepted")
	}
}

func TestBoundedChurnReusesJournalCapacity(t *testing.T) {
	limits := testLimits(32)
	limits.MaxPrunePerWrite = 32
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()
	intent := "sha256:" + strings.Repeat("6", 64)

	for round := 0; round < 20; round++ {
		for index := 0; index < 32; index++ {
			scope := testScope(fmt.Sprintf("request-%04d-%04d", round, index))
			if _, _, err := store.Begin(
				scope, intent, now, now.Add(time.Millisecond),
			); err != nil {
				t.Fatal(err)
			}
		}
		now = now.Add(2 * time.Millisecond)
		deleted, more, err := store.PruneExpired(now, 32)
		if err != nil {
			t.Fatal(err)
		}
		if deleted != 32 || more {
			t.Fatalf("round %d: deleted = %d, more = %v", round, deleted, more)
		}
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Records != 0 || stats.FileSize > 4<<20 {
		t.Fatalf("bounded churn stats: %#v", stats)
	}
}

func TestBoundedNonceChurnReusesJournalCapacity(t *testing.T) {
	limits := testLimits(32)
	limits.MaxNonces = 32
	limits.MaxPrunePerWrite = 32
	store, _ := openTestStore(t, limits)
	now := time.Unix(1_800_000_000, 0).UTC()

	for round := 0; round < 20; round++ {
		for index := 0; index < 32; index++ {
			scope := testScope(fmt.Sprintf("nonce-%04d-%04d", round, index))
			nonce := testNonce(byte(index))
			claim := testNonceClaim(scope, nonce, now.Add(time.Millisecond))
			if err := store.ClaimNonce(claim, now); err != nil {
				t.Fatal(err)
			}
		}
		now = now.Add(2 * time.Millisecond)
		deleted, more, err := store.PruneNonces(now, 32)
		if err != nil {
			t.Fatal(err)
		}
		if deleted != 32 || more {
			t.Fatalf(
				"round %d: deleted nonces = %d, more = %v",
				round, deleted, more,
			)
		}
	}
	stats, err := store.Stats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Nonces != 0 || stats.FileSize > 4<<20 {
		t.Fatalf("bounded nonce churn stats: %#v", stats)
	}
}
