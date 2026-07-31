package journal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
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

func TestOpenAndRetentionLimits(t *testing.T) {
	if _, err := Open("relative.db", DefaultLimits()); err == nil {
		t.Fatal("relative journal path accepted")
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
