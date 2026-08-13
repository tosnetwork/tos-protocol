package nativeregistrypublisher

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
)

type backendStub struct {
	calls         int
	prepareCalls  int
	recovering    []bool
	prepared      []PreparedMutation
	returnErrOnce error
	canonical     *Receipt
	resolveErr    error
}

func (b *backendStub) CheckReady(context.Context, Policy) error { return nil }
func (b *backendStub) EnrollmentBinding() string                { return "sha256:backend" }
func (b *backendStub) Close() error                             { return nil }
func (b *backendStub) Prepare(context.Context, nativeregistry.Submission) (PreparedMutation, error) {
	b.prepareCalls++
	return PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "Ym9j", MessageDigest: "sha256:prepared"}, nil
}
func (b *backendStub) Resolve(context.Context, nativeregistry.Submission) (Receipt, error) {
	if b.resolveErr != nil {
		return Receipt{}, b.resolveErr
	}
	if b.canonical != nil {
		return *b.canonical, nil
	}
	return Receipt{}, nativeregistry.ErrPublisherNotFound
}
func (b *backendStub) Publish(_ context.Context, _ nativeregistry.Submission, prepared PreparedMutation, recovering bool) (Receipt, error) {
	b.calls++
	b.recovering = append(b.recovering, recovering)
	b.prepared = append(b.prepared, prepared)
	receipt := Receipt{TransactionReference: "tx:1"}
	b.canonical = &receipt
	if b.returnErrOnce != nil {
		err := b.returnErrOnce
		b.returnErrOnce = nil
		return Receipt{}, err
	}
	return receipt, nil
}

func testPolicy() Policy {
	return Policy{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32), RegistryWorkchain: 0, ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("33", 32), LocatorVersion: nativeexecution.LocatorVersion, ActionVersion: nativeexecution.Version, PayerIdentity: "0:" + strings.Repeat("44", 32)}
}

func validPublisherSubmission(t *testing.T) nativeregistry.Submission {
	t.Helper()
	network := nativeprotocol.NetworkDomain{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	publicKey := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey))
	controller := nativeprotocol.ControllerPolicy{Threshold: 1, RecoveryThreshold: 1,
		Controllers:    []nativeprotocol.ControllerKey{{KeyID: "root", Algorithm: "ed25519", PublicKeyBase64: publicKey, Weight: 1, Purposes: []string{"agent_control", "recovery"}}},
		RecoveryKeyIDs: []string{"root"}, RecoveryTimelock: 60}
	policyCBOR, policyDigest, err := nativeprotocol.EncodeControllerPolicy(controller)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString([]byte("01234567890123456789012345678901"))
	agentID, err := nativeprotocol.AgentID(nativeprotocol.AgentBootstrap{Version: nativeprotocol.Version, Network: network, ObjectNonceBase64: nonce, InitialControllerPolicy: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	payload, payloadDigest, err := nativeprotocol.EncodePayload(nativeprotocol.ActionRegisterAgent, nativeprotocol.RegisterAgentPayload{ObjectNonceBase64: nonce, InitialPolicyDigest: policyDigest, InitialPolicyCBORBase64: policyCBOR})
	if err != nil {
		t.Fatal(err)
	}
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: nativeprotocol.ActionRegisterAgent, Network: network,
		AgentID: agentID, Generation: 1, Sequence: 1, PolicyDigest: policyDigest,
		PayloadDigest: payloadDigest, PayloadCBORBase64: payload, NonceBase64: nonce}
	return nativeregistry.Submission{Version: nativeprotocol.Version, Action: action}
}

func TestJournalRequiresExplicitEnrollmentAndPinsBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{}
	if _, err := Open(path, "journal-a", testPolicy(), backend); err == nil {
		t.Fatal("missing journal was silently initialized")
	}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, "journal-b", testPolicy(), backend); err == nil {
		t.Fatal("journal identity substitution accepted")
	}
	changed := testPolicy()
	changed.RegistryWorkchain = -1
	if _, err := Open(path, "journal-a", changed, backend); err == nil {
		t.Fatal("enrollment policy substitution accepted")
	}
}

func TestPendingRecoveryNeverStartsSecondBroadcast(t *testing.T) {
	// validateEnvelope is covered by nativeregistry. This test operates at the
	// durable store boundary to prove that a lost response becomes recovery.
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{returnErrOnce: errors.New("lost response")}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	store, err := openActionStore(path, "journal-a", testPolicy(), backend.EnrollmentBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	submission := nativeregistry.Submission{Version: "tos_native_registry_v1"}
	if _, err := store.claim("action-1", "digest-1", submission); err != nil {
		t.Fatal(err)
	}
	if err := store.prepare("action-1", "digest-1", PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "Ym9j", MessageDigest: "sha256:prepared"}); err != nil {
		t.Fatal(err)
	}
	if err := store.markAttempt("action-1", "digest-1"); err != nil {
		t.Fatal(err)
	}
	record, err := store.claim("action-1", "digest-1", submission)
	if err != nil || record.Attempts != 1 || record.State != statePending {
		t.Fatalf("pending recovery record: %+v err=%v", record, err)
	}
}

func TestLostResponseRecoveryCompletesWithoutSecondBroadcast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{returnErrOnce: errors.New("lost response")}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	publisher, err := Open(path, "journal-a", testPolicy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	submission := validPublisherSubmission(t)
	id, digest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	if err := publisher.Publish(context.Background(), submission, id, digest); err == nil {
		t.Fatal("lost response was reported successful")
	}
	if backend.calls != 1 {
		t.Fatalf("first attempt made %d broadcasts", backend.calls)
	}
	if err := publisher.Publish(context.Background(), submission, id, digest); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 {
		t.Fatalf("recovery made %d broadcasts", backend.calls)
	}
	if err := publisher.Close(); err != nil {
		t.Fatal(err)
	}
	publisher, err = Open(path, "journal-a", testPolicy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if err := publisher.Resolve(context.Background(), submission, id, digest); err != nil {
		t.Fatal(err)
	}
}

func TestCompletedRecordCannotRegressOrConflict(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	store, err := openActionStore(path, "journal-a", testPolicy(), backend.EnrollmentBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.claim("action-1", "digest-1", nativeregistry.Submission{Version: "tos_native_registry_v1"}); err != nil {
		t.Fatal(err)
	}
	if err := store.prepare("action-1", "digest-1", PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "Ym9j", MessageDigest: "sha256:prepared"}); err != nil {
		t.Fatal(err)
	}
	if err := store.complete("action-1", "digest-1", Receipt{TransactionReference: "tx:1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.claim("action-1", "digest-2", nativeregistry.Submission{}); err == nil {
		t.Fatal("changed semantics accepted")
	}
	if err := store.complete("action-1", "digest-1", Receipt{TransactionReference: "tx:2"}); err == nil {
		t.Fatal("terminal receipt changed")
	}
}

func TestPreparedMessageSurvivesCrashBeforeBroadcast(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	submission := validPublisherSubmission(t)
	id, digest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	store, err := openActionStore(path, "journal-a", testPolicy(), backend.EnrollmentBinding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.claim(id, digest, submission); err != nil {
		t.Fatal(err)
	}
	durable := PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "c2lnbmVkLW1lc3NhZ2U=", MessageDigest: "sha256:durable"}
	if err = store.prepare(id, digest, durable); err != nil {
		t.Fatal(err)
	}
	if err = store.close(); err != nil {
		t.Fatal(err)
	}
	publisher, err := Open(path, "journal-a", testPolicy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if err = publisher.Publish(context.Background(), submission, id, digest); err != nil {
		t.Fatal(err)
	}
	if backend.prepareCalls != 0 || backend.calls != 1 || len(backend.prepared) != 1 || backend.prepared[0] != durable {
		t.Fatalf("prepared crash recovery changed bytes: prepares=%d publishes=%d values=%+v", backend.prepareCalls, backend.calls, backend.prepared)
	}
}

func TestPreparedMessageSurvivesCrashAfterBroadcastBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	submission := validPublisherSubmission(t)
	id, digest, _ := nativeregistry.ValidateSubmission(submission)
	store, err := openActionStore(path, "journal-a", testPolicy(), backend.EnrollmentBinding())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = store.claim(id, digest, submission)
	durable := PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "c2lnbmVkLW1lc3NhZ2U=", MessageDigest: "sha256:durable"}
	if err = store.prepare(id, digest, durable); err != nil {
		t.Fatal(err)
	}
	if err = store.markAttempt(id, digest); err != nil {
		t.Fatal(err)
	}
	_ = store.close()
	publisher, err := Open(path, "journal-a", testPolicy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	if err = publisher.Publish(context.Background(), submission, id, digest); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 || !backend.recovering[0] || backend.prepared[0] != durable {
		t.Fatalf("broadcast-boundary recovery did not reuse exact bytes: %+v", backend)
	}
}

func TestConcurrentIndependentRelayersConvergeOnOneMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	backend := &backendStub{}
	if err := InitializeJournal(path, "journal-a", testPolicy(), backend.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	publisher, err := Open(path, "journal-a", testPolicy(), backend)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	submission := validPublisherSubmission(t)
	id, digest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	errorsOut := make(chan error, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	for i := 0; i < 2; i++ {
		go func() {
			ready.Done()
			<-start
			errorsOut <- publisher.Publish(context.Background(), submission, id, digest)
		}()
	}
	ready.Wait()
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-errorsOut; err != nil {
			t.Fatal(err)
		}
	}
	if backend.calls != 1 || backend.prepareCalls != 1 {
		t.Fatalf("concurrent relayers prepared=%d broadcast=%d, want exactly one", backend.prepareCalls, backend.calls)
	}
}

func TestPhase5BPublisherCrashHelper(t *testing.T) {
	if os.Getenv("GO_WANT_PHASE5B_CRASH_HELPER") != "1" {
		return
	}
	path, stage := os.Getenv("PHASE5B_CRASH_JOURNAL"), os.Getenv("PHASE5B_CRASH_STAGE")
	store, err := openActionStore(path, "journal-a", testPolicy(), "sha256:backend")
	if err != nil {
		t.Fatal(err)
	}
	submission := validPublisherSubmission(t)
	id, digest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.claim(id, digest, submission); err != nil {
		t.Fatal(err)
	}
	prepared := PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "c2lnbmVkLW1lc3NhZ2U=", MessageDigest: "sha256:durable"}
	if err = store.prepare(id, digest, prepared); err != nil {
		t.Fatal(err)
	}
	if stage == "attempt" || stage == "completed" {
		if err = store.markAttempt(id, digest); err != nil {
			t.Fatal(err)
		}
	}
	if stage == "completed" {
		if err = store.complete(id, digest, Receipt{TransactionReference: "tx:1"}); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately do not close bbolt. SIGKILL models process termination at
	// the exact durable boundary; the parent must recover the journal.
	process, _ := os.FindProcess(os.Getpid())
	_ = process.Kill()
}

func TestPublisherProcessKillRecoveryMatrix(t *testing.T) {
	for _, stage := range []string{"prepared", "attempt", "completed"} {
		t.Run(stage, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.db")
			if err := InitializeJournal(path, "journal-a", testPolicy(), "sha256:backend"); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestPhase5BPublisherCrashHelper$")
			command.Env = append(os.Environ(), "GO_WANT_PHASE5B_CRASH_HELPER=1", "PHASE5B_CRASH_JOURNAL="+path, "PHASE5B_CRASH_STAGE="+stage)
			if err := command.Run(); err == nil {
				t.Fatal("crash helper exited normally")
			}
			backend := &backendStub{}
			if stage == "completed" {
				backend.canonical = &Receipt{TransactionReference: "tx:1"}
			}
			publisher, err := Open(path, "journal-a", testPolicy(), backend)
			if err != nil {
				t.Fatalf("open killed journal: %v", err)
			}
			defer publisher.Close()
			submission := validPublisherSubmission(t)
			id, digest, _ := nativeregistry.ValidateSubmission(submission)
			if err := publisher.Publish(context.Background(), submission, id, digest); err != nil {
				t.Fatal(err)
			}
			if stage == "completed" {
				if backend.calls != 0 || backend.prepareCalls != 0 {
					t.Fatalf("completed crash replay mutated: %+v", backend)
				}
			} else if backend.calls != 1 || backend.prepareCalls != 0 || backend.prepared[0].MessageDigest != "sha256:durable" {
				t.Fatalf("%s crash did not reuse durable prepared bytes: %+v", stage, backend)
			}
		})
	}
}
