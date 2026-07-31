package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
)

func coreScope() journal.Scope {
	return journal.Scope{
		Network: "testnet", Authority: "runtime-key-1",
		ServiceID: "edge.example.ai", SessionID: "session-0001",
		Operation: "invoke", RequestID: "request-0001",
	}
}

func TestCoreOwnsDurableRequestLifecycle(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	record, disposition, err := core.BeginRequest(
		coreScope(), "sha256:"+strings.Repeat("a", 64), now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != journal.BeginCreated {
		t.Fatalf("disposition = %q", disposition)
	}
	record, err = core.TransitionRequest(
		coreScope(), record.Revision, journal.StateAuthorized, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := core.Request(coreScope())
	if err != nil {
		t.Fatal(err)
	}
	if recovered != record {
		t.Fatalf("request mismatch: %#v != %#v", recovered, record)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 1 || health.JournalFileBytes == 0 {
		t.Fatalf("unexpected health: %#v", health)
	}
}

func TestCoreAdmitsVerifiedEnvelopeAtomically(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := identity.Sign(
		privateKey, "tos.invoke.v1", coreScope().Authority,
		[]byte("canonical request intent"), now.Add(-time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Verify(publicKey, "tos.invoke.v1", now); err != nil {
		t.Fatal(err)
	}
	intent := "sha256:" + strings.Repeat("9", 64)
	record, disposition, err := core.AdmitVerifiedEnvelope(
		coreScope(), intent, envelope, now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != journal.BeginCreated || record.Scope != coreScope() {
		t.Fatalf("unexpected admission: %#v, %q", record, disposition)
	}
	replayed, disposition, err := core.AdmitVerifiedEnvelope(
		coreScope(), intent, envelope, now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != journal.BeginReplay || replayed != record {
		t.Fatalf("unexpected replay: %#v, %q", replayed, disposition)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 1 || health.NonceClaims != 1 {
		t.Fatalf("unexpected health after admission: %#v", health)
	}
}

func TestCoreRejectsEnvelopeAuthorityMismatchBeforeClaim(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := identity.Sign(
		privateKey, "tos.invoke.v1", "different-runtime-key",
		[]byte("canonical request intent"), now.Add(-time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.AdmitVerifiedEnvelope(
		coreScope(), "sha256:"+strings.Repeat("8", 64),
		envelope, now.Add(time.Hour),
	); err == nil {
		t.Fatal("mismatched envelope authority accepted")
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 0 || health.NonceClaims != 0 {
		t.Fatalf("rejected envelope changed durable state: %#v", health)
	}
}

func TestCoreCleanupLoopExpiresInBoundedBatch(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.RequestJournalLimits.MaxRecords = 2
	config.RequestJournalLimits.MaxPrunePerWrite = 1
	config.CleanupInterval = 10 * time.Millisecond
	now := time.Unix(1_800_000_000, 0).UTC()
	var clockMu sync.RWMutex
	clock := func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return now
	}
	core, err := openCore(config, clock)
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	for index, requestID := range []string{"request-0001", "request-0002"} {
		scope := coreScope()
		scope.RequestID = requestID
		if _, _, err := core.BeginRequest(
			scope, "sha256:"+strings.Repeat(string(rune('a'+index)), 64),
			now.Add(time.Second),
		); err != nil {
			t.Fatal(err)
		}
	}
	clockMu.Lock()
	now = now.Add(2 * time.Second)
	clockMu.Unlock()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		health, healthErr := core.Health()
		if healthErr == nil && health.RequestRecords == 0 &&
			health.LastCleanupSucceeded {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	health, healthErr := core.Health()
	t.Fatalf("cleanup did not converge: health=%#v error=%v", health, healthErr)
}

func TestCoreRejectsInvalidCleanupConfiguration(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = 0
	if _, err := OpenCore(config); err == nil {
		t.Fatal("zero cleanup interval accepted")
	}
}

func TestCorePreservesIntentConflict(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if _, _, err := core.BeginRequest(
		coreScope(), "sha256:"+strings.Repeat("a", 64), now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := core.BeginRequest(
		coreScope(), "sha256:"+strings.Repeat("b", 64), now.Add(time.Hour),
	); !errors.Is(err, journal.ErrConflict) {
		t.Fatalf("conflict error = %v", err)
	}
}
