package edge

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func coreScope() journal.Scope {
	return journal.Scope{
		Network: "testnet", Authority: "runtime-key-1",
		ServiceID: "edge.example.ai", SessionID: "session-0001",
		Operation: "invoke", RequestID: "request-0001",
	}
}

type corePayload struct {
	RequestID string `json:"requestId"`
	SessionID string `json:"sessionId"`
	Operation string `json:"operation"`
}

func authorizedCoreEnvelope(
	t *testing.T,
	now time.Time,
) authorization.AuthorizedEnvelope {
	t.Helper()
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	scope := coreScope()
	manifest := protocol.ServiceManifest{
		Version: protocol.ManifestVersion, ManifestID: "manifest-0001",
		ServiceID: scope.ServiceID, Controller: "tos:test:controller",
		Network: scope.Network, Revision: "manifest-revision-1",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		RuntimeKeys: []protocol.RuntimeKey{{
			KeyID: scope.Authority, Algorithm: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(runtimePublic),
			Roles:     []string{protocol.RuntimeRoleAuthenticate},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		}},
		Endpoints: []protocol.ServiceEndpoint{{
			Transport: "https", Audience: "authenticated",
			URL: "https://edge.example/v1",
		}},
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1.0",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://edge.example/.well-known/tos-inference.json",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
	manifestEnvelope, err := identity.SignCanonical(
		controllerPrivate, protocol.ServiceManifestDomain,
		manifest.Controller, manifest, manifest.IssuedAt, manifest.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := codec.Digest(protocol.ServiceManifestDomain, manifest)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := authorization.NewVerifier(authorization.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifier.VerifyManifest(
		authorization.AuthoritySnapshot{
			Active: true, Network: scope.Network, ServiceID: scope.ServiceID,
			Controller: manifest.Controller, ControllerPublicKey: controllerPublic,
			ManifestDigest: manifestDigest, ObservedAt: now,
		},
		manifestEnvelope,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := corePayload{
		RequestID: scope.RequestID, SessionID: scope.SessionID,
		Operation: scope.Operation,
	}
	runtimeEnvelope, err := identity.SignCanonical(
		runtimePrivate, "tos.invoke.v1", scope.Authority,
		payload, now.Add(-time.Second), now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := verified.AuthorizeRuntimeEnvelope(
		runtimeEnvelope, "tos.invoke.v1", protocol.RuntimeRoleAuthenticate,
		now,
		authorization.AdmissionBinding{
			SessionID: scope.SessionID, Operation: scope.Operation,
			RequestID:    scope.RequestID,
			IntentDigest: "sha256:" + strings.Repeat("9", 64),
		},
		func(encoded []byte) error {
			var decoded corePayload
			if err := codec.Unmarshal(encoded, &decoded); err != nil {
				return err
			}
			if decoded != payload {
				return errors.New("core payload binding mismatch")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return authorized
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

func TestCoreAdmitsAuthorizedEnvelopeAtomically(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	authorized := authorizedCoreEnvelope(t, now)
	intent := "sha256:" + strings.Repeat("9", 64)
	record, disposition, err := core.AdmitAuthorizedEnvelope(
		coreScope(), intent, authorized, now.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if disposition != journal.BeginCreated || record.Scope != coreScope() {
		t.Fatalf("unexpected admission: %#v, %q", record, disposition)
	}
	replayed, disposition, err := core.AdmitAuthorizedEnvelope(
		coreScope(), intent, authorized, now.Add(time.Hour),
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

func TestCoreRejectsAuthorizationScopeMismatchBeforeClaim(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	authorized := authorizedCoreEnvelope(t, now)
	mismatched := coreScope()
	mismatched.Authority = "different-runtime-key"
	if _, _, err := core.AdmitAuthorizedEnvelope(
		mismatched, "sha256:"+strings.Repeat("9", 64),
		authorized, now.Add(time.Hour),
	); err == nil {
		t.Fatal("mismatched authorization scope accepted")
	}
	if _, _, err := core.AdmitAuthorizedEnvelope(
		coreScope(), "sha256:"+strings.Repeat("8", 64),
		authorized, now.Add(time.Hour),
	); err == nil {
		t.Fatal("mismatched authorization intent accepted")
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
