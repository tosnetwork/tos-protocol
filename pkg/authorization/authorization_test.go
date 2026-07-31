package authorization

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const runtimeDomain = "tos.invoke.v1"

type testPayload struct {
	RequestID string `json:"requestId"`
	SessionID string `json:"sessionId"`
	Operation string `json:"operation"`
}

type authFixture struct {
	now               time.Time
	controllerPrivate ed25519.PrivateKey
	runtimePrivate    ed25519.PrivateKey
	manifest          protocol.ServiceManifest
	manifestEnvelope  identity.Envelope
	snapshot          AuthoritySnapshot
}

func newAuthFixture(t *testing.T) authFixture {
	t.Helper()
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	manifest := protocol.ServiceManifest{
		Version: protocol.ManifestVersion, ManifestID: "manifest-0001",
		ServiceID: "edge.example.ai", Controller: "tos:test:controller",
		Network: "testnet", Revision: "manifest-revision-1",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute),
		RuntimeKeys: []protocol.RuntimeKey{{
			KeyID: "runtime-key-1", Algorithm: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(runtimePublic),
			Roles: []string{
				protocol.RuntimeRoleAuthenticate,
				protocol.RuntimeRoleQuote,
				protocol.RuntimeRoleReceipt,
			},
			NotBefore: now.Add(-time.Minute),
			NotAfter:  now.Add(20 * time.Minute),
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
		controllerPrivate, protocol.ServiceManifestDomain, manifest.Controller,
		manifest, manifest.IssuedAt, manifest.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest, err := codec.Digest(protocol.ServiceManifestDomain, manifest)
	if err != nil {
		t.Fatal(err)
	}
	return authFixture{
		now: now, controllerPrivate: controllerPrivate,
		runtimePrivate: runtimePrivate, manifest: manifest,
		manifestEnvelope: manifestEnvelope,
		snapshot: AuthoritySnapshot{
			Active: true, Network: manifest.Network, ServiceID: manifest.ServiceID,
			Controller: manifest.Controller, ControllerPublicKey: controllerPublic,
			ManifestDigest: manifestDigest, ObservedMasterSeqno: 100,
			ObservedAt: now.Add(-time.Second),
		},
	}
}

func newTestVerifier(t *testing.T) *Verifier {
	t.Helper()
	verifier, err := NewVerifier(DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func signRuntimePayload(
	t *testing.T,
	fixture authFixture,
	payload testPayload,
	expiresAt time.Time,
) identity.Envelope {
	t.Helper()
	envelope, err := identity.SignCanonical(
		fixture.runtimePrivate, runtimeDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		payload, fixture.now.Add(-time.Second), expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func validateTestPayload(expected testPayload) PayloadValidator {
	return func(encoded []byte) error {
		var payload testPayload
		if err := codec.Unmarshal(encoded, &payload); err != nil {
			return err
		}
		if payload != expected {
			return errors.New("payload binding mismatch")
		}
		return nil
	}
}

func testAdmissionBinding(payload testPayload) AdmissionBinding {
	return AdmissionBinding{
		SessionID: payload.SessionID, Operation: payload.Operation,
		RequestID:    payload.RequestID,
		IntentDigest: "sha256:" + strings.Repeat("9", 64),
	}
}

func TestVerifierAuthorizesCurrentManifestRuntimeAndPayload(t *testing.T) {
	fixture := newAuthFixture(t)
	verifier := newTestVerifier(t)
	verified, err := verifier.VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload{
		RequestID: "request-0001", SessionID: "session-0001",
		Operation: "invoke",
	}
	envelope := signRuntimePayload(
		t, fixture, payload, fixture.now.Add(time.Minute),
	)
	authorized, err := verified.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}

	envelope.Payload[0] ^= 1
	admitted, err := authorized.EnvelopeForAdmission(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.manifest.RuntimeKeys[0].KeyID,
		testAdmissionBinding(payload), fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	var recovered testPayload
	if err := admitted.VerifyCanonical(
		ed25519.NewKeyFromSeed(fixture.runtimePrivate.Seed()).Public().(ed25519.PublicKey),
		runtimeDomain, fixture.now, &recovered,
	); err != nil {
		t.Fatal(err)
	}
	if recovered != payload {
		t.Fatalf("authorized payload changed: %#v", recovered)
	}
}

func TestVerifierRejectsStaleReplacedAndWrongControllerManifest(t *testing.T) {
	fixture := newAuthFixture(t)
	verifier := newTestVerifier(t)

	stale := fixture.snapshot
	stale.ObservedAt = fixture.now.Add(-DefaultMaxAuthorityAge)
	if _, err := verifier.VerifyManifest(
		stale, fixture.manifestEnvelope, fixture.now,
	); err == nil {
		t.Fatal("stale authority snapshot accepted")
	}

	replaced := fixture.snapshot
	replaced.ManifestDigest = "sha256:" + strings.Repeat("f", 64)
	if _, err := verifier.VerifyManifest(
		replaced, fixture.manifestEnvelope, fixture.now,
	); err == nil {
		t.Fatal("superseded manifest accepted")
	}

	_, otherController, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongControllerEnvelope, err := identity.SignCanonical(
		otherController, protocol.ServiceManifestDomain,
		fixture.manifest.Controller, fixture.manifest,
		fixture.manifest.IssuedAt, fixture.manifest.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyManifest(
		fixture.snapshot, wrongControllerEnvelope, fixture.now,
	); err == nil {
		t.Fatal("manifest signed by the wrong controller key accepted")
	}
}

func TestVerifierRejectsRevokedWrongRoleDomainAndKeyWindow(t *testing.T) {
	fixture := newAuthFixture(t)
	payload := testPayload{
		RequestID: "request-0001", SessionID: "session-0001",
		Operation: "invoke",
	}
	envelope := signRuntimePayload(
		t, fixture, payload, fixture.now.Add(time.Minute),
	)
	verifier := newTestVerifier(t)

	revokedSnapshot := fixture.snapshot
	revokedSnapshot.RevokedRuntimeKeyIDs = []string{
		fixture.manifest.RuntimeKeys[0].KeyID,
	}
	revokedManifest, err := verifier.VerifyManifest(
		revokedSnapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revokedManifest.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	); err == nil {
		t.Fatal("revoked runtime key accepted")
	}

	verified, err := verifier.VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleEvidence,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	); err == nil {
		t.Fatal("runtime key without the required role accepted")
	}
	if _, err := verified.AuthorizeRuntimeEnvelope(
		envelope, "tos.quote.v1", protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	); err == nil {
		t.Fatal("cross-domain runtime envelope accepted")
	}

	outsideWindow := signRuntimePayload(
		t, fixture, payload,
		fixture.manifest.RuntimeKeys[0].NotAfter.Add(time.Second),
	)
	if _, err := verified.AuthorizeRuntimeEnvelope(
		outsideWindow, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	); err == nil {
		t.Fatal("runtime envelope beyond key validity accepted")
	}
}

func TestVerifierRequiresSemanticValidationBeforeAuthorization(t *testing.T) {
	fixture := newAuthFixture(t)
	verifier := newTestVerifier(t)
	verified, err := verifier.VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload{
		RequestID: "request-0001", SessionID: "session-0001",
		Operation: "invoke",
	}
	envelope := signRuntimePayload(
		t, fixture, payload, fixture.now.Add(time.Minute),
	)
	if _, err := verified.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), nil,
	); err == nil {
		t.Fatal("nil semantic validator accepted")
	}
	if _, err := verified.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload),
		func([]byte) error { return errors.New("policy denied") },
	); err == nil {
		t.Fatal("semantic validation failure ignored")
	}

	nonCanonical, err := identity.Sign(
		fixture.runtimePrivate, runtimeDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		[]byte{0x18, 0x17},
		fixture.now.Add(-time.Second), fixture.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verified.AuthorizeRuntimeEnvelope(
		nonCanonical, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload),
		func([]byte) error { return nil },
	); err == nil {
		t.Fatal("non-canonical signed runtime payload accepted")
	}
}

func TestManifestEnvelopeMustCoverManifestValidity(t *testing.T) {
	fixture := newAuthFixture(t)
	shortEnvelope, err := identity.SignCanonical(
		fixture.controllerPrivate, protocol.ServiceManifestDomain,
		fixture.manifest.Controller, fixture.manifest,
		fixture.manifest.IssuedAt,
		fixture.manifest.ExpiresAt.Add(-time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, shortEnvelope, fixture.now,
	); err == nil {
		t.Fatal("controller envelope shorter than manifest accepted")
	}
}

func TestManifestCoverageUsesEnvelopeMillisecondPrecision(t *testing.T) {
	fixture := newAuthFixture(t)
	fixture.manifest.IssuedAt = fixture.manifest.IssuedAt.Add(500 * time.Microsecond)
	fixture.manifest.ExpiresAt = fixture.manifest.ExpiresAt.Add(500 * time.Microsecond)
	fixture.manifest.RuntimeKeys[0].NotBefore =
		fixture.manifest.RuntimeKeys[0].NotBefore.Add(500 * time.Microsecond)
	fixture.manifest.RuntimeKeys[0].NotAfter =
		fixture.manifest.RuntimeKeys[0].NotAfter.Add(500 * time.Microsecond)
	envelope, err := identity.SignCanonical(
		fixture.controllerPrivate, protocol.ServiceManifestDomain,
		fixture.manifest.Controller, fixture.manifest,
		fixture.manifest.IssuedAt, fixture.manifest.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.snapshot.ManifestDigest, err = codec.Digest(
		protocol.ServiceManifestDomain, fixture.manifest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, envelope, fixture.now,
	); err != nil {
		t.Fatalf("millisecond-normalized manifest rejected: %v", err)
	}
}

type staticResolver struct {
	snapshot AuthoritySnapshot
	err      error
}

func (r staticResolver) ResolveAuthority(
	context.Context,
	Reference,
) (AuthoritySnapshot, error) {
	return r.snapshot, r.err
}

func TestResolveAndVerifyManifestBindsReferenceAndPropagatesErrors(t *testing.T) {
	fixture := newAuthFixture(t)
	verifier := newTestVerifier(t)
	reference := Reference{
		Network:   fixture.manifest.Network,
		Address:   "tos:test:service-contract",
		ServiceID: fixture.manifest.ServiceID,
	}
	if _, err := verifier.ResolveAndVerifyManifest(
		context.Background(), staticResolver{snapshot: fixture.snapshot},
		reference, fixture.manifestEnvelope, fixture.now,
	); err != nil {
		t.Fatal(err)
	}

	mismatched := fixture.snapshot
	mismatched.ServiceID = "different.example.ai"
	if _, err := verifier.ResolveAndVerifyManifest(
		context.Background(), staticResolver{snapshot: mismatched},
		reference, fixture.manifestEnvelope, fixture.now,
	); err == nil {
		t.Fatal("resolver reference substitution accepted")
	}
	sentinel := errors.New("resolver unavailable")
	if _, err := verifier.ResolveAndVerifyManifest(
		context.Background(), staticResolver{err: sentinel},
		reference, fixture.manifestEnvelope, fixture.now,
	); !errors.Is(err, sentinel) {
		t.Fatalf("resolver error = %v", err)
	}
}

func TestAuthorizedEnvelopeExpiresWithAuthorityFreshness(t *testing.T) {
	fixture := newAuthFixture(t)
	verifier := newTestVerifier(t)
	verified, err := verifier.VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := testPayload{
		RequestID: "request-0001", SessionID: "session-0001",
		Operation: "invoke",
	}
	envelope := signRuntimePayload(
		t, fixture, payload, fixture.now.Add(10*time.Minute),
	)
	authorized, err := verified.AuthorizeRuntimeEnvelope(
		envelope, runtimeDomain, protocol.RuntimeRoleAuthenticate,
		fixture.now, testAdmissionBinding(payload), validateTestPayload(payload),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authorized.EnvelopeForAdmission(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.manifest.RuntimeKeys[0].KeyID,
		testAdmissionBinding(payload),
		fixture.snapshot.ObservedAt.Add(DefaultMaxAuthorityAge),
	); err == nil {
		t.Fatal("authorization outlived authority freshness")
	}
}

func TestVerifiedManifestSupportsConcurrentBoundedAuthorization(t *testing.T) {
	fixture := newAuthFixture(t)
	verified, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	type candidate struct {
		payload  testPayload
		envelope identity.Envelope
		binding  AdmissionBinding
	}
	candidates := make([]candidate, 64)
	for index := range candidates {
		payload := testPayload{
			RequestID: fmt.Sprintf("request-%04d", index),
			SessionID: "session-0001", Operation: "invoke",
		}
		candidates[index] = candidate{
			payload: payload,
			envelope: signRuntimePayload(
				t, fixture, payload, fixture.now.Add(time.Minute),
			),
			binding: testAdmissionBinding(payload),
		}
	}

	errorsSeen := make(chan error, len(candidates))
	var wait sync.WaitGroup
	for _, item := range candidates {
		item := item
		wait.Add(1)
		go func() {
			defer wait.Done()
			authorized, authorizeErr := verified.AuthorizeRuntimeEnvelope(
				item.envelope, runtimeDomain,
				protocol.RuntimeRoleAuthenticate, fixture.now,
				item.binding, validateTestPayload(item.payload),
			)
			if authorizeErr != nil {
				errorsSeen <- authorizeErr
				return
			}
			if _, admissionErr := authorized.EnvelopeForAdmission(
				fixture.manifest.Network, fixture.manifest.ServiceID,
				fixture.manifest.RuntimeKeys[0].KeyID,
				item.binding, fixture.now,
			); admissionErr != nil {
				errorsSeen <- admissionErr
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
}
