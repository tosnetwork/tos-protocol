package edge

import (
	"context"
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
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
	"github.com/tosnetwork/tos-protocol/pkg/payment"
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

type edgeClientKeyResolver struct {
	snapshot authorization.ClientKeySnapshot
}

func (r edgeClientKeyResolver) ResolveClientKey(
	_ context.Context,
	reference authorization.ClientKeyReference,
) (authorization.ClientKeySnapshot, error) {
	if reference.Network != r.snapshot.Network ||
		reference.ServiceID != r.snapshot.ServiceID ||
		reference.KeyID != r.snapshot.KeyID ||
		reference.MinimumMasterSeqno > r.snapshot.ObservedMasterSeqno {
		return authorization.ClientKeySnapshot{}, errors.New("client key reference mismatch")
	}
	output := r.snapshot
	output.PublicKey = append(ed25519.PublicKey(nil), output.PublicKey...)
	return output, nil
}

type coreSessionFixture struct {
	now            time.Time
	network        string
	serviceID      string
	sessionID      string
	clientID       string
	runtimePrivate ed25519.PrivateKey
	clientPrivate  ed25519.PrivateKey
	resolver       edgeClientKeyResolver
	manifest       *authorization.VerifiedManifest
	session        *authorization.VerifiedSessionGrant
}

func newCoreSessionFixture(t *testing.T, now time.Time) coreSessionFixture {
	t.Helper()
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	runtimePublic, runtimePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := protocol.ServiceManifest{
		Version: protocol.ManifestVersion, ManifestID: "manifest-session-1",
		ServiceID: "edge.example.ai", Controller: "tos:test:controller",
		Network: "testnet", Revision: "manifest-revision-1",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		RuntimeKeys: []protocol.RuntimeKey{{
			KeyID: "runtime-auth-key", Algorithm: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(runtimePublic),
			Roles: []string{
				protocol.RuntimeRoleAuthenticate,
				protocol.RuntimeRoleQuote,
			},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		}},
		Endpoints: []protocol.ServiceEndpoint{{
			Transport: "https", Audience: "authenticated",
			URL: "https://edge.example/v1",
		}},
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1.0",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://edge.example/profile.json",
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
	verifiedManifest, err := verifier.VerifyManifest(
		authorization.AuthoritySnapshot{
			Active: true, Network: manifest.Network, ServiceID: manifest.ServiceID,
			Controller: manifest.Controller, ControllerPublicKey: controllerPublic,
			ManifestDigest: manifestDigest, ObservedMasterSeqno: 100,
			ObservedAt: now,
		},
		manifestEnvelope, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	grant := protocol.SessionGrant{
		Version: protocol.BaseEnvelopeVersion, SessionID: "session-0001",
		ServiceID: manifest.ServiceID, ProfileID: manifest.Profiles[0].ID,
		ProfileVersion: manifest.Profiles[0].Version,
		Client:         "client-key-1", RuntimeKeyID: manifest.RuntimeKeys[0].KeyID,
		ManifestRevision: manifest.Revision, Operations: []string{"invoke"},
		MaxRequests: 2, MaxNanoTOS: 10,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(30 * time.Minute),
	}
	grantEnvelope, err := identity.SignCanonical(
		runtimePrivate, protocol.SessionGrantDomain, grant.RuntimeKeyID,
		grant, grant.IssuedAt, grant.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSession, err := verifiedManifest.VerifySessionGrant(grantEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	return coreSessionFixture{
		now: now, network: manifest.Network, serviceID: manifest.ServiceID,
		sessionID: grant.SessionID, clientID: grant.Client,
		runtimePrivate: runtimePrivate,
		clientPrivate:  clientPrivate,
		resolver: edgeClientKeyResolver{snapshot: authorization.ClientKeySnapshot{
			Network: manifest.Network, ServiceID: manifest.ServiceID,
			KeyID: grant.Client, Principal: grant.Client,
			PublicKey: clientPublic,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
			ObservedMasterSeqno: 100, ObservedAt: now,
		}},
		manifest: verifiedManifest,
		session:  verifiedSession,
	}
}

func (f coreSessionFixture) authorizePayment(
	t *testing.T,
	requestID string,
) (journal.Scope, authorization.AuthorizedPayment) {
	t.Helper()
	scope := journal.Scope{
		Network: f.network, Authority: f.clientID, ServiceID: f.serviceID,
		SessionID: f.sessionID, Operation: "invoke", RequestID: requestID,
	}
	quote := protocol.Quote{
		Version: protocol.BaseEnvelopeVersion,
		QuoteID: "quote-" + requestID, RequestID: requestID,
		SessionID: f.sessionID, ServiceID: f.serviceID,
		ProfileID: "tos.ai.inference", Operation: scope.Operation,
		IntentDigest:     "sha256:" + strings.Repeat("9", 64),
		ServiceRevision:  "manifest-revision-1",
		ResourceRevision: "resource-revision-1",
		Network:          f.network, Payee: "service-wallet",
		Settlement:   "payment-reference-" + requestID,
		PriceNanoTOS: 5, MaxInputBytes: 1_024, MaxOutputBytes: 2_048,
		IssuedAt: f.now, Deadline: f.now.Add(5 * time.Minute),
		ExpiresAt: f.now.Add(time.Minute),
	}
	quoteEnvelope, err := identity.SignCanonical(
		f.runtimePrivate, protocol.QuoteDomain, "runtime-auth-key",
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedQuote, err := f.manifest.VerifyQuote(quoteEnvelope, f.now)
	if err != nil {
		t.Fatal(err)
	}
	paymentAuthorization := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "authorization-" + requestID,
		QuoteID:         quote.QuoteID, RequestID: requestID,
		Network: f.network, Payer: f.clientID, Payee: quote.Payee,
		MaxNanoTOS: 5, Reference: quote.Settlement,
		ExpiresAt: quote.ExpiresAt,
	}
	paymentEnvelope, err := identity.SignCanonical(
		f.clientPrivate, protocol.PaymentAuthorizationDomain, f.clientID,
		paymentAuthorization, f.now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := verifiedQuote.AuthorizePayment(
		context.Background(), f.session, f.resolver, 100, nil,
		paymentEnvelope, "", f.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope, authorized
}

type corePaymentResolver struct {
	state chain.PaymentState
}

func (r corePaymentResolver) ObservePayment(
	_ context.Context,
	_ chain.PaymentReference,
) (chain.PaymentState, error) {
	return r.state, nil
}

func (f coreSessionFixture) authorize(
	t *testing.T,
	requestID string,
	charge uint64,
) (journal.Scope, authorization.AuthorizedSessionEnvelope) {
	t.Helper()
	scope := journal.Scope{
		Network: f.network, Authority: f.clientID, ServiceID: f.serviceID,
		SessionID: f.sessionID, Operation: "invoke", RequestID: requestID,
	}
	payload := corePayload{
		RequestID: requestID, SessionID: scope.SessionID,
		Operation: scope.Operation,
	}
	envelope, err := identity.SignCanonical(
		f.clientPrivate, "tos.invoke.v1", f.clientID, payload,
		f.now, f.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := f.session.AuthorizeClientEnvelope(
		context.Background(), f.resolver, 100, nil,
		envelope, "tos.invoke.v1", "", f.now,
		authorization.AdmissionBinding{
			SessionID: scope.SessionID, Operation: scope.Operation,
			RequestID:    requestID,
			IntentDigest: "sha256:" + strings.Repeat("9", 64),
		},
		charge,
		func(
			encoded []byte,
			binding authorization.AdmissionBinding,
			validatedCharge uint64,
		) error {
			if binding.SessionID != scope.SessionID ||
				binding.RequestID != requestID ||
				validatedCharge != charge {
				return errors.New("client session admission binding mismatch")
			}
			var decoded corePayload
			if err := codec.Unmarshal(encoded, &decoded); err != nil {
				return err
			}
			if decoded != payload {
				return errors.New("client session payload mismatch")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return scope, authorized
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

func TestCoreAtomicallyAdmitsSessionBudgets(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	intent := "sha256:" + strings.Repeat("9", 64)

	firstScope, first := fixture.authorize(t, "session-request-1", 4)
	if _, _, err := core.AdmitAuthorizedSessionEnvelope(
		firstScope, intent, 5, first, fixture.now.Add(30*time.Minute),
	); err == nil {
		t.Fatal("mismatched session charge accepted")
	}
	record, disposition, err := core.AdmitAuthorizedSessionEnvelope(
		firstScope, intent, 4, first, fixture.now.Add(30*time.Minute),
	)
	if err != nil || disposition != journal.BeginCreated {
		t.Fatalf("first session admission: %#v %q %v", record, disposition, err)
	}
	if replay, replayDisposition, err := core.AdmitAuthorizedSessionEnvelope(
		firstScope, intent, 4, first, fixture.now.Add(30*time.Minute),
	); err != nil || replayDisposition != journal.BeginReplay || replay != record {
		t.Fatalf("session replay: %#v %q %v", replay, replayDisposition, err)
	}
	secondScope, second := fixture.authorize(t, "session-request-2", 6)
	if _, disposition, err := core.AdmitAuthorizedSessionEnvelope(
		secondScope, intent, 6, second, fixture.now.Add(30*time.Minute),
	); err != nil || disposition != journal.BeginCreated {
		t.Fatalf("second session admission: %q %v", disposition, err)
	}
	thirdScope, third := fixture.authorize(t, "session-request-3", 0)
	if _, _, err := core.AdmitAuthorizedSessionEnvelope(
		thirdScope, intent, 0, third, fixture.now.Add(30*time.Minute),
	); !errors.Is(err, journal.ErrBudgetLimit) {
		t.Fatalf("exhausted session error = %v", err)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 2 || health.NonceClaims != 2 ||
		health.BudgetUsages != 1 {
		t.Fatalf("unexpected session health: %#v", health)
	}
}

func TestCoreAppliesOnlyVerifiedPaymentObservation(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	scope, authorized := fixture.authorizePayment(t, "payment-request-0001")
	intent := "sha256:" + strings.Repeat("9", 64)
	pending, disposition, err := core.AdmitAuthorizedPayment(
		scope, intent, authorized, now.Add(30*time.Minute),
	)
	if err != nil || disposition != journal.BeginCreated ||
		pending.State != journal.StatePending {
		t.Fatalf(
			"payment admission: record=%#v disposition=%q err=%v",
			pending, disposition, err,
		)
	}
	if _, _, _, err := core.ApplyVerifiedPayment(
		scope, intent, authorized, payment.VerifiedObservation{}, 100,
	); err == nil {
		t.Fatal("unverified payment observation accepted")
	}
	material, err := authorized.ObservationMaterial(now)
	if err != nil {
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
	verified, err := observer.Observe(
		context.Background(), authorized, 100, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, applied, paymentDisposition, err := core.ApplyVerifiedPayment(
		scope, intent, authorized, verified, 101,
	)
	if err != nil {
		t.Fatal(err)
	}
	if paymentDisposition != journal.PaymentApplied ||
		record.State != journal.StateAuthorized || record.Revision != 2 ||
		applied.Status != journal.PaymentStatusApplied {
		t.Fatalf(
			"applied payment: record=%#v payment=%#v disposition=%q",
			record, applied, paymentDisposition,
		)
	}
	replayedRecord, replayedPayment, paymentDisposition, err :=
		core.ApplyVerifiedPayment(scope, intent, authorized, verified, 101)
	if err != nil ||
		paymentDisposition != journal.PaymentReplay ||
		replayedRecord != record || replayedPayment != applied {
		t.Fatalf(
			"payment replay: record=%#v payment=%#v disposition=%q err=%v",
			replayedRecord, replayedPayment, paymentDisposition, err,
		)
	}
	stored, err := core.Payment(scope)
	if err != nil || stored != applied {
		t.Fatalf("stored payment=%#v err=%v", stored, err)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 1 || health.PaymentRecords != 1 {
		t.Fatalf("unexpected payment health: %#v", health)
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
