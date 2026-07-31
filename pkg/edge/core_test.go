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
	now              time.Time
	network          string
	serviceID        string
	sessionID        string
	clientID         string
	runtimePrivate   ed25519.PrivateKey
	clientPrivate    ed25519.PrivateKey
	resolver         edgeClientKeyResolver
	snapshot         authorization.AuthoritySnapshot
	manifestEnvelope identity.Envelope
	manifest         *authorization.VerifiedManifest
	session          *authorization.VerifiedSessionGrant
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
				protocol.RuntimeRoleReceipt,
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
		snapshot: authorization.AuthoritySnapshot{
			Active: true, Network: manifest.Network, ServiceID: manifest.ServiceID,
			Controller: manifest.Controller, ControllerPublicKey: controllerPublic,
			ManifestDigest: manifestDigest, ObservedMasterSeqno: 100,
			ObservedAt: now,
		},
		manifestEnvelope: manifestEnvelope,
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

func (f coreSessionFixture) refreshManifest(
	t *testing.T,
	now time.Time,
) *authorization.VerifiedManifest {
	t.Helper()
	snapshot := f.snapshot
	snapshot.ObservedAt = now
	snapshot.ObservedMasterSeqno++
	verifier, err := authorization.NewVerifier(authorization.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := verifier.VerifyManifest(
		snapshot,
		f.manifestEnvelope,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
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

type corePaymentMapResolver struct {
	states map[string]chain.PaymentState
}

func (r corePaymentMapResolver) ObservePayment(
	_ context.Context,
	reference chain.PaymentReference,
) (chain.PaymentState, error) {
	state, ok := r.states[reference.Reference]
	if !ok {
		return chain.PaymentState{}, errors.New("unknown payment reference")
	}
	return state, nil
}

type coreBlockingPaymentResolver struct {
	started chan struct{}
	once    sync.Once
}

func (r *coreBlockingPaymentResolver) ObservePayment(
	ctx context.Context,
	_ chain.PaymentReference,
) (chain.PaymentState, error) {
	r.once.Do(func() { close(r.started) })
	<-ctx.Done()
	return chain.PaymentState{}, ctx.Err()
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
	initialState := chain.PaymentState{
		Network: material.Network, AuthorizationID: material.AuthorizationID,
		QuoteID: material.QuoteID, RequestID: material.RequestID,
		Reference: material.Reference, Confirmed: true, Finalized: true,
		AmountNanoTOS: material.PriceNanoTOS,
		Payer:         material.Payer, Payee: material.Payee,
		ObservedMasterSeqno: 101, ObservedAt: now,
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{state: initialState},
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
	refreshedState := initialState
	refreshedState.ObservedMasterSeqno = 102
	reconciliationObserver, err := payment.NewObserver(
		corePaymentResolver{state: refreshedState},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	refreshed, paymentDisposition, err := core.ReconcilePayment(
		context.Background(), scope, reconciliationObserver,
	)
	if err != nil || paymentDisposition != journal.PaymentRefreshed ||
		refreshed.Status != journal.PaymentStatusApplied ||
		refreshed.ObservedMasterSeqno != 102 {
		t.Fatalf(
			"payment refresh: payment=%#v disposition=%q err=%v",
			refreshed, paymentDisposition, err,
		)
	}
	reorganizedState := refreshedState
	reorganizedState.Confirmed = false
	reorganizedState.Reorganized = true
	reorganizedState.ObservedMasterSeqno = 103
	reorganizationObserver, err := payment.NewObserver(
		corePaymentResolver{state: reorganizedState},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	reorganized, paymentDisposition, err := core.ReconcilePayment(
		context.Background(), scope, reorganizationObserver,
	)
	if err != nil || paymentDisposition != journal.PaymentReorganized ||
		reorganized.Status != journal.PaymentStatusReorganized ||
		reorganized.ObservedMasterSeqno != 103 {
		t.Fatalf(
			"payment reorganization: payment=%#v disposition=%q err=%v",
			reorganized, paymentDisposition, err,
		)
	}
	if _, err := core.TransitionRequest(
		scope, record.Revision, journal.StateRunning, "", "",
	); !errors.Is(err, journal.ErrPaymentReorganized) {
		t.Fatalf("reorganized dispatch error=%v", err)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 1 || health.PaymentRecords != 1 {
		t.Fatalf("unexpected payment health: %#v", health)
	}
}

func TestCoreAtomicallyAppliesManifestAuthorizedReceipt(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	scope, authorized := fixture.authorizePayment(t, "receipt-request-0001")
	intent := "sha256:" + strings.Repeat("9", 64)
	if _, disposition, err := core.AdmitAuthorizedPayment(
		scope, intent, authorized, now.Add(30*time.Minute),
	); err != nil || disposition != journal.BeginCreated {
		t.Fatalf(
			"admit receipted payment: disposition=%q err=%v",
			disposition, err,
		)
	}
	material, err := authorized.ObservationMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	state := chain.PaymentState{
		Network: material.Network, AuthorizationID: material.AuthorizationID,
		QuoteID: material.QuoteID, RequestID: material.RequestID,
		Reference: material.Reference, Confirmed: true, Finalized: true,
		AmountNanoTOS: material.PriceNanoTOS,
		Payer:         material.Payer, Payee: material.Payee,
		ObservedMasterSeqno: 101, ObservedAt: now,
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{state: state},
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
	request, _, disposition, err := core.ApplyVerifiedPayment(
		scope, intent, authorized, observed, 101,
	)
	if err != nil || disposition != journal.PaymentApplied {
		t.Fatalf(
			"apply receipted payment: disposition=%q err=%v",
			disposition, err,
		)
	}
	running, err := core.TransitionRequest(
		scope, request.Revision, journal.StateRunning, "", "",
	)
	if err != nil {
		t.Fatal(err)
	}
	receiptValue := protocol.Receipt{
		Version:   protocol.BaseEnvelopeVersion,
		ReceiptID: "receipt-0001", RequestID: scope.RequestID,
		QuoteID:         material.QuoteID,
		AuthorizationID: material.AuthorizationID,
		ServiceID:       scope.ServiceID, Status: "succeeded",
		Usage: []protocol.UsageItem{
			{Unit: "output_tokens", Quantity: 10},
		},
		ChargedNanoTOS:   material.PriceNanoTOS,
		ResultDigest:     "sha256:" + strings.Repeat("6", 64),
		ServiceRevision:  "manifest-revision-1",
		ResourceRevision: "resource-revision-1",
		CompletedAt:      now,
	}
	receiptEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.ReceiptDomain,
		"runtime-auth-key", receiptValue, now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedReceipt, err := fixture.manifest.VerifyReceipt(
		receiptEnvelope, authorized, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := core.ApplyVerifiedReceipt(
		scope, running.Revision, authorization.VerifiedReceipt{},
	); err == nil {
		t.Fatal("unverified receipt accepted")
	}
	terminal, stored, receiptDisposition, err := core.ApplyVerifiedReceipt(
		scope, running.Revision, verifiedReceipt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if receiptDisposition != journal.ReceiptApplied ||
		terminal.State != journal.StateSucceeded ||
		terminal.Revision != running.Revision+1 ||
		terminal.ResultDigest != receiptValue.ResultDigest ||
		stored.ReceiptID != receiptValue.ReceiptID ||
		stored.RuntimeKeyID != "runtime-auth-key" {
		t.Fatalf(
			"receipt application: record=%#v receipt=%#v disposition=%q",
			terminal, stored, receiptDisposition,
		)
	}
	replayedRecord, replayedReceipt, receiptDisposition, err :=
		core.ApplyVerifiedReceipt(scope, running.Revision, verifiedReceipt)
	if err != nil ||
		receiptDisposition != journal.ReceiptReplay ||
		replayedRecord != terminal ||
		replayedReceipt.ReceiptID != stored.ReceiptID {
		t.Fatalf(
			"receipt replay: record=%#v receipt=%#v disposition=%q err=%v",
			replayedRecord, replayedReceipt, receiptDisposition, err,
		)
	}
	recovered, err := core.Receipt(scope)
	if err != nil || recovered.ReceiptID != stored.ReceiptID {
		t.Fatalf("recovered receipt=%#v err=%v", recovered, err)
	}
	health, err := core.Health()
	if err != nil {
		t.Fatal(err)
	}
	if health.RequestRecords != 1 ||
		health.PaymentRecords != 1 ||
		health.ReceiptRecords != 1 {
		t.Fatalf("unexpected receipt health: %#v", health)
	}
}

func TestCoreReconcilesPaymentsInDurableBoundedBatches(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	config.RequestJournalLimits.MaxPrunePerWrite = 2
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	fixture := newCoreSessionFixture(t, now)
	intent := "sha256:" + strings.Repeat("9", 64)
	reconciliationStates := make(map[string]chain.PaymentState, 2)
	for index, requestID := range []string{
		"payment-batch-0001",
		"payment-batch-0002",
	} {
		scope, authorized := fixture.authorizePayment(t, requestID)
		if _, disposition, err := core.AdmitAuthorizedPayment(
			scope, intent, authorized, now.Add(30*time.Minute),
		); err != nil || disposition != journal.BeginCreated {
			t.Fatalf(
				"admit batch payment %d: disposition=%q err=%v",
				index, disposition, err,
			)
		}
		material, err := authorized.ObservationMaterial(now)
		if err != nil {
			t.Fatal(err)
		}
		initialState := chain.PaymentState{
			Network:         material.Network,
			AuthorizationID: material.AuthorizationID,
			QuoteID:         material.QuoteID, RequestID: material.RequestID,
			Reference: material.Reference, Confirmed: true, Finalized: true,
			AmountNanoTOS: material.PriceNanoTOS,
			Payer:         material.Payer, Payee: material.Payee,
			ObservedMasterSeqno: 101, ObservedAt: now,
		}
		observer, err := payment.NewObserver(
			corePaymentResolver{state: initialState},
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
		if _, _, disposition, err := core.ApplyVerifiedPayment(
			scope, intent, authorized, verified, 101,
		); err != nil || disposition != journal.PaymentApplied {
			t.Fatalf(
				"apply batch payment %d: disposition=%q err=%v",
				index, disposition, err,
			)
		}
		reconciledState := initialState
		reconciledState.ObservedMasterSeqno = 102
		if index == 1 {
			reconciledState.Confirmed = false
			reconciledState.Reorganized = true
		}
		reconciliationStates[material.Reference] = reconciledState
	}
	reconciliationObserver, err := payment.NewObserver(
		corePaymentMapResolver{states: reconciliationStates},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	report, err := core.ReconcilePaymentBatch(
		context.Background(), reconciliationObserver, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if report.Scanned != 2 || report.Eligible != 2 ||
		report.Refreshed != 1 || report.Reorganized != 1 ||
		report.Replayed != 0 || report.Failed != 0 ||
		len(report.Failures) != 0 {
		t.Fatalf("unexpected reconciliation report: %#v", report)
	}
	replayed, err := core.ReconcilePaymentBatch(
		context.Background(), reconciliationObserver, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Wrapped || replayed.Scanned != 2 ||
		replayed.Replayed != 2 || replayed.Failed != 0 {
		t.Fatalf("unexpected wrapped reconciliation report: %#v", replayed)
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

func TestCorePaymentReconciliationLoopReportsHealth(t *testing.T) {
	observer, err := payment.NewObserver(
		corePaymentResolver{},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = time.Hour
	config.PaymentObserver = observer
	config.PaymentReconciliationInterval = 10 * time.Millisecond
	config.PaymentReconciliationTimeout = 100 * time.Millisecond
	config.PaymentReconciliationBatch = 1
	now := time.Unix(1_800_000_000, 0).UTC()
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		health, healthErr := core.Health()
		if healthErr == nil &&
			health.LastPaymentReconciliationSucceeded &&
			health.LastPaymentReconciliationAt.Equal(now) &&
			health.LastPaymentReconciliationScanned == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	health, healthErr := core.Health()
	t.Fatalf(
		"payment reconciliation loop did not run: health=%#v error=%v",
		health, healthErr,
	)
}

func TestCoreCloseCancelsScheduledPaymentReconciliation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requests.db")
	limits := journal.DefaultLimits()
	now := time.Unix(1_800_000_000, 0).UTC()
	scope := journal.Scope{
		Network: "testnet", Authority: "client-key-1",
		ServiceID: "edge.example.ai", SessionID: "session-0001",
		Operation: "invoke", RequestID: "scheduled-payment-0001",
	}
	intent := "sha256:" + strings.Repeat("a", 64)
	store, err := journal.Open(path, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Begin(
		scope, intent, now, now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := store.ApplyPayment(journal.PaymentAdmission{
		Scope: scope, IntentDigest: intent,
		AuthorizationID: "authorization-scheduled-0001",
		QuoteID:         "quote-scheduled-0001",
		Reference:       "payment-reference-scheduled-0001",
		Payer:           "payer-wallet", Payee: "service-wallet",
		AmountNanoTOS:         5,
		QuoteEnvelopeDigest:   "sha256:" + strings.Repeat("e", 64),
		PaymentEnvelopeDigest: "sha256:" + strings.Repeat("f", 64),
		ObservedMasterSeqno:   101, ObservedAt: now,
	}, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	resolver := &coreBlockingPaymentResolver{started: make(chan struct{})}
	observer, err := payment.NewObserver(resolver, payment.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultCoreConfig(path)
	config.CleanupInterval = time.Hour
	config.PaymentObserver = observer
	config.PaymentReconciliationInterval = 10 * time.Millisecond
	config.PaymentReconciliationTimeout = time.Minute
	config.PaymentReconciliationBatch = 1
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-resolver.started:
	case <-time.After(time.Second):
		_ = core.Close()
		t.Fatal("scheduled payment reconciliation did not start")
	}
	startedClose := time.Now()
	if err := core.Close(); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(startedClose); elapsed > time.Second {
		t.Fatalf("Core close did not cancel reconciliation: %v", elapsed)
	}
}

func TestCoreRejectsInvalidCleanupConfiguration(t *testing.T) {
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.CleanupInterval = 0
	if _, err := OpenCore(config); err == nil {
		t.Fatal("zero cleanup interval accepted")
	}
	config = DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.PaymentReconciliationInterval = time.Minute
	if _, err := OpenCore(config); err == nil {
		t.Fatal("payment reconciliation settings without observer accepted")
	}
	observer, err := payment.NewObserver(
		corePaymentResolver{},
		payment.DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	config = DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	config.PaymentObserver = observer
	config.PaymentReconciliationInterval = time.Minute
	config.PaymentReconciliationTimeout = time.Second
	config.PaymentReconciliationBatch =
		config.RequestJournalLimits.MaxPrunePerWrite + 1
	if _, err := OpenCore(config); err == nil {
		t.Fatal("oversized payment reconciliation batch accepted")
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
