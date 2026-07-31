package payment

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type testPaymentResolver struct {
	state chain.PaymentState
	ref   chain.PaymentReference
	err   error
	wait  bool
}

func (r *testPaymentResolver) ObservePayment(
	ctx context.Context,
	reference chain.PaymentReference,
) (chain.PaymentState, error) {
	r.ref = reference
	if r.wait {
		<-ctx.Done()
		return chain.PaymentState{}, ctx.Err()
	}
	return r.state, r.err
}

type testClientResolver struct {
	snapshot authorization.ClientKeySnapshot
}

func (r testClientResolver) ResolveClientKey(
	_ context.Context,
	_ authorization.ClientKeyReference,
) (authorization.ClientKeySnapshot, error) {
	return r.snapshot, nil
}

type observerFixture struct {
	now        time.Time
	authorized authorization.AuthorizedPayment
	material   authorization.PaymentObservationMaterial
	state      chain.PaymentState
}

func newObserverFixture(t *testing.T) observerFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
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
		Version: protocol.ManifestVersion, ManifestID: "manifest-0001",
		ServiceID: "edge.example.ai", Controller: "controller-key-1",
		Network: "testnet", Revision: "manifest-revision-1",
		IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour),
		RuntimeKeys: []protocol.RuntimeKey{{
			KeyID: "runtime-key-1", Algorithm: "Ed25519",
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
	verifier, err := authorization.NewVerifier(authorization.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	verifiedManifest, err := verifier.VerifyManifest(
		authorization.AuthoritySnapshot{
			Active: true, Network: manifest.Network,
			ServiceID: manifest.ServiceID, Controller: manifest.Controller,
			ControllerPublicKey: controllerPublic,
			ManifestDigest:      manifestDigest,
			ObservedMasterSeqno: 100, ObservedAt: now,
		},
		manifestEnvelope,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	session := protocol.SessionGrant{
		Version: protocol.BaseEnvelopeVersion, SessionID: "session-0001",
		ServiceID: manifest.ServiceID, ProfileID: manifest.Profiles[0].ID,
		ProfileVersion: manifest.Profiles[0].Version,
		Client:         "client-key-1", RuntimeKeyID: manifest.RuntimeKeys[0].KeyID,
		ManifestRevision: manifest.Revision, Operations: []string{"invoke"},
		MaxRequests: 2, MaxNanoTOS: 10,
		IssuedAt: now.Add(-time.Second), ExpiresAt: now.Add(10 * time.Minute),
	}
	sessionEnvelope, err := identity.SignCanonical(
		runtimePrivate, protocol.SessionGrantDomain, session.RuntimeKeyID,
		session, session.IssuedAt, session.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedSession, err := verifiedManifest.VerifySessionGrant(sessionEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	quote := protocol.Quote{
		Version: protocol.BaseEnvelopeVersion,
		QuoteID: "quote-0001", RequestID: "request-0001",
		SessionID: session.SessionID, ServiceID: manifest.ServiceID,
		ProfileID: session.ProfileID, Operation: "invoke",
		IntentDigest:     "sha256:" + strings.Repeat("9", 64),
		ServiceRevision:  manifest.Revision,
		ResourceRevision: "resource-revision-1",
		Network:          manifest.Network, Payee: "service-wallet",
		Settlement:   "payment-reference-0001",
		PriceNanoTOS: 5, MaxInputBytes: 1024, MaxOutputBytes: 2048,
		IssuedAt: now, Deadline: now.Add(5 * time.Minute),
		ExpiresAt: now.Add(time.Minute),
	}
	quoteEnvelope, err := identity.SignCanonical(
		runtimePrivate, protocol.QuoteDomain, session.RuntimeKeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedQuote, err := verifiedManifest.VerifyQuote(quoteEnvelope, now)
	if err != nil {
		t.Fatal(err)
	}
	paymentAuthorization := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "authorization-0001",
		QuoteID:         quote.QuoteID, RequestID: quote.RequestID,
		Network: quote.Network, Payer: "payer-wallet",
		Payee: quote.Payee, MaxNanoTOS: 6,
		Reference: quote.Settlement, ExpiresAt: quote.ExpiresAt,
	}
	paymentEnvelope, err := identity.SignCanonical(
		clientPrivate, protocol.PaymentAuthorizationDomain, session.Client,
		paymentAuthorization, now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := verifiedQuote.AuthorizePayment(
		context.Background(), verifiedSession,
		testClientResolver{snapshot: authorization.ClientKeySnapshot{
			Network: manifest.Network, ServiceID: manifest.ServiceID,
			KeyID: session.Client, Principal: "payer-wallet",
			PublicKey: clientPublic,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			ObservedMasterSeqno: 100, ObservedAt: now,
		}},
		100, nil, paymentEnvelope, "", now,
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := authorized.ObservationMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	return observerFixture{
		now: now, authorized: authorized, material: material,
		state: chain.PaymentState{
			Network:         material.Network,
			AuthorizationID: material.AuthorizationID,
			QuoteID:         material.QuoteID, RequestID: material.RequestID,
			Reference: material.Reference, Confirmed: true, Finalized: true,
			AmountNanoTOS: material.PriceNanoTOS,
			Payer:         material.Payer, Payee: material.Payee,
			ObservedMasterSeqno: 101, ObservedAt: now,
		},
	}
}

func reconciliationBinding(fixture observerFixture) ReconciliationBinding {
	return ReconciliationBinding{
		Network: fixture.material.Network, ServiceID: fixture.material.ServiceID,
		SessionID: fixture.material.SessionID, Operation: fixture.material.Operation,
		RequestID:             fixture.material.RequestID,
		IntentDigest:          fixture.material.IntentDigest,
		AuthorizationID:       fixture.material.AuthorizationID,
		QuoteID:               fixture.material.QuoteID,
		Reference:             fixture.material.Reference,
		Payer:                 fixture.material.Payer,
		Payee:                 fixture.material.Payee,
		AmountNanoTOS:         fixture.state.AmountNanoTOS,
		QuoteEnvelopeDigest:   fixture.material.QuoteEnvelopeDigest,
		PaymentEnvelopeDigest: fixture.material.PaymentEnvelopeDigest,
	}
}

func TestObserverVerifiesExactFinalPayment(t *testing.T) {
	fixture := newObserverFixture(t)
	resolver := &testPaymentResolver{state: fixture.state}
	observer, err := NewObserver(resolver, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := observer.Observe(
		context.Background(), fixture.authorized, 100, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	expectedReference := chain.PaymentReference{
		Network:            fixture.material.Network,
		AuthorizationID:    fixture.material.AuthorizationID,
		QuoteID:            fixture.material.QuoteID,
		RequestID:          fixture.material.RequestID,
		Reference:          fixture.material.Reference,
		MinimumMasterSeqno: 100,
	}
	if resolver.ref != expectedReference {
		t.Fatalf("query reference = %#v", resolver.ref)
	}
	material, err := verified.ApplicationMaterial(
		fixture.material.Network, fixture.material.ServiceID,
		fixture.material.SessionID, fixture.material.Operation,
		fixture.material.RequestID, fixture.material.IntentDigest,
		fixture.material.AuthorizationID, fixture.material.QuoteID,
		fixture.material.Reference, 101, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.AmountNanoTOS != fixture.state.AmountNanoTOS ||
		material.ObservedMasterSeqno != fixture.state.ObservedMasterSeqno ||
		material.QuoteEnvelopeDigest == "" ||
		material.PaymentEnvelopeDigest == "" {
		t.Fatalf("unexpected application material: %#v", material)
	}
	if _, err := verified.ApplicationMaterial(
		fixture.material.Network, fixture.material.ServiceID,
		fixture.material.SessionID, fixture.material.Operation,
		"request-attacker", fixture.material.IntentDigest,
		fixture.material.AuthorizationID, fixture.material.QuoteID,
		fixture.material.Reference, 101, fixture.now,
	); err == nil {
		t.Fatal("verified payment reused for another request")
	}
	if _, err := verified.ApplicationMaterial(
		fixture.material.Network, fixture.material.ServiceID,
		fixture.material.SessionID, fixture.material.Operation,
		fixture.material.RequestID, fixture.material.IntentDigest,
		fixture.material.AuthorizationID, fixture.material.QuoteID,
		fixture.material.Reference, 101,
		fixture.material.ValidUntil.Add(time.Millisecond),
	); err == nil {
		t.Fatal("payment observation outlived its signed authorization")
	}
}

func TestReconcileVerifiesAppliedPaymentAfterAuthorizationExpiry(t *testing.T) {
	fixture := newObserverFixture(t)
	now := fixture.material.ValidUntil.Add(time.Minute)
	state := fixture.state
	state.ObservedMasterSeqno = 102
	state.ObservedAt = now
	resolver := &testPaymentResolver{state: state}
	observer, err := NewObserver(resolver, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	binding := reconciliationBinding(fixture)
	verified, err := observer.Reconcile(
		context.Background(), binding, 101, now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if resolver.ref != (chain.PaymentReference{
		Network: binding.Network, AuthorizationID: binding.AuthorizationID,
		QuoteID: binding.QuoteID, RequestID: binding.RequestID,
		Reference: binding.Reference, MinimumMasterSeqno: 101,
	}) {
		t.Fatalf("reconciliation reference=%#v", resolver.ref)
	}
	material, err := verified.ApplicationMaterial(binding, 102, now)
	if err != nil {
		t.Fatal(err)
	}
	if material.Status != ReconciliationApplied ||
		material.ObservedMasterSeqno != 102 ||
		!material.ObservedAt.Equal(now) {
		t.Fatalf("unexpected reconciliation material: %#v", material)
	}
	changed := binding
	changed.RequestID = "attacker-request"
	if _, err := verified.ApplicationMaterial(
		changed, 102, now,
	); err == nil {
		t.Fatal("verified reconciliation reused with another binding")
	}
	if _, err := verified.ApplicationMaterial(
		binding, 103, now,
	); err == nil {
		t.Fatal("verified reconciliation reused below a newer high-water mark")
	}
	if _, err := verified.ApplicationMaterial(
		binding, 102, now.Add(DefaultMaxObservationAge),
	); err == nil {
		t.Fatal("expired reconciliation accepted")
	}
}

func TestReconcileVerifiesFinalReorganization(t *testing.T) {
	fixture := newObserverFixture(t)
	state := fixture.state
	state.Confirmed = false
	state.Reorganized = true
	state.ObservedMasterSeqno = 102
	state.ObservedAt = fixture.now.Add(time.Second)
	observer, err := NewObserver(
		&testPaymentResolver{state: state},
		DefaultPolicy(),
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := reconciliationBinding(fixture)
	verified, err := observer.Reconcile(
		context.Background(), binding, 101, fixture.now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := verified.ApplicationMaterial(
		binding, 101, fixture.now.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if material.Status != ReconciliationReorganized {
		t.Fatalf("reconciliation status=%q", material.Status)
	}
}

func TestReconcileRejectsAmbiguousOrRegressedState(t *testing.T) {
	fixture := newObserverFixture(t)
	binding := reconciliationBinding(fixture)
	tests := []struct {
		name   string
		mutate func(*chain.PaymentState)
	}{
		{"reference", func(s *chain.PaymentState) { s.Reference = "other-reference" }},
		{"payer", func(s *chain.PaymentState) { s.Payer = "other-payer" }},
		{"amount", func(s *chain.PaymentState) { s.AmountNanoTOS++ }},
		{"rollback", func(s *chain.PaymentState) { s.ObservedMasterSeqno = 100 }},
		{"stale", func(s *chain.PaymentState) {
			s.ObservedAt = fixture.now.Add(-DefaultMaxObservationAge)
		}},
		{"future", func(s *chain.PaymentState) {
			s.ObservedAt = fixture.now.Add(identity.MaxClockSkew + time.Millisecond)
		}},
		{"not-final", func(s *chain.PaymentState) { s.Finalized = false }},
		{"unconfirmed", func(s *chain.PaymentState) { s.Confirmed = false }},
		{"reorganized-confirmed", func(s *chain.PaymentState) {
			s.Reorganized = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := fixture.state
			test.mutate(&state)
			observer, err := NewObserver(
				&testPaymentResolver{state: state},
				DefaultPolicy(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := observer.Reconcile(
				context.Background(), binding, 101, fixture.now,
			); err == nil {
				t.Fatal("invalid reconciliation state accepted")
			}
		})
	}
	if _, err := (VerifiedReconciliation{}).ApplicationMaterial(
		binding, 101, fixture.now,
	); err == nil {
		t.Fatal("zero reconciliation result accepted")
	}
}

func TestObserverRejectsInvalidChainStates(t *testing.T) {
	fixture := newObserverFixture(t)
	tests := []struct {
		name   string
		mutate func(*chain.PaymentState)
	}{
		{"reference", func(s *chain.PaymentState) { s.Reference = "other-reference" }},
		{"reorganized", func(s *chain.PaymentState) { s.Reorganized = true }},
		{"unconfirmed", func(s *chain.PaymentState) { s.Confirmed = false }},
		{"not-final", func(s *chain.PaymentState) { s.Finalized = false }},
		{"payer", func(s *chain.PaymentState) { s.Payer = "other-payer" }},
		{"underpaid", func(s *chain.PaymentState) { s.AmountNanoTOS = 4 }},
		{"overpaid", func(s *chain.PaymentState) { s.AmountNanoTOS = 6 }},
		{"over-authorized", func(s *chain.PaymentState) { s.AmountNanoTOS = 7 }},
		{"rollback", func(s *chain.PaymentState) { s.ObservedMasterSeqno = 99 }},
		{"stale", func(s *chain.PaymentState) {
			s.ObservedAt = fixture.now.Add(-DefaultMaxObservationAge)
		}},
		{"future", func(s *chain.PaymentState) {
			s.ObservedAt = fixture.now.Add(identity.MaxClockSkew + time.Millisecond)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := fixture.state
			test.mutate(&state)
			observer, err := NewObserver(
				&testPaymentResolver{state: state},
				DefaultPolicy(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := observer.Observe(
				context.Background(), fixture.authorized, 100, fixture.now,
			); err == nil {
				t.Fatal("invalid payment state accepted")
			}
		})
	}
}

func TestObserverPropagatesCancellationAndTimeout(t *testing.T) {
	fixture := newObserverFixture(t)
	resolver := &testPaymentResolver{state: fixture.state}
	observer, err := NewObserver(resolver, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := observer.Observe(
		ctx, fixture.authorized, 100, fixture.now,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled observation error = %v", err)
	}

	policy := DefaultPolicy()
	policy.QueryTimeout = time.Millisecond
	observer, err = NewObserver(&testPaymentResolver{wait: true}, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Observe(
		context.Background(), fixture.authorized, 100, fixture.now,
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timed-out observation error = %v", err)
	}
}

func TestObserverCanExplicitlyAcceptConfirmedNonFinalState(t *testing.T) {
	fixture := newObserverFixture(t)
	fixture.state.Finalized = false
	policy := DefaultPolicy()
	policy.RequireFinalized = false
	observer, err := NewObserver(
		&testPaymentResolver{state: fixture.state},
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Observe(
		context.Background(), fixture.authorized, 100, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
}

func TestObserverCanExplicitlyAcceptAuthorizedOverpayment(t *testing.T) {
	fixture := newObserverFixture(t)
	fixture.state.AmountNanoTOS = fixture.material.MaxNanoTOS
	policy := DefaultPolicy()
	policy.AllowOverpayment = true
	observer, err := NewObserver(
		&testPaymentResolver{state: fixture.state},
		policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Observe(
		context.Background(), fixture.authorized, 100, fixture.now,
	); err != nil {
		t.Fatal(err)
	}
}
