package authorization

import (
	"context"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestQuoteAndPaymentAuthorizationBinding(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	rootSnapshot := fixture.resolver.keys[fixture.session.Client]
	rootSnapshot.Principal = "payer-wallet"
	fixture.resolver.keys[fixture.session.Client] = rootSnapshot
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	quote := sessionQuote(fixture)
	quoteEnvelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedQuote, err := manifest.VerifyQuote(quoteEnvelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	paymentAuthorization := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "authorization-0001",
		QuoteID:         quote.QuoteID, RequestID: quote.RequestID,
		Network: quote.Network, Payer: "payer-wallet",
		Payee: quote.Payee, MaxNanoTOS: 6,
		Reference: quote.Settlement,
		ExpiresAt: quote.ExpiresAt,
	}
	paymentEnvelope, err := identity.SignCanonical(
		fixture.rootPrivate, protocol.PaymentAuthorizationDomain,
		fixture.session.Client, paymentAuthorization,
		fixture.now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := verifiedQuote.AuthorizePayment(
		context.Background(), fixture.verified, fixture.resolver, 100,
		nil, paymentEnvelope, "", fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	material, err := authorized.ObservationMaterial(fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	if material.AuthorizationID != paymentAuthorization.AuthorizationID ||
		material.QuoteID != quote.QuoteID ||
		material.RequestID != quote.RequestID ||
		material.PriceNanoTOS != quote.PriceNanoTOS ||
		material.MaxNanoTOS != paymentAuthorization.MaxNanoTOS ||
		material.QuoteEnvelopeDigest == "" ||
		material.PaymentEnvelopeDigest == "" {
		t.Fatalf("unexpected observation material: %#v", material)
	}
	requestAuthorization, chargeNanoTOS, err := authorized.RequestAuthorization()
	if err != nil || chargeNanoTOS != quote.PriceNanoTOS {
		t.Fatalf("request authorization charge = %d, err = %v", chargeNanoTOS, err)
	}
	if _, err := requestAuthorization.AdmissionMaterial(
		fixture.manifest.Network, fixture.manifest.ServiceID,
		fixture.session.Client,
		AdmissionBinding{
			SessionID: quote.SessionID, Operation: quote.Operation,
			RequestID: quote.RequestID, IntentDigest: quote.IntentDigest,
		},
		quote.PriceNanoTOS, fixture.now,
	); err != nil {
		t.Fatal(err)
	}

	paymentAuthorization.Payee = "attacker-wallet"
	attackerEnvelope, err := identity.SignCanonical(
		fixture.rootPrivate, protocol.PaymentAuthorizationDomain,
		fixture.session.Client, paymentAuthorization,
		fixture.now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedQuote.AuthorizePayment(
		context.Background(), fixture.verified, fixture.resolver, 100,
		nil, attackerEnvelope, "", fixture.now,
	); err == nil {
		t.Fatal("payment authorization with substituted payee accepted")
	}

	paymentAuthorization.Payee = quote.Payee
	paymentAuthorization.Payer = "other-payer"
	otherPayerEnvelope, err := identity.SignCanonical(
		fixture.rootPrivate, protocol.PaymentAuthorizationDomain,
		fixture.session.Client, paymentAuthorization,
		fixture.now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedQuote.AuthorizePayment(
		context.Background(), fixture.verified, fixture.resolver, 100,
		nil, otherPayerEnvelope, "", fixture.now,
	); err == nil {
		t.Fatal("payment authorization with substituted payer accepted")
	}

	paymentAuthorization.Payer = "payer-wallet"
	paymentAuthorization.MaxNanoTOS = fixture.session.MaxNanoTOS + 1
	expandedEnvelope, err := identity.SignCanonical(
		fixture.rootPrivate, protocol.PaymentAuthorizationDomain,
		fixture.session.Client, paymentAuthorization,
		fixture.now, paymentAuthorization.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifiedQuote.AuthorizePayment(
		context.Background(), fixture.verified, fixture.resolver, 100,
		nil, expandedEnvelope, "", fixture.now,
	); err == nil {
		t.Fatal("payment authorization expanding the session budget accepted")
	}
}

func TestQuoteRejectsManifestAndSessionConfusion(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	quote := sessionQuote(fixture)
	quote.ServiceRevision = "other-manifest"
	envelope, err := identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifyQuote(envelope, fixture.now); err == nil {
		t.Fatal("quote from another manifest revision accepted")
	}

	quote = sessionQuote(fixture)
	quote.ProfileID = "tos.storage.v1"
	envelope, err = identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manifest.VerifyQuote(envelope, fixture.now); err == nil {
		t.Fatal("quote for absent profile accepted")
	}

	quote = sessionQuote(fixture)
	envelope, err = identity.SignCanonical(
		fixture.runtimePrivate, protocol.QuoteDomain,
		fixture.manifest.RuntimeKeys[0].KeyID,
		quote, quote.IssuedAt, quote.ExpiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	verifiedQuote, err := manifest.VerifyQuote(envelope, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	otherSession := *fixture.verified
	otherSession.grant = cloneSessionGrant(otherSession.grant)
	otherSession.grant.SessionID = "session-0002"
	if _, err := verifiedQuote.AuthorizePayment(
		context.Background(), &otherSession, fixture.resolver, 100,
		nil, fixture.clientEnvelope, "", fixture.now,
	); err == nil {
		t.Fatal("quote applied to another session accepted")
	}
}

func sessionQuote(fixture sessionAuthFixture) protocol.Quote {
	return protocol.Quote{
		Version: protocol.BaseEnvelopeVersion,
		QuoteID: "quote-0001", RequestID: fixture.payload.RequestID,
		SessionID:        fixture.session.SessionID,
		ServiceID:        fixture.manifest.ServiceID,
		ProfileID:        fixture.session.ProfileID,
		Operation:        fixture.payload.Operation,
		IntentDigest:     fixture.admissionBinding.IntentDigest,
		ServiceRevision:  fixture.manifest.Revision,
		ResourceRevision: "resource-revision-1",
		Network:          fixture.manifest.Network,
		Payee:            "service-wallet", Settlement: "payment-reference-0001",
		PriceNanoTOS: 5, MaxInputBytes: 1024, MaxOutputBytes: 2048,
		IssuedAt: fixture.now, Deadline: fixture.now.Add(5 * time.Minute),
		ExpiresAt: fixture.now.Add(time.Minute),
	}
}
