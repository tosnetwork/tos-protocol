package authorization

import (
	"context"
	"strings"
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

type receiptAuthorizationFixture struct {
	session    sessionAuthFixture
	manifest   *VerifiedManifest
	authorized AuthorizedPayment
	quote      protocol.Quote
	payment    protocol.PaymentAuthorization
}

func newReceiptAuthorizationFixture(
	t *testing.T,
) receiptAuthorizationFixture {
	t.Helper()
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
	verifiedQuote, err := manifest.VerifyQuote(
		quoteEnvelope,
		fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	paymentAuthorization := protocol.PaymentAuthorization{
		Version:         protocol.BaseEnvelopeVersion,
		AuthorizationID: "authorization-0001",
		QuoteID:         quote.QuoteID, RequestID: quote.RequestID,
		Network: quote.Network, Payer: "payer-wallet", Payee: quote.Payee,
		MaxNanoTOS: 6, Reference: quote.Settlement,
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
	return receiptAuthorizationFixture{
		session: fixture, manifest: manifest, authorized: authorized,
		quote: quote, payment: paymentAuthorization,
	}
}

func TestReceiptAuthorizationBindsCurrentRuntimeAndPayment(t *testing.T) {
	fixture := newReceiptAuthorizationFixture(t)
	receiptNow := fixture.session.now.Add(2 * time.Minute)
	if _, err := fixture.authorized.ObservationMaterial(receiptNow); err == nil {
		t.Fatal("expired payment authorization remained observable")
	}
	receipt := protocol.Receipt{
		Version:   protocol.BaseEnvelopeVersion,
		ReceiptID: "receipt-0001", RequestID: fixture.quote.RequestID,
		QuoteID:         fixture.quote.QuoteID,
		AuthorizationID: fixture.payment.AuthorizationID,
		ServiceID:       fixture.quote.ServiceID, Status: "succeeded",
		Usage:            []protocol.UsageItem{{Unit: "output_tokens", Quantity: 10}},
		ChargedNanoTOS:   fixture.quote.PriceNanoTOS,
		ResultDigest:     "sha256:" + strings.Repeat("b", 64),
		ServiceRevision:  fixture.quote.ServiceRevision,
		ResourceRevision: fixture.quote.ResourceRevision,
		CompletedAt:      receiptNow,
	}
	envelope, err := identity.SignCanonical(
		fixture.session.runtimePrivate, protocol.ReceiptDomain,
		fixture.session.manifest.RuntimeKeys[0].KeyID,
		receipt, receiptNow, receiptNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := fixture.manifest.VerifyReceipt(
		envelope, fixture.authorized, receiptNow,
	)
	if err != nil {
		t.Fatal(err)
	}
	binding := ReceiptBinding{
		Network: fixture.quote.Network, ServiceID: fixture.quote.ServiceID,
		SessionID: fixture.quote.SessionID, Operation: fixture.quote.Operation,
		RequestID:       fixture.quote.RequestID,
		IntentDigest:    fixture.quote.IntentDigest,
		AuthorizationID: fixture.payment.AuthorizationID,
		QuoteID:         fixture.quote.QuoteID,
	}
	material, err := verified.ApplicationMaterial(binding, receiptNow)
	if err != nil {
		t.Fatal(err)
	}
	if material.ReceiptID != receipt.ReceiptID ||
		material.RuntimeKeyID !=
			fixture.session.manifest.RuntimeKeys[0].KeyID ||
		material.Status != receipt.Status ||
		material.ChargedNanoTOS != receipt.ChargedNanoTOS ||
		material.ResultDigest != receipt.ResultDigest ||
		material.EnvelopeDigest == "" ||
		len(material.Usage) != 1 {
		t.Fatalf("unexpected receipt material: %#v", material)
	}
	material.Usage[0].Quantity = 999
	material.Envelope.Payload[0] ^= 1
	again, err := verified.ApplicationMaterial(binding, receiptNow)
	if err != nil {
		t.Fatal(err)
	}
	if again.Usage[0].Quantity != 10 {
		t.Fatal("receipt usage was not defensively copied")
	}
	fingerprint, err := again.Envelope.Fingerprint()
	if err != nil || fingerprint != again.EnvelopeDigest {
		t.Fatalf("defensive receipt envelope: digest=%q err=%v", fingerprint, err)
	}
	changed := binding
	changed.RequestID = "request-attacker"
	if _, err := verified.ApplicationMaterial(
		changed, receiptNow,
	); err == nil {
		t.Fatal("verified receipt reused for another request")
	}
	if _, err := (VerifiedReceipt{}).ApplicationMaterial(
		binding, receiptNow,
	); err == nil {
		t.Fatal("zero verified receipt accepted")
	}
}

func TestReceiptAuthorizationRejectsSubstitutionAndWrongRole(t *testing.T) {
	fixture := newReceiptAuthorizationFixture(t)
	receiptNow := fixture.session.now.Add(2 * time.Minute)
	receipt := protocol.Receipt{
		Version:   protocol.BaseEnvelopeVersion,
		ReceiptID: "receipt-0001", RequestID: fixture.quote.RequestID,
		QuoteID:         fixture.quote.QuoteID,
		AuthorizationID: "authorization-attacker",
		ServiceID:       fixture.quote.ServiceID, Status: "failed",
		Usage: []protocol.UsageItem{}, ChargedNanoTOS: 0,
		ServiceRevision:  fixture.quote.ServiceRevision,
		ResourceRevision: fixture.quote.ResourceRevision,
		CompletedAt:      receiptNow,
	}
	envelope, err := identity.SignCanonical(
		fixture.session.runtimePrivate, protocol.ReceiptDomain,
		fixture.session.manifest.RuntimeKeys[0].KeyID,
		receipt, receiptNow, receiptNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manifest.VerifyReceipt(
		envelope, fixture.authorized, receiptNow,
	); err == nil {
		t.Fatal("receipt with substituted payment authorization accepted")
	}

	receipt.AuthorizationID = fixture.payment.AuthorizationID
	envelope, err = identity.SignCanonical(
		fixture.session.runtimePrivate, protocol.ReceiptDomain,
		fixture.session.manifest.RuntimeKeys[0].KeyID,
		receipt, receiptNow, receiptNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	withoutRole := *fixture.manifest
	withoutRole.runtimeKeys = make(
		map[string]protocol.RuntimeKey,
		len(fixture.manifest.runtimeKeys),
	)
	for keyID, key := range fixture.manifest.runtimeKeys {
		key.Roles = []string{protocol.RuntimeRoleAuthenticate}
		withoutRole.runtimeKeys[keyID] = key
	}
	if _, err := withoutRole.VerifyReceipt(
		envelope, fixture.authorized, receiptNow,
	); err == nil {
		t.Fatal("receipt signed by a key without receipt role accepted")
	}
}
