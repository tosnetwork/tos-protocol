package authorization

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type receiptSignerFunc func(
	context.Context,
	[]byte,
	time.Time,
	time.Time,
) (identity.Envelope, error)

func (f receiptSignerFunc) SignReceipt(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	return f(ctx, payload, issuedAt, expiresAt)
}

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

func TestReceiptIssuanceBindsDraftAndExternalSigner(t *testing.T) {
	fixture := newReceiptAuthorizationFixture(t)
	receiptNow := fixture.session.now.Add(2 * time.Minute)
	signerCalls := 0
	signer := receiptSignerFunc(func(
		ctx context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		signerCalls++
		if err := ctx.Err(); err != nil {
			return identity.Envelope{}, err
		}
		return identity.Sign(
			fixture.session.runtimePrivate,
			protocol.ReceiptDomain,
			fixture.session.manifest.RuntimeKeys[0].KeyID,
			payload,
			issuedAt,
			expiresAt,
		)
	})
	draft := ReceiptDraft{
		ReceiptID: "receipt-issued-0001", Status: "succeeded",
		Usage: []protocol.UsageItem{
			{Unit: "output_tokens", Quantity: 10},
		},
		ChargedNanoTOS: fixture.quote.PriceNanoTOS,
		ResultDigest:   "sha256:" + strings.Repeat("c", 64),
		CompletedAt:    receiptNow,
	}
	verified, err := fixture.manifest.IssueReceipt(
		context.Background(),
		fixture.authorized,
		draft,
		signer,
		receiptNow,
		receiptNow.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := fixture.authorized.ReceiptInvocationMaterial()
	if err != nil {
		t.Fatal(err)
	}
	material, err := verified.ApplicationMaterial(ReceiptBinding{
		Network: invocation.Network, ServiceID: invocation.ServiceID,
		SessionID: invocation.SessionID, Operation: invocation.Operation,
		RequestID: invocation.RequestID, IntentDigest: invocation.IntentDigest,
		AuthorizationID: invocation.AuthorizationID,
		QuoteID:         invocation.QuoteID,
	}, receiptNow)
	if err != nil {
		t.Fatal(err)
	}
	if signerCalls != 1 || material.ReceiptID != draft.ReceiptID ||
		material.ChargedNanoTOS != draft.ChargedNanoTOS ||
		material.ServiceRevision != fixture.quote.ServiceRevision ||
		material.ResourceRevision != fixture.quote.ResourceRevision {
		t.Fatalf(
			"calls=%d material=%#v",
			signerCalls,
			material,
		)
	}

	draft.Usage[0].Quantity = 999
	if material.Usage[0].Quantity != 10 {
		t.Fatal("issued receipt aliased caller usage")
	}
}

func TestDurableReceiptIssuanceAfterQuoteExpiry(t *testing.T) {
	fixture := newReceiptAuthorizationFixture(t)
	durable, err := fixture.authorized.DurableExecutionAuthorization()
	if err != nil {
		t.Fatal(err)
	}
	material, err := durable.ReceiptInvocationMaterial()
	if err != nil {
		t.Fatal(err)
	}
	live, err := fixture.authorized.ReceiptInvocationMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(material, live) {
		t.Fatalf("durable material = %#v, live = %#v", material, live)
	}
	receiptNow := fixture.quote.ExpiresAt.Add(time.Minute)
	if _, err := fixture.authorized.ObservationMaterial(receiptNow); err == nil {
		t.Fatal("expired payment authorization remained observable")
	}
	signer := receiptSignerFunc(func(
		ctx context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		if err := ctx.Err(); err != nil {
			return identity.Envelope{}, err
		}
		return identity.Sign(
			fixture.session.runtimePrivate,
			protocol.ReceiptDomain,
			fixture.session.manifest.RuntimeKeys[0].KeyID,
			payload,
			issuedAt,
			expiresAt,
		)
	})
	if _, err := fixture.manifest.IssueDurableReceipt(
		context.Background(),
		durable,
		ReceiptDraft{
			ReceiptID: "receipt-durable-0001", Status: "failed",
			Usage: []protocol.UsageItem{}, CompletedAt: receiptNow,
		},
		signer,
		receiptNow,
		receiptNow.Add(time.Minute),
	); err != nil {
		t.Fatal(err)
	}
	changed := durable
	changed.ProfileExtensions = []string{
		"urn:tos:extension:z", "urn:tos:extension:a",
	}
	if _, err := changed.ReceiptInvocationMaterial(); err == nil {
		t.Fatal("noncanonical durable profile accepted")
	}
}

func TestReceiptIssuanceRejectsSignerDeviationAndCancellation(t *testing.T) {
	fixture := newReceiptAuthorizationFixture(t)
	receiptNow := fixture.session.now.Add(2 * time.Minute)
	draft := ReceiptDraft{
		ReceiptID: "receipt-issued-0002", Status: "succeeded",
		Usage:          []protocol.UsageItem{},
		ChargedNanoTOS: fixture.quote.PriceNanoTOS,
		ResultDigest:   "sha256:" + strings.Repeat("d", 64),
		CompletedAt:    receiptNow,
	}
	mutatingSigner := receiptSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		payload = append([]byte(nil), payload...)
		payload[0] ^= 1
		return identity.Sign(
			fixture.session.runtimePrivate,
			protocol.ReceiptDomain,
			fixture.session.manifest.RuntimeKeys[0].KeyID,
			payload,
			issuedAt,
			expiresAt,
		)
	})
	if _, err := fixture.manifest.IssueReceipt(
		context.Background(),
		fixture.authorized,
		draft,
		mutatingSigner,
		receiptNow,
		receiptNow.Add(time.Minute),
	); err == nil || !strings.Contains(err.Error(), "changed payload") {
		t.Fatalf("mutating receipt signer error=%v", err)
	}

	wrongKeySigner := receiptSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		return identity.Sign(
			fixture.session.runtimePrivate,
			protocol.ReceiptDomain,
			"runtime-wrong-key",
			payload,
			issuedAt,
			expiresAt,
		)
	})
	if _, err := fixture.manifest.IssueReceipt(
		context.Background(),
		fixture.authorized,
		draft,
		wrongKeySigner,
		receiptNow,
		receiptNow.Add(time.Minute),
	); err == nil {
		t.Fatal("receipt signer outside current manifest accepted")
	}

	called := false
	canceledSigner := receiptSignerFunc(func(
		context.Context,
		[]byte,
		time.Time,
		time.Time,
	) (identity.Envelope, error) {
		called = true
		return identity.Envelope{}, errors.New("unexpected signer call")
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := fixture.manifest.IssueReceipt(
		ctx,
		fixture.authorized,
		draft,
		canceledSigner,
		receiptNow,
		receiptNow.Add(time.Minute),
	); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("canceled issue err=%v called=%v", err, called)
	}

	panickingSigner := receiptSignerFunc(func(
		context.Context,
		[]byte,
		time.Time,
		time.Time,
	) (identity.Envelope, error) {
		panic("custody panic")
	})
	var typedNilSigner receiptSignerFunc
	if _, err := fixture.manifest.IssueReceipt(
		context.Background(), fixture.authorized, draft, typedNilSigner,
		receiptNow, receiptNow.Add(time.Minute),
	); err == nil {
		t.Fatal("typed-nil receipt signer accepted")
	}
	if _, err := fixture.manifest.IssueReceipt(
		context.Background(), fixture.authorized, draft, panickingSigner,
		receiptNow, receiptNow.Add(time.Minute),
	); err == nil {
		t.Fatal("receipt signing panic escaped")
	}

	draft.ChargedNanoTOS = fixture.quote.PriceNanoTOS + 1
	if _, err := fixture.manifest.IssueReceipt(
		context.Background(),
		fixture.authorized,
		draft,
		wrongKeySigner,
		receiptNow,
		receiptNow.Add(time.Minute),
	); err == nil || !strings.Contains(err.Error(), "quoted price") {
		t.Fatalf("excess receipt charge error=%v", err)
	}
}
