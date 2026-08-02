package authorization

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type quoteSignerFunc func(
	context.Context,
	[]byte,
	time.Time,
	time.Time,
) (identity.Envelope, error)

func (f quoteSignerFunc) SignQuote(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	return f(ctx, payload, issuedAt, expiresAt)
}

func TestIssueQuoteDerivesManifestAndSessionAuthority(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	draft := quoteDraft(fixture)
	signerCalls := 0
	signer := quoteSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		signerCalls++
		return identity.Sign(
			fixture.runtimePrivate, protocol.QuoteDomain,
			fixture.manifest.RuntimeKeys[0].KeyID,
			payload, issuedAt, expiresAt,
		)
	})
	verified, err := manifest.IssueQuote(
		context.Background(), fixture.verified, draft, signer, fixture.now,
	)
	if err != nil || verified == nil || signerCalls != 1 {
		t.Fatalf("issued quote=%v calls=%d err=%v", verified, signerCalls, err)
	}
	envelope, err := verified.SignedEnvelope(fixture.now)
	if err != nil || envelope.KeyID != fixture.manifest.RuntimeKeys[0].KeyID {
		t.Fatalf("issued quote envelope=%#v err=%v", envelope, err)
	}
	envelope.Payload[0] ^= 0xff
	again, err := verified.SignedEnvelope(fixture.now)
	if err != nil || string(again.Payload) == string(envelope.Payload) {
		t.Fatal("verified quote envelope aliases caller mutation")
	}
	if verified.quote.Network != fixture.manifest.Network ||
		verified.quote.ServiceID != fixture.manifest.ServiceID ||
		verified.quote.ServiceRevision != fixture.manifest.Revision ||
		verified.quote.SessionID != fixture.session.SessionID ||
		verified.quote.ProfileID != fixture.session.ProfileID ||
		verified.quote.Operation != fixture.payload.Operation ||
		verified.quote.QuoteID != draft.QuoteID ||
		verified.quote.ResourceLimits[0] != draft.ResourceLimits[0] {
		t.Fatalf("issued quote has incorrect derived authority: %#v", verified.quote)
	}
	draft.ResourceLimits[0].Quantity++
	if verified.quote.ResourceLimits[0].Quantity == draft.ResourceLimits[0].Quantity {
		t.Fatal("issued quote aliases caller resource limits")
	}
}

func TestIssueQuoteRejectsUnsafeSignerAndSessionDrift(t *testing.T) {
	fixture := newSessionAuthFixture(t)
	manifest, err := newTestVerifier(t).VerifyManifest(
		fixture.snapshot, fixture.manifestEnvelope, fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	draft := quoteDraft(fixture)
	validSigner := quoteSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		return identity.Sign(
			fixture.runtimePrivate, protocol.QuoteDomain,
			fixture.manifest.RuntimeKeys[0].KeyID,
			payload, issuedAt, expiresAt,
		)
	})
	var typedNilSigner quoteSignerFunc
	if _, err := manifest.IssueQuote(
		context.Background(), fixture.verified, draft,
		typedNilSigner, fixture.now,
	); err == nil {
		t.Fatal("typed-nil quote signer accepted")
	}
	for name, mutate := range map[string]func(*QuoteDraft){
		"operation": func(value *QuoteDraft) { value.Operation = "not-authorized" },
		"expiry": func(value *QuoteDraft) {
			value.ExpiresAt = fixture.session.ExpiresAt.Add(time.Millisecond)
			value.Deadline = value.ExpiresAt
		},
		"invalid resource": func(value *QuoteDraft) {
			value.ResourceLimits = append(value.ResourceLimits, value.ResourceLimits[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := draft
			changed.ResourceLimits = append(
				[]protocol.ResourceLimit(nil), draft.ResourceLimits...,
			)
			mutate(&changed)
			if _, err := manifest.IssueQuote(
				context.Background(), fixture.verified, changed,
				validSigner, fixture.now,
			); err == nil {
				t.Fatal("unsafe quote was issued")
			}
		})
	}
	mutatingSigner := quoteSignerFunc(func(
		_ context.Context,
		payload []byte,
		issuedAt time.Time,
		expiresAt time.Time,
	) (identity.Envelope, error) {
		payload = append([]byte(nil), payload...)
		payload[0] ^= 0xff
		return identity.Sign(
			fixture.runtimePrivate, protocol.QuoteDomain,
			fixture.manifest.RuntimeKeys[0].KeyID,
			payload, issuedAt, expiresAt,
		)
	})
	if _, err := manifest.IssueQuote(
		context.Background(), fixture.verified, draft,
		mutatingSigner, fixture.now,
	); err == nil {
		t.Fatal("quote signer payload substitution was accepted")
	}
	failingSigner := quoteSignerFunc(func(
		context.Context, []byte, time.Time, time.Time,
	) (identity.Envelope, error) {
		return identity.Envelope{}, errors.New("custody unavailable")
	})
	if _, err := manifest.IssueQuote(
		context.Background(), fixture.verified, draft,
		failingSigner, fixture.now,
	); err == nil {
		t.Fatal("quote signing failure was ignored")
	}
	panickingSigner := quoteSignerFunc(func(
		context.Context, []byte, time.Time, time.Time,
	) (identity.Envelope, error) {
		panic("custody panic")
	})
	if _, err := manifest.IssueQuote(
		context.Background(), fixture.verified, draft,
		panickingSigner, fixture.now,
	); err == nil {
		t.Fatal("quote signing panic escaped")
	}
}

func quoteDraft(fixture sessionAuthFixture) QuoteDraft {
	return QuoteDraft{
		QuoteID: "issued-quote-0001", RequestID: fixture.payload.RequestID,
		Operation:        fixture.payload.Operation,
		IntentDigest:     fixture.admissionBinding.IntentDigest,
		ResourceRevision: "resource-revision-1",
		Payee:            "service-wallet", Settlement: "payment-reference-0001",
		PriceNanoTOS: 5, MaxInputBytes: 1024, MaxOutputBytes: 2048,
		ResourceLimits: []protocol.ResourceLimit{{
			ID: "ram", Unit: protocol.ResourceUnitBytes, Quantity: 1024,
		}},
		Deadline:  fixture.now.Add(5 * time.Minute),
		ExpiresAt: fixture.now.Add(time.Minute),
	}
}
