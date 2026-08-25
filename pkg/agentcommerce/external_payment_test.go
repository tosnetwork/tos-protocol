package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type externalAttestorPin struct{ key ed25519.PublicKey }

func (pin externalAttestorPin) AuthorizeExternalPaymentAttestor(id, adapter string, key ed25519.PublicKey, _ time.Time) error {
	if id != "attestor:test" || adapter != "tos.payment.external.v1" || !pin.key.Equal(key) {
		return errors.New("not pinned")
	}
	return nil
}

func TestExternalPaymentAttestationCannotBeReplayedAcrossRequests(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))
	amount := AgreementAmount{AssetNamespace: "external", AssetIdentifier: "usd", AmountAtomic: "5000", Unit: "cent"}
	materialized, err := MaterializeSettlementObligations("owner:test", "agent:payer", "sha256:"+strings.Repeat("1", 64), "pay",
		"sha256:"+strings.Repeat("3", 64), AgreementObligation{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:payer",
			BeneficiaryAgentID: "agent:payee", SubjectContentType: "text/plain", Subject: []byte("external payment"), Amount: &amount, DueAtUnix: uint64(now.Add(time.Hour).Unix()),
			ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix()), SettlementAdapterURI: "tos.payment.external.v1",
			SettlementParameters: []byte("account:payee"), ConfidentialityPolicy: "participants", CancellationPolicy: "before-due", DisputePolicy: "manual",
			AuthorizationPredicateIDs: []string{"predicate:payer"}})
	if err != nil || len(materialized) != 1 {
		t.Fatal(err)
	}
	obligation := materialized[0]
	profileDigest := "sha256:" + strings.Repeat("4", 64)
	request, err := BuildExternalAgreementPaymentRequestAmount("owner:test", "agent:payer", "external:test", "bank:test",
		profileDigest, []byte("account:payee"), obligation, obligation.Amount)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := AgreementPaymentRequestDigest(request)
	attestation, err := SignExternalPaymentAttestation(ExternalPaymentAttestationBody{SchemaVersion: 1,
		AdapterURI: request.SettlementAdapterURI, AttestorID: "attestor:test", PaymentRequestDigest: digest,
		StableActionID: request.StableActionID, ExactTransferReference: "external:transfer:1", FinalityReference: "ledger:final:9",
		ResolvedAtUnix: uint64(now.Add(-time.Second).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}, key)
	if err != nil {
		t.Fatal(err)
	}
	resolver := externalAttestorPin{key.Public().(ed25519.PublicKey)}
	evidence, err := ExternalPaymentEvidence(request, attestation, resolver, now)
	if err != nil || VerifyAgreementPaymentEvidence(request, evidence, ExternalPaymentEvidenceVerifier{Resolver: resolver}, now) != nil {
		t.Fatal("valid external settlement evidence failed", err)
	}
	mutated, err := BuildExternalAgreementPaymentRequestAmount("owner:test", "agent:payer", "external:test", "bank:test",
		profileDigest, []byte("account:attacker"), obligation, obligation.Amount)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAgreementPaymentEvidence(mutated, evidence, ExternalPaymentEvidenceVerifier{Resolver: resolver}, now); err == nil {
		t.Fatal("external attestation was replayed to a changed destination")
	}
}

func TestExternalPaymentHasDistinctSemanticIdentity(t *testing.T) {
	now := uint64(2_000_000_000)
	obligation := SettlementObligation{AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64), AgreementObligationID: "payment:1",
		ObligationInstanceID: "sha256:" + strings.Repeat("2", 64), Sequence: 1, PayerAgentID: "agent:buyer", PayeeAgentID: "agent:provider",
		Amount: AgreementAmount{AssetNamespace: "external", AssetIdentifier: "usd", AmountAtomic: "5000", Unit: "cent"}, ExpiresAtUnix: now + 100,
		MaximumAggregateAmount: AgreementAmount{AssetNamespace: "external", AssetIdentifier: "usd", AmountAtomic: "5000", Unit: "cent"},
		SettlementAdapterURI:   "tos.payment.external.v1", SettlementParametersDigest: "sha256:" + strings.Repeat("3", 64), StableActionID: "sha256:" + strings.Repeat("4", 64)}
	direct, err := BuildAgreementPaymentRequest("owner:test", "agent:payer", "external:test", []byte("account:payee"), obligation)
	if err != nil {
		t.Fatal(err)
	}
	external, err := BuildExternalAgreementPaymentRequestAmount("owner:test", "agent:payer", "external:test", "bank:test",
		"sha256:"+strings.Repeat("5", 64), []byte("account:payee"), obligation, obligation.Amount)
	if err != nil {
		t.Fatal(err)
	}
	if external.StableActionID == direct.StableActionID || external.SchemaVersion != 2 ||
		external.SemanticActionKind != "settlement.external" || ValidateAgreementPaymentRequest(external) != nil {
		t.Fatal("external settlement did not use its independently verifiable semantic identity")
	}
}
