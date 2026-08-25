package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type providerOfferResolver struct{ key ed25519.PublicKey }

func (resolver providerOfferResolver) AuthorizeProviderOfferKey(context ProviderProofContext,
	binding PaidDemandQuoteBindingBody, key ed25519.PublicKey, _ time.Time) error {
	if context.Purpose != "provider-offer.sign" || context.ProviderAgentID != binding.ProviderAgentID || !resolver.key.Equal(key) {
		return errors.New("unauthorized Provider Offer key")
	}
	return nil
}

type acceptingPaidDemandVerifier struct{}

func (acceptingPaidDemandVerifier) VerifyPaidDemandNativeEvidence(_ PaidDemandQuoteBindingBody, kind string, evidence []byte,
	_ uint64, reference string, _ time.Time) error {
	if (kind != "buyer_accept" && kind != "provider_offer") || len(evidence) == 0 || reference == "" {
		return errors.New("rejected test evidence")
	}
	return nil
}

func TestPaidDemandEvidenceBindsExactGenericAgreement(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	profile := PaidDemandQuoteProfileDigest()
	provider := AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: "agent:provider"}
	buyerWallet := AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet", SubjectIdentifier: "wallet:buyer", RepresentedAgentID: "agent:buyer"}
	body := AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:paid", Version: 1, NetworkContext: "tos:test",
		Participants:     []AgreementParticipant{{AgentID: "agent:buyer", Roles: []string{"buyer"}}, {AgentID: "agent:provider", Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("one chain-bound task"),
		Obligations: []AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: "agent:buyer", BeneficiaryAgentID: "agent:provider", DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay exact quote"), Amount: &AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "50", Unit: "nano"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", SettlementAdapterURI: "tos.escrow.paid-demand.v1",
				SettlementParameters: []byte("quote-profile-v1"), AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: "agent:provider", BeneficiaryAgentID: "agent:buyer", SubjectContentType: "text/plain", Subject: []byte("perform task"),
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}},
		},
		AuthorizationPredicates: []AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: buyerWallet, ObligationIDs: []string{"pay"}, EvidenceProfileURI: EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: provider, ObligationIDs: []string{"work"}, EvidenceProfileURI: EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		}, ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	var err error
	body, err = PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := AgreementBodyDigest(body)
	binding := PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: body.NetworkContext, AgreementBodyDigest: digest,
		AgreementObligationIDs: []string{"pay", "work"}, AgreementAuthorizationPredicateIDs: []string{"predicate:buyer", "predicate:provider"},
		AgreementAuthorizationTargetDigests: []string{body.AuthorizationPredicates[0].EvidenceTargetProjectionDigest, body.AuthorizationPredicates[1].EvidenceTargetProjectionDigest},
		EvidenceProfileURI:                  EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile,
		DemandMutationDigest: "sha256:" + strings.Repeat("1", 64), ProviderOfferID: "offer:one", ProviderAgentID: "agent:provider",
		BuyerAgentID: "agent:buyer", BuyerWallet: "wallet:buyer", ProviderWallet: "wallet:provider",
		NativeQuoteTermsProjectionDigest: "tvm-cell-sha256:" + strings.Repeat("2", 64), AcceptByUnix: uint64(now.Add(30 * time.Minute).Unix())}
	providerEvidence, err := PaidDemandEvidenceFromBinding(body, provider, binding, "provider_offer", []byte("signed offer"), uint64(now.Unix()), "provider-proof")
	if err != nil {
		t.Fatal(err)
	}
	buyerEvidence, err := PaidDemandEvidenceFromBinding(body, buyerWallet, binding, "buyer_accept", []byte("finalized accept"), uint64(now.Unix()), "block:1")
	if err != nil {
		t.Fatal(err)
	}
	verifier := PaidDemandQuoteEvidenceVerifier{Native: acceptingPaidDemandVerifier{}}
	if err := ValidateAgreementAuthorization(AgentAgreement{Body: body, AuthorizationEvidence: []AgreementAuthorizationEvidence{buyerEvidence, providerEvidence}}, verifier, now); err != nil {
		t.Fatal(err)
	}
	mutated := body
	mutated.Terms = []byte("different task")
	mutated, err = PrepareAgreementTargets(clearAgreementTargets(mutated))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PaidDemandEvidenceFromBinding(mutated, buyerWallet, binding, "buyer_accept", []byte("finalized accept"), uint64(now.Unix()), "block:1"); err == nil {
		t.Fatal("chain evidence replayed to a modified Agreement")
	}
}

func clearAgreementTargets(body AgentAgreementBody) AgentAgreementBody {
	for index := range body.AuthorizationPredicates {
		body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	return body
}

func TestProviderOfferSignsOneExactBindingAndProofContext(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	binding := PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: "tos:test", AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64),
		AgreementObligationIDs: []string{"pay"}, AgreementAuthorizationPredicateIDs: []string{"predicate:buyer"},
		AgreementAuthorizationTargetDigests: []string{"sha256:" + strings.Repeat("2", 64)}, EvidenceProfileURI: EvidenceProfilePaidDemandQuote,
		EvidenceProfileVersion: 1, EvidenceProfileDigest: PaidDemandQuoteProfileDigest(), DemandMutationDigest: "sha256:" + strings.Repeat("3", 64),
		ProviderOfferID: "offer:one", ProviderAgentID: "agent:provider", BuyerAgentID: "agent:buyer", BuyerWallet: "wallet:buyer",
		ProviderWallet: "wallet:provider", NativeQuoteTermsProjectionDigest: "tvm-cell-sha256:" + strings.Repeat("4", 64),
		AcceptByUnix: uint64(now.Add(time.Hour).Unix())}
	context := ProviderProofContext{SchemaVersion: 1, NetworkContext: binding.NetworkContext, ProviderAgentID: binding.ProviderAgentID,
		Purpose: "provider-offer.sign", PublicKey: "ed25519:" + strings.Repeat("00", 32), AgentGeneration: 1,
		ControllerPolicyDigest: "sha256:" + strings.Repeat("5", 64), DelegationDigest: "sha256:" + strings.Repeat("6", 64),
		ScopeBoundsDigest: "sha256:" + strings.Repeat("7", 64), OwnerMandateDigest: "sha256:" + strings.Repeat("8", 64),
		IssuanceAuthorityReferenceDigest: "sha256:" + strings.Repeat("9", 64), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()),
		ExpiresAtUnix: uint64(now.Add(2 * time.Hour).Unix())}
	context.PublicKey = "ed25519:" + fmtHex(key.Public().(ed25519.PublicKey))
	offer, err := SignProviderOffer(binding, context, key)
	if err != nil || VerifyProviderOffer(offer, providerOfferResolver{key.Public().(ed25519.PublicKey)}, now) != nil {
		t.Fatal("valid Provider Offer failed", err)
	}
	digest, err := ProviderOfferDigest(offer)
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatal("Provider Offer has no canonical digest")
	}
	mutated := offer
	mutated.Binding.BuyerWallet = "wallet:attacker"
	if VerifyProviderOffer(mutated, providerOfferResolver{key.Public().(ed25519.PublicKey)}, now) == nil {
		t.Fatal("Provider signature survived binding substitution")
	}
}

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for index, item := range value {
		result[index*2] = alphabet[item>>4]
		result[index*2+1] = alphabet[item&15]
	}
	return string(result)
}
