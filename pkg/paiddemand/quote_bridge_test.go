package paiddemand

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

type offerKeyResolver struct{ key ed25519.PublicKey }

func (resolver offerKeyResolver) AuthorizeProviderOfferKey(_ commerce.ProviderProofContext,
	_ commerce.PaidDemandQuoteBindingBody, key ed25519.PublicKey, _ time.Time) error {
	if !resolver.key.Equal(key) {
		return errors.New("wrong key")
	}
	return nil
}

func TestGenericAgreementBuildsAndRecoversOneAcceptedQuoteV2(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	provider := "agent_" + strings.Repeat("44", 32)
	buyer := "agent:buyer"
	buyerWallet, providerWallet := "0:"+strings.Repeat("11", 32), "0:"+strings.Repeat("22", 32)
	masterBytes, _ := hex.DecodeString(strings.Repeat("33", 32))
	master := "0:" + hex.EncodeToString(masterBytes)
	terms := nativecore.EscrowTermsV1{BuyerAddress: buyerWallet, ProviderAddress: providerWallet,
		FundingDeadline: uint64(now.Add(20 * time.Minute).Unix()), RefundAvailableAt: uint64(now.Add(2 * time.Hour).Unix())}
	termsCell, _ := nativecore.BuildEscrowTermsCellV1(terms)
	transport := nativecore.TransportBindingV1{SecurityMode: 1, MaxRequestBytes: 4096, BaseURL: "https://provider.test"}
	_, transportDigest, _ := nativecore.BuildTransportBindingCellV1(transport)
	_, disputeDigest := nativecore.BuildObjectiveDisputePolicyCellV1()
	signerKey := bytes.Repeat([]byte{0x55}, 32)
	authorization, _ := nativecore.BuildEscrowAuthorizationCellV1(signerKey)
	network := &nativev1.NetworkDomain{NetworkId: "tos:test", GenesisRootHash: "sha256:" + strings.Repeat("aa", 32), GenesisFileHash: "sha256:" + strings.Repeat("bb", 32)}
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + strings.Repeat("66", 32), CapabilityVersion: "1.0.0",
		ProviderAgentId: provider, ManifestDigest: "sha256:" + strings.Repeat("77", 32), TransportBindingDigest: transportDigest,
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: masterBytes, CodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32)},
			WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("99", 32), Decimals: 6}, AtomicAmount: "1000"},
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(termsCell.Hash()), DisputePolicyDigest: disputeDigest,
		ExpiresAtUnixSeconds: uint64(now.Add(10 * time.Minute).Unix())}
	_, projection, err := nativecore.BuildAcceptedQuoteCommitment(network, proposal, "sha256:"+hex.EncodeToString(authorization.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	profile := commerce.PaidDemandQuoteProfileDigest()
	providerSubject := commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: provider}
	buyerSubject := commerce.AgreementAuthoritySubject{SubjectKind: "wallet", SubjectNamespace: "tos.wallet", SubjectIdentifier: buyerWallet, RepresentedAgentID: buyer}
	agreement := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:test", Version: 1, NetworkContext: network.NetworkId,
		Participants:     []commerce.AgreementParticipant{{AgentID: buyer, Roles: []string{"buyer"}}, {AgentID: provider, Roles: []string{"provider"}}},
		TermsContentType: "text/plain", Terms: []byte("bounded work"), Obligations: []commerce.AgreementObligation{
			{ObligationID: "pay", Kind: "payment", ObligorAgentID: buyer, BeneficiaryAgentID: provider, DependsOnObligationIDs: []string{"work"},
				SubjectContentType: "text/plain", Subject: []byte("pay"), Amount: &commerce.AgreementAmount{AssetNamespace: "tos.contract", AssetIdentifier: master, AmountAtomic: "1000", Unit: "atomic"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", SettlementAdapterURI: SettlementAdapterURI,
				SettlementParameters: []byte(providerWallet), AuthorizationPredicateIDs: []string{"predicate:buyer"}},
			{ObligationID: "work", Kind: "service", ObligorAgentID: provider, BeneficiaryAgentID: buyer, SubjectContentType: "text/plain", Subject: []byte("bounded work"),
				ConfidentialityPolicy: "participants", CancellationPolicy: "chain-profile", DisputePolicy: "objective", AuthorizationPredicateIDs: []string{"predicate:provider"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: buyerSubject, ObligationIDs: []string{"pay"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: providerSubject, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfilePaidDemandQuote,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profile, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	agreement, err = commerce.PrepareAgreementTargets(agreement)
	if err != nil {
		t.Fatal(err)
	}
	agreementDigest, _ := commerce.AgreementBodyDigest(agreement)
	binding := commerce.PaidDemandQuoteBindingBody{SchemaVersion: 1, NetworkContext: network.NetworkId, AgreementBodyDigest: agreementDigest,
		AgreementObligationIDs: []string{"pay", "work"}, AgreementAuthorizationPredicateIDs: []string{"predicate:buyer", "predicate:provider"},
		AgreementAuthorizationTargetDigests: []string{agreement.AuthorizationPredicates[0].EvidenceTargetProjectionDigest, agreement.AuthorizationPredicates[1].EvidenceTargetProjectionDigest},
		EvidenceProfileURI:                  commerce.EvidenceProfilePaidDemandQuote, EvidenceProfileVersion: 1, EvidenceProfileDigest: profile,
		DemandMutationDigest: "sha256:" + strings.Repeat("cc", 32), ProviderOfferID: "offer:test", ProviderAgentID: provider,
		BuyerAgentID: buyer, BuyerWallet: buyerWallet, ProviderWallet: providerWallet, NativeQuoteTermsProjectionDigest: projection,
		AcceptByUnix: proposal.ExpiresAtUnixSeconds}
	providerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	context := commerce.ProviderProofContext{SchemaVersion: 1, NetworkContext: network.NetworkId, ProviderAgentID: provider,
		Purpose: "provider-offer.sign", PublicKey: "ed25519:" + hex.EncodeToString(providerKey.Public().(ed25519.PublicKey)), AgentGeneration: 1,
		ControllerPolicyDigest: "sha256:" + strings.Repeat("01", 32), DelegationDigest: "sha256:" + strings.Repeat("02", 32),
		ScopeBoundsDigest: "sha256:" + strings.Repeat("03", 32), OwnerMandateDigest: "sha256:" + strings.Repeat("04", 32),
		IssuanceAuthorityReferenceDigest: "sha256:" + strings.Repeat("05", 32), ValidFromUnix: uint64(now.Add(-time.Hour).Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	offer, err := commerce.SignProviderOffer(binding, context, providerKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := offerKeyResolver{providerKey.Public().(ed25519.PublicKey)}
	input := QuoteBuildInput{Agreement: agreement, ProviderOffer: offer, ProviderOfferResolver: resolver, Network: network,
		Proposal: proposal, ExecutionSignerAuthorization: "sha256:" + hex.EncodeToString(authorization.Hash()), EscrowTerms: terms,
		ExecutionDeadlineUnix: uint64(now.Add(90 * time.Minute).Unix()), Now: now}
	quote, commitment, err := BuildAcceptedQuote(input)
	if err != nil {
		t.Fatal(err)
	}
	decoded, recovered, err := VerifyAcceptedQuote(quote, agreement, network, terms, resolver, now)
	if err != nil || decoded.NativeTermsProjection != projection || recovered.Binding.AgreementBodyDigest != agreementDigest || commitment == projection {
		t.Fatalf("decoded=%+v recovered=%+v err=%v", decoded, recovered, err)
	}
	changed := agreement
	changed.Terms = []byte("changed")
	changed, _ = commerce.PrepareAgreementTargets(clearTargets(changed))
	if _, _, err := VerifyAcceptedQuote(quote, changed, network, terms, resolver, now); err == nil {
		t.Fatal("Accepted Quote replayed to a changed generic Agreement")
	}
}

func clearTargets(body commerce.AgentAgreementBody) commerce.AgentAgreementBody {
	for index := range body.AuthorizationPredicates {
		body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	return body
}
