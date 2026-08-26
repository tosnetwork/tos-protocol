package agentcommerce

import (
	"strings"
	"testing"
	"time"
)

type paymentVerifier struct{}

func (paymentVerifier) VerifyPaymentEvidence(AgreementPaymentRequest, AgreementPaymentEvidence, time.Time) error {
	return nil
}

func TestAgreementPaymentBindsObligationAssetAmountAndDestination(t *testing.T) {
	now := uint64(2_000_000_000)
	obligation := SettlementObligation{AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64), AgreementObligationID: "payment:1",
		ObligationInstanceID: "sha256:" + strings.Repeat("2", 64), Sequence: 1, PayerAgentID: "agent:buyer", PayeeAgentID: "agent:provider",
		Amount: AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "nanotos"}, ExpiresAtUnix: now + 100,
		MaximumAggregateAmount: AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "nanotos"},
		SettlementAdapterURI:   "tos.payment.direct.v1", SettlementParametersDigest: "sha256:" + strings.Repeat("3", 64), StableActionID: "sha256:" + strings.Repeat("4", 64)}
	request, err := BuildAgreementPaymentRequest("owner", "agent:buyer", "tos:testnet", []byte("0:destination"), obligation)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := AgreementPaymentRequestDigest(request)
	evidence := AgreementPaymentEvidence{PaymentRequestDigest: digest, StableActionID: request.StableActionID, ExactTransferReference: "tx:abc",
		AdapterEvidenceProfile: "tos.finalized-transfer.v1", ResolvedState: "finalized", ResolvedAtUnix: now, FinalityReference: "checkpoint:10", Evidence: []byte("proof")}
	if err := VerifyAgreementPaymentEvidence(request, evidence, paymentVerifier{}, time.Unix(int64(now+1), 0)); err != nil {
		t.Fatal(err)
	}
	mutated := request
	mutated.Destination = []byte("0:attacker")
	if err := ValidateAgreementPaymentRequest(mutated); err == nil {
		t.Fatal("destination substitution preserved payment identity")
	}
	mutated = request
	mutated.Amount.AmountAtomic = "51"
	if err := ValidateAgreementPaymentRequest(mutated); err == nil {
		t.Fatal("amount substitution preserved payment identity")
	}
}

func TestDomainBoundAgreementPaymentCannotReplayAcrossGenesis(t *testing.T) {
	obligation := SettlementObligation{AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64),
		AgreementObligationID: "payment:domain", ObligationInstanceID: "sha256:" + strings.Repeat("2", 64),
		Sequence: 1, PayerAgentID: "agent:buyer", PayeeAgentID: "agent:provider",
		Amount:                 AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "1", Unit: "nanotos"},
		MaximumAggregateAmount: AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "1", Unit: "nanotos"},
		SettlementAdapterURI:   "tos.payment.direct.v1", SettlementParametersDigest: "sha256:" + strings.Repeat("3", 64),
		StableActionID: "sha256:" + strings.Repeat("4", 64), ExpiresAtUnix: 2_000_000_100}
	first, err := BuildDomainBoundAgreementPaymentRequest("owner", "agent:buyer", "tos:testnet",
		"sha256:"+strings.Repeat("a", 64), []byte("0:destination"), obligation)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildDomainBoundAgreementPaymentRequest("owner", "agent:buyer", "tos:testnet",
		"sha256:"+strings.Repeat("b", 64), []byte("0:destination"), obligation)
	if err != nil {
		t.Fatal(err)
	}
	if first.StableActionID == second.StableActionID {
		t.Fatal("different genesis domains produced the same payment identity")
	}
	mutated := first
	mutated.NetworkDomainDigest = second.NetworkDomainDigest
	if err := ValidateAgreementPaymentRequest(mutated); err == nil {
		t.Fatal("network-domain mutation preserved the owner-authorized payment identity")
	}
}

func TestDomainBoundAgreementPaymentCrossLanguageRelayVectors(t *testing.T) {
	networkDomainDigest := "sha256:2bb4cdc2e2e1001bc54e519087598582717217b82cbfd005c0acfe03269f6a69"
	tests := []struct {
		name                     string
		ownerID                  string
		agentID                  string
		agreementBodyDigest      string
		agreementObligationID    string
		obligationInstanceID     string
		payerAgentID             string
		payeeAgentID             string
		amount                   string
		destination              string
		expiresAtUnix            uint64
		wantStableActionID       string
		wantPaymentRequestDigest string
		wantExactRequestDigest   string
	}{
		{
			name: "underlying", ownerID: "owner:client", agentID: "agent:client",
			agreementBodyDigest:   "sha256:" + strings.Repeat("5", 64),
			agreementObligationID: "obligation:underlying-payment",
			obligationInstanceID:  "sha256:" + strings.Repeat("6", 64),
			payerAgentID:          "agent:client", payeeAgentID: "agent:merchant", amount: "25",
			destination: "0:" + strings.Repeat("2", 64), expiresAtUnix: 1_800_000_480,
			wantStableActionID:       "sha256:f951d5db1f4a955b156164b9985a9be3e965e2959ca6dce6db2436147662e0ae",
			wantPaymentRequestDigest: "sha256:bebcfeeaefba55c1a468eab68c01a91904ea62145716cd66dc6ce81473821004",
			wantExactRequestDigest:   "sha256:f218789c7750655634f28dc6607798d0004537aa63528e63b921fb9ea96c1039",
		},
		{
			name: "sponsorship", ownerID: "owner:provider", agentID: "agent:provider",
			agreementBodyDigest:   "sha256:73a957cd7cb5071f151469f859a44bfccabaeb0bd2e9ead1728949b33d642b7b",
			agreementObligationID: "obligation:sponsorship",
			obligationInstanceID:  "sha256:" + strings.Repeat("1", 64),
			payerAgentID:          "agent:provider", payeeAgentID: "agent:client", amount: "50",
			destination: "0:" + strings.Repeat("1", 64), expiresAtUnix: 1_800_000_100,
			wantStableActionID:       "sha256:63376b35343ff6bd7bf2973fe21c906606b1b90aea68571fe94b88a11d5b77f1",
			wantPaymentRequestDigest: "sha256:01a3bfbd898518c5fda6770cb102118a7129c6453ac0900397ad25876c892f8a",
			wantExactRequestDigest:   "sha256:e32961bbde8f8489bbb216de7c5547918927aab67e353f339d51d1b625abc79d",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			amount := AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "tos:testnet",
				AmountAtomic: test.amount, Unit: "nanotos"}
			obligation := SettlementObligation{AgreementBodyDigest: test.agreementBodyDigest,
				AgreementObligationID: test.agreementObligationID, ObligationInstanceID: test.obligationInstanceID,
				Sequence: 1, PayerAgentID: test.payerAgentID, PayeeAgentID: test.payeeAgentID, Amount: amount,
				MaximumAggregateAmount: amount, SettlementAdapterURI: "tos.payment.direct.v1",
				SettlementParametersDigest: "sha256:" + strings.Repeat("3", 64),
				StableActionID:             "sha256:" + strings.Repeat("4", 64), ExpiresAtUnix: test.expiresAtUnix}
			request, err := BuildDomainBoundAgreementPaymentRequest(test.ownerID, test.agentID, "tos:testnet",
				networkDomainDigest, []byte(test.destination), obligation)
			if err != nil {
				t.Fatal(err)
			}
			canonical, _, err := PaymentAuthorizationMaterial(request)
			if err != nil {
				t.Fatal(err)
			}
			paymentDigest, err := AgreementPaymentRequestDigest(request)
			if err != nil {
				t.Fatal(err)
			}
			exactDigest, err := ExactRequestDigest(canonical)
			if err != nil {
				t.Fatal(err)
			}
			if request.SchemaVersion != 3 || request.StableActionID != test.wantStableActionID ||
				paymentDigest != test.wantPaymentRequestDigest || exactDigest != test.wantExactRequestDigest {
				t.Fatalf("cross-language relay payment vector changed: schema=%d stable=%s payment=%s exact=%s",
					request.SchemaVersion, request.StableActionID, paymentDigest, exactDigest)
			}
		})
	}
}
