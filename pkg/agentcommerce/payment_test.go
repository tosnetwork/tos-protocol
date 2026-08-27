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
			wantStableActionID:       "sha256:81ee1e20e2dc9135975343ca3433116e73477f3edd9c876d49941c54451ad0fa",
			wantPaymentRequestDigest: "sha256:bc5ae55dcbc7b3f45ac4014b6973c8ca55879464b260d1157b167a8a906d2c34",
			wantExactRequestDigest:   "sha256:c16ad477c999b08ea3fefece7ec62fd4f8bee1805a1fc76f45a45623c3a6a294",
		},
		{
			name: "sponsorship", ownerID: "owner:provider", agentID: "agent:provider",
			agreementBodyDigest:   "sha256:73a957cd7cb5071f151469f859a44bfccabaeb0bd2e9ead1728949b33d642b7b",
			agreementObligationID: "obligation:sponsorship",
			obligationInstanceID:  "sha256:" + strings.Repeat("1", 64),
			payerAgentID:          "agent:provider", payeeAgentID: "agent:client", amount: "50",
			destination: "0:" + strings.Repeat("1", 64), expiresAtUnix: 1_800_000_100,
			wantStableActionID:       "sha256:2e662b496bdad77a6816a182bad86a70255fa5c1594ba53e39ff45f22c2feb42",
			wantPaymentRequestDigest: "sha256:79b6567e848f66dfb46283ac7c5651ba74a4070e97027112ffdfdc20fd17f5ea",
			wantExactRequestDigest:   "sha256:afeb5b08ca097a4ffedefab91d8c649c9355fe16c9d3f66dda4d150be93584aa",
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
