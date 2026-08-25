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
