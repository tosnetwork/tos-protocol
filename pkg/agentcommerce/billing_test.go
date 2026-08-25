package agentcommerce

import (
	"strings"
	"testing"
	"time"
)

func TestFinitePeriodicBillingAndPartialPayment(t *testing.T) {
	now := uint64(2_000_000_000)
	amount := AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "10", Unit: "total"}
	obligation := AgreementObligation{ObligationID: "payment:periodic", Kind: "payment", ObligorAgentID: "agent:buyer",
		BeneficiaryAgentID: "agent:provider", SubjectContentType: "text/plain", Subject: []byte("three bounded periods"), Amount: &amount,
		ConfidentialityPolicy: "participants", CancellationPolicy: "future-only", DisputePolicy: "manual-v1",
		SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("network=tos:testnet"),
		AuthorizationPredicateIDs: []string{"predicate:buyer"}, BillingTerms: &BillingTerms{BillingKind: "periodic", FirstSequence: 1,
			RecurrenceStartUnix: now, RecurrenceEndUnix: now + 400, RecurrenceCount: 3, RecurrenceIntervalSecs: 100,
			MaximumAggregateAmount:   AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "30", Unit: "total"},
			CancellationCutoffPolicy: "before-period"}}
	instances, err := MaterializeSettlementObligations("owner:test", "agent:provider", "sha256:"+strings.Repeat("1", 64),
		obligation.ObligationID, "sha256:"+strings.Repeat("2", 64), obligation)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 3 || instances[0].PredecessorInstanceID != "" || instances[1].PredecessorInstanceID != instances[0].ObligationInstanceID ||
		instances[2].Sequence != 3 || instances[0].StableActionID == instances[1].StableActionID {
		t.Fatalf("invalid materialization: %+v", instances)
	}
	state, err := NewSettlementState(instances[0])
	if err != nil {
		t.Fatal(err)
	}
	half := AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "4", Unit: "total"}
	state, err = ApplyPayment(state, instances[0], "sha256:"+strings.Repeat("3", 64), half, time.Unix(int64(now+1), 0))
	if err != nil || state.State != SettlementPartiallyPaid || state.OutstandingAmount.AmountAtomic != "6" {
		t.Fatalf("partial payment = %+v, %v", state, err)
	}
	final := AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "6", Unit: "total"}
	state, err = ApplyPayment(state, instances[0], "sha256:"+strings.Repeat("4", 64), final, time.Unix(int64(now+2), 0))
	if err != nil || state.State != SettlementPaid || state.OutstandingAmount.AmountAtomic != "0" {
		t.Fatalf("final payment = %+v, %v", state, err)
	}
	if _, err := ApplyPayment(state, instances[0], "sha256:"+strings.Repeat("5", 64), final, time.Unix(int64(now+3), 0)); err == nil {
		t.Fatal("terminal paid obligation accepted another transfer")
	}
}

func TestPeriodicBillingCannotExceedAggregateCap(t *testing.T) {
	now := uint64(2_000_000_000)
	amount := AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "10", Unit: "total"}
	obligation := AgreementObligation{ObligationID: "payment:periodic", Kind: "payment", ObligorAgentID: "agent:buyer", BeneficiaryAgentID: "agent:provider",
		SubjectContentType: "text/plain", Subject: []byte("bounded"), Amount: &amount, ConfidentialityPolicy: "participants",
		CancellationPolicy: "future-only", DisputePolicy: "manual-v1", SettlementAdapterURI: "tos.payment.direct.v1",
		SettlementParameters: []byte("network=tos:testnet"), AuthorizationPredicateIDs: []string{"predicate:buyer"},
		BillingTerms: &BillingTerms{BillingKind: "periodic", FirstSequence: 1, RecurrenceStartUnix: now, RecurrenceEndUnix: now + 400,
			RecurrenceCount: 3, RecurrenceIntervalSecs: 100, MaximumAggregateAmount: AgreementAmount{AssetNamespace: "tos.asset",
				AssetIdentifier: "native", AmountAtomic: "29", Unit: "total"}, CancellationCutoffPolicy: "before-period"}}
	if _, err := MaterializeSettlementObligations("owner:test", "agent:provider", "sha256:"+strings.Repeat("1", 64),
		obligation.ObligationID, "sha256:"+strings.Repeat("2", 64), obligation); err == nil {
		t.Fatal("periodic billing exceeded aggregate cap")
	}
}

func TestOverdueRequiresExactDeadlineEvidenceAndPreservesBalance(t *testing.T) {
	now := uint64(2_000_000_000)
	obligation := SettlementObligation{AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64), AgreementObligationID: "payment",
		ObligationInstanceID: "sha256:" + strings.Repeat("2", 64), Sequence: 1, PayerAgentID: "agent:buyer", PayeeAgentID: "agent:provider",
		Amount:    AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "10", Unit: "nano"},
		DueAtUnix: now, ExpiresAtUnix: now + 100, MaximumAggregateAmount: AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "10", Unit: "nano"},
		SettlementAdapterURI: "tos.payment.direct.v1", SettlementParametersDigest: "sha256:" + strings.Repeat("3", 64),
		StableActionID: "sha256:" + strings.Repeat("4", 64)}
	state, err := NewSettlementState(obligation)
	if err != nil {
		t.Fatal(err)
	}
	evidence := "sha256:" + strings.Repeat("5", 64)
	if _, err := ResolveSettlementState(state, obligation, SettlementOverdue, evidence, time.Unix(int64(now-1), 0)); err == nil {
		t.Fatal("obligation became overdue before its deadline")
	}
	state, err = ResolveSettlementState(state, obligation, SettlementOverdue, evidence, time.Unix(int64(now), 0))
	if err != nil || state.State != SettlementOverdue || state.OutstandingAmount.AmountAtomic != "10" {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if replay, err := ResolveSettlementState(state, obligation, SettlementOverdue, evidence, time.Unix(int64(now+1), 0)); err != nil || replay.StateRevision != state.StateRevision {
		t.Fatalf("exact replay=%+v err=%v", replay, err)
	}
}

func TestExternalDecimalBillingUsesExactArithmetic(t *testing.T) {
	now := uint64(2_000_000_000)
	amount := AgreementAmount{AssetNamespace: "iso4217", AssetIdentifier: "USD", AmountDecimal: "0.125", Unit: "USD"}
	obligation := AgreementObligation{ObligationID: "payment:decimal", Kind: "payment", ObligorAgentID: "agent:buyer",
		BeneficiaryAgentID: "agent:provider", SubjectContentType: "text/plain", Subject: []byte("external payment"), Amount: &amount,
		ConfidentialityPolicy: "participants", CancellationPolicy: "future-only", DisputePolicy: "manual-v1",
		SettlementAdapterURI: "external.payment.v1", SettlementParameters: []byte("processor=test"),
		AuthorizationPredicateIDs: []string{"predicate:buyer"}, BillingTerms: &BillingTerms{BillingKind: "periodic", FirstSequence: 1,
			RecurrenceStartUnix: now, RecurrenceEndUnix: now + 100, RecurrenceCount: 2, RecurrenceIntervalSecs: 10,
			MaximumAggregateAmount:   AgreementAmount{AssetNamespace: "iso4217", AssetIdentifier: "USD", AmountDecimal: "0.25", Unit: "USD"},
			CancellationCutoffPolicy: "before-period"}}
	instances, err := MaterializeSettlementObligations("owner:test", "agent:provider", "sha256:"+strings.Repeat("1", 64),
		obligation.ObligationID, "sha256:"+strings.Repeat("2", 64), obligation)
	if err != nil || len(instances) != 2 {
		t.Fatalf("decimal materialization: instances=%+v err=%v", instances, err)
	}
	state, err := NewSettlementState(instances[0])
	if err != nil {
		t.Fatal(err)
	}
	paid := AgreementAmount{AssetNamespace: "iso4217", AssetIdentifier: "USD", AmountDecimal: "0.005", Unit: "USD"}
	state, err = ApplyPayment(state, instances[0], "sha256:"+strings.Repeat("3", 64), paid, time.Unix(int64(now+1), 0))
	if err != nil || state.PaidToDate.AmountDecimal != "0.005" || state.OutstandingAmount.AmountDecimal != "0.12" {
		t.Fatalf("exact decimal payment = %+v, %v", state, err)
	}
}
