package agentcommerce

import (
	"strings"
	"testing"
)

func TestIntentApplicationIsCanonicalAndNonAuthorizing(t *testing.T) {
	application := IntentApplication{SchemaVersion: 1, IntentDigest: "sha256:" + strings.Repeat("1", 64),
		IntentIssuerAgentID: "agent:buyer", ApplicantAgentID: "agent:provider", Message: "I can complete the bounded request.",
		CapabilityHints:    []CapabilityHint{{Relation: "available", CapabilityNamespace: "tos.skill", CapabilityIdentifier: "review"}},
		SettlementOffers:   []SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}},
		ProposedAmount:     &AgreementAmount{AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountAtomic: "50", Unit: "nano"},
		PaymentDestination: []byte("tos1provider"), ExpiresAtUnix: 2_000_000_000}
	canonical, err := CanonicalIntentApplication(application)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeIntentApplication(canonical)
	if err != nil || decoded.ApplicantAgentID != application.ApplicantAgentID {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	decoded.IntentDigest = "sha256:" + strings.Repeat("2", 64)
	if changed, err := CanonicalIntentApplication(decoded); err != nil || string(changed) == string(canonical) {
		t.Fatal("changed Intent reference reused canonical application bytes")
	}
}
