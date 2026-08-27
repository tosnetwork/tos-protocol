package agentcommerce

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func fixtureConditionalTemplate(t *testing.T) ConditionalSettlementTemplateV1 {
	t.Helper()
	digest := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	profile := ProfileRefV1{ProfileURI: "tos.test.adapter.v1", ProfileVersion: 1, ProfileDigest: digest("1")}
	asset := AssetIdentityV1{AssetNamespace: "tos", AssetIdentifier: "asset:test", Unit: "atomic"}
	destination := PayoutDestinationV1{SchemaVersion: 1, SettlementAdapterProfile: profile,
		BeneficiarySubject: "agent:beneficiary", Asset: asset, NetworkOrSystemDigest: digest("2"),
		DestinationEncoding: "bytes", DestinationBytes: []byte("destination")}
	destinationDigest, err := PayoutDestinationDigestV1(destination)
	if err != nil {
		t.Fatal(err)
	}
	parametersBytes, err := codec.Marshal(map[string]interface{}{"network": "test"})
	if err != nil {
		t.Fatal(err)
	}
	parameters := ProfileQualifiedSettlementParametersV1{SchemaVersion: 1, SettlementAdapterProfile: profile,
		PayoutDestinationDigest: destinationDigest, AdapterParameters: parametersBytes}
	parametersDigest, err := SettlementParametersDigestV1(parameters)
	if err != nil {
		t.Fatal(err)
	}
	return ConditionalSettlementTemplateV1{TemplateID: "template:1", AgreementObligationID: "obligation:payout",
		ConditionProfile: profile, AuthorizedDecisionProfile: profile, PayerAgentID: "agent:guarantor",
		PayeeAgentID: "agent:beneficiary", Asset: asset,
		MaximumPerInstance:     AtomicAmountV1{Asset: asset, AmountAtomic: "100"},
		MaximumAggregateAmount: AtomicAmountV1{Asset: asset, AmountAtomic: "1000"}, MaximumInstances: 10,
		FirstSequence: 1, SettlementAdapterProfile: profile, SettlementParameters: parameters,
		SettlementParametersDigest: parametersDigest,
		PayoutDestinationBinding: PayoutDestinationBindingV1{Mode: "agreement_fixed",
			DestinationAuthorizationPredicateID: "predicate:beneficiary", PayoutDestination: destination},
		MaterializationDomain: "tos.test.materialize.v1", CancellationPolicyDigest: digest("3"), DisputePolicyDigest: digest("4")}
}

func TestConditionalSettlementTemplateRoundTrip(t *testing.T) {
	template := fixtureConditionalTemplate(t)
	if err := ValidateConditionalSettlementTemplateV1(template); err != nil {
		t.Fatal(err)
	}
	canonical, err := codec.Marshal(template)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeConditionalSettlementTemplateV1(canonical)
	if err != nil || decoded.TemplateID != template.TemplateID {
		t.Fatalf("round trip failed: %+v %v", decoded, err)
	}
	template.SettlementParameters.PayoutDestinationDigest = "sha256:" + strings.Repeat("f", 64)
	if ValidateConditionalSettlementTemplateV1(template) == nil {
		t.Fatal("accepted substituted payout destination")
	}
}
