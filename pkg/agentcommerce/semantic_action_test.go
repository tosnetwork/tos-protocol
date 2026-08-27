package agentcommerce

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestAgreementProposeFrozenVector(t *testing.T) {
	values := map[string]SemanticValue{
		"owner_id":              ID("owner:test"),
		"agent_id":              ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("11", 32)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("22", 32)),
	}
	wantPreimage := "544f532d53414900000100010028746f732e73656d616e7469632d616374696f6e2e61677265656d656e742e70726f706f73652e7631001161677265656d656e742e70726f706f7365000400086f776e65725f69640000000a6f776e65723a7465737400086167656e745f69640000000a6167656e743a74657374001561677265656d656e745f626f64795f6469676573740000002011111111111111111111111111111111111111111111111111111111111111110014726563697069656e745f7365745f646967657374000000202222222222222222222222222222222222222222222222222222222222222222"
	identity, preimage, err := DeriveStableActionID("agreement.propose", values)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(preimage); got != wantPreimage {
		t.Fatalf("preimage = %s", got)
	}
	if want := "sha256:4e98f9968e35e2493b666370342471a3e80336a23d61f57b6f5b15d93d230b3c"; identity != want {
		t.Fatalf("identity = %s, want %s", identity, want)
	}
	values["recipient_set_digest"] = Digest32("sha256:" + strings.Repeat("33", 32))
	identity, _, err = DeriveStableActionID("agreement.propose", values)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:c7dac213b5297bf30b08422b3c59887c953a54c06c71919813e76fdfb0444c98"; identity != want {
		t.Fatalf("mutated identity = %s, want %s", identity, want)
	}
}

func TestRegistryRejectsMutationAndInvalidFields(t *testing.T) {
	base := map[string]SemanticValue{
		"owner_id":              ID("owner:test"),
		"agent_id":              ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("11", 32)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("22", 32)),
	}
	first, _, err := DeriveStableActionID("agreement.propose", base)
	if err != nil {
		t.Fatal(err)
	}
	mutated := make(map[string]SemanticValue, len(base))
	for name, value := range base {
		mutated[name] = value
	}
	mutated["owner_id"] = ID("owner:other")
	second, _, err := DeriveStableActionID("agreement.propose", mutated)
	if err != nil || first == second {
		t.Fatalf("semantic mutation did not change identity: %q %v", second, err)
	}
	mutated["extra"] = ID("forbidden")
	if _, _, err := DeriveStableActionID("agreement.propose", mutated); err == nil {
		t.Fatal("extra field was accepted")
	}
	delete(mutated, "extra")
	delete(mutated, "recipient_set_digest")
	if _, _, err := DeriveStableActionID("agreement.propose", mutated); err == nil {
		t.Fatal("missing field was accepted")
	}
	if _, _, err := DeriveStableActionID("unknown.kind", base); err == nil {
		t.Fatal("unknown action kind was accepted")
	}
}

func TestAtomicAmountCanonicalization(t *testing.T) {
	base := map[string]SemanticValue{
		"owner_id":               ID("owner:test"),
		"agent_id":               ID("agent:test"),
		"agreement_body_digest":  Digest32("sha256:" + strings.Repeat("11", 32)),
		"obligation_instance_id": Digest32("sha256:" + strings.Repeat("12", 32)),
		"payer_id":               ID("agent:payer"),
		"payee_id":               ID("agent:payee"),
		"network_id":             ID("tos:test"),
		"asset_digest":           Digest32("sha256:" + strings.Repeat("13", 32)),
		"amount_atomic":          ID("10"),
		"destination_digest":     Digest32("sha256:" + strings.Repeat("14", 32)),
	}
	if _, _, err := DeriveStableActionID("payment.direct", base); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "00", "01", "-1", "1.0"} {
		base["amount_atomic"] = ID(bad)
		if _, _, err := DeriveStableActionID("payment.direct", base); err == nil {
			t.Fatalf("non-canonical amount %q was accepted", bad)
		}
	}
}

func TestExactRequestDigestBindsLengthAndBytes(t *testing.T) {
	first, err := ExactRequestDigest([]byte("ab"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExactRequestDigest([]byte("a\x00b"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second || !canonicalDigestPattern.MatchString(first) {
		t.Fatalf("request digests are invalid: %q %q", first, second)
	}
	if _, err := ExactRequestDigest(nil); err == nil {
		t.Fatal("empty action request was accepted")
	}
}

func TestRegistryContainsEveryReleasedKind(t *testing.T) {
	registry := SemanticActionRegistry()
	if len(registry) != 42 {
		t.Fatalf("registry has %d entries, want 42", len(registry))
	}
	for kind, candidate := range registry {
		if candidate.ActionKind != kind || candidate.DomainTag != "tos.semantic-action."+kind+".v1" || len(candidate.Fields) == 0 {
			t.Fatalf("invalid registry entry: %+v", candidate)
		}
	}
}

func TestSemanticFieldsRoundTripAtSink(t *testing.T) {
	values := map[string]SemanticValue{
		"owner_id": ID("owner_1"), "agent_id": ID("agent_1"), "carrier_id": ID("carrier_1"),
		"intent_object_id": ID("intent_1"), "revision": U64(7),
		"operation_digest": Digest32("sha256:" + strings.Repeat("a", 64)),
	}
	wire, err := ExportSemanticFields("publication.publish", values)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ImportSemanticFields("publication.publish", wire)
	if err != nil {
		t.Fatal(err)
	}
	want, _, _ := DeriveStableActionID("publication.publish", values)
	got, _, _ := DeriveStableActionID("publication.publish", decoded)
	if got != want {
		t.Fatalf("sink derived %s, want %s", got, want)
	}
	wire[0], wire[1] = wire[1], wire[0]
	if _, err := ImportSemanticFields("publication.publish", wire); err == nil {
		t.Fatal("accepted reordered semantic fields")
	}
}
