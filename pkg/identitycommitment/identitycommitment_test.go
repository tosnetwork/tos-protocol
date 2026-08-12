package identitycommitment

import (
	"testing"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
)

func TestCanonicalDigestsIgnoreMutableAndPrivateProjectionFields(t *testing.T) {
	base := &atostosv1.AgentIdentity{AgentId: "agent", CanonicalUri: "atos://agent", Controllers: []string{"0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, Assurance: "tos_chain_verified"}
	first, err := IdentityDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:5c4865aa2776e74c8067ead00da932c066a6f544b7c2171473c30a4df3aa2242"; first != want {
		t.Fatalf("identity vector = %s, want %s", first, want)
	}
	changed := &atostosv1.AgentIdentity{AgentId: base.AgentId, CanonicalUri: base.CanonicalUri, Controllers: append([]string(nil), base.Controllers...), Assurance: base.Assurance, UpdatedUnixMillis: 123, PublicAttributes: map[string]string{"private": "not committed"}, IdentityRef: &atostosv1.NetworkReference{Network: "other"}}
	second, err := IdentityDigest(changed)
	if err != nil || second != first {
		t.Fatalf("identity projection fields changed digest: first=%s second=%s err=%v", first, second, err)
	}
	binding, err := BindingDigest("principal", "agent")
	if err != nil || binding == "" {
		t.Fatalf("binding digest unavailable: %s %v", binding, err)
	}
	if want := "sha256:03317371cbeed67ef5c0e7b51cae7eea7ca53c151c6145bad11bc39540b1439b"; binding != want {
		t.Fatalf("binding vector = %s, want %s", binding, want)
	}
}
