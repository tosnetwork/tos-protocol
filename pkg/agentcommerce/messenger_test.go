package agentcommerce

import "testing"

func TestMessengerEffectBindsActualOutboundBytes(t *testing.T) {
	request := MessengerEffectRequestV1{SchemaVersion: 1, RecipientAgentIDs: []string{"agent_b"},
		EventKind: "text", ContentType: "text/plain", Payload: []byte("offer")}
	canonical, err := CanonicalMessengerEffectRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeMessengerEffectRequest(canonical)
	if err != nil || string(decoded.Payload) != "offer" {
		t.Fatalf("decode: %+v %v", decoded, err)
	}
	request.Payload = []byte("different offer")
	other, _ := CanonicalMessengerEffectRequest(request)
	first, _ := ExactRequestDigest(canonical)
	second, _ := ExactRequestDigest(other)
	if first == second {
		t.Fatal("outbound payload substitution did not change exact request digest")
	}
}
