package agentpacket

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

type resolver map[string]*nativev1.AgentStateV1

func (r resolver) ResolveAgent(id string) (*nativev1.AgentStateV1, bool, error) {
	value, ok := r[id]
	return value, ok, nil
}

func TestSignedPacketRequiresFinalizedAgentsAndRejectsReplay(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	private := ed25519.NewKeyFromSeed(seed)
	sender, recipient := "agent_"+repeatHex("11"), "agent_"+repeatHex("22")
	state := &nativev1.AgentStateV1{AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: private.Public().(ed25519.PublicKey)}}}}
	packet, err := Sign(Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("33"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("hello")}, private)
	if err != nil {
		t.Fatal(err)
	}
	guard := &ReplayGuard{TTL: time.Hour}
	states := resolver{sender: state, recipient: &nativev1.AgentStateV1{AgentId: recipient}}
	if err := Verify(states, guard, packet, time.Unix(100, 0)); err != nil {
		t.Fatal(err)
	}
	if err := Verify(states, guard, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("replayed packet accepted")
	}
	packet.Payload[0] ^= 1
	if err := Verify(states, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("mutated payload accepted")
	}
}

func TestPacketRejectsUnauthorizedSenderAndMissingRecipient(t *testing.T) {
	first, private, _ := ed25519.GenerateKey(nil)
	sender, recipient := "agent_"+repeatHex("44"), "agent_"+repeatHex("55")
	packet, err := Sign(Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("66"), Sequence: 1, CreatedAtUnix: 100, Payload: []byte("x")}, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(resolver{sender: &nativev1.AgentStateV1{AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: first}}}}}, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("missing recipient accepted")
	}
	other, _, _ := ed25519.GenerateKey(nil)
	packet.SenderPublicKey = other
	if err := Verify(resolver{sender: &nativev1.AgentStateV1{AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: first}}}}, recipient: &nativev1.AgentStateV1{AgentId: recipient}}, &ReplayGuard{}, packet, time.Unix(100, 0)); err == nil {
		t.Fatal("unauthorized sender accepted")
	}
}

func TestJSONWireRoundTripAndStrictParsing(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	packet, err := Sign(Packet{SenderAgentID: "agent_" + repeatHex("77"), RecipientAgentID: "agent_" + repeatHex("88"),
		CapabilityID: "cap_" + repeatHex("99"), Sequence: 2, CreatedAtUnix: 200, Payload: []byte("wire")}, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeJSON(packet)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeJSON(raw)
	if err != nil || string(decoded.Payload) != "wire" || string(decoded.Signature) != string(packet.Signature) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	for _, mutation := range [][]byte{append(raw, []byte("{}")...), append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...)} {
		if _, err := DecodeJSON(mutation); err == nil {
			t.Fatal("non-strict wire accepted")
		}
	}
}

type receiveStub struct{ count int }

func (r *receiveStub) Receive(context.Context, Packet) error { r.count++; return nil }

func TestHTTPHandlerVerifiesBeforeDeliveryAndPostDisablesRedirects(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	sender, recipient := "agent_"+repeatHex("aa"), "agent_"+repeatHex("bb")
	packet, err := Sign(Packet{SenderAgentID: sender, RecipientAgentID: recipient, CapabilityID: "cap_" + repeatHex("cc"), Sequence: 1, CreatedAtUnix: uint64(time.Now().Unix()), Payload: []byte("hello")}, private)
	if err != nil {
		t.Fatal(err)
	}
	receiver := &receiveStub{}
	server := httptest.NewServer(Handler(resolver{sender: &nativev1.AgentStateV1{AgentId: sender, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: private.Public().(ed25519.PublicKey)}}}}, recipient: &nativev1.AgentStateV1{AgentId: recipient}}, &ReplayGuard{}, receiver))
	defer server.Close()
	if err := Post(context.Background(), server.Client(), server.URL, packet); err != nil {
		t.Fatal(err)
	}
	if receiver.count != 1 {
		t.Fatalf("received=%d", receiver.count)
	}
	if err := Post(context.Background(), server.Client(), server.URL, packet); err == nil {
		t.Fatal("replay was delivered")
	}
	redirect := httptest.NewServer(http.RedirectHandler(server.URL, http.StatusTemporaryRedirect))
	defer redirect.Close()
	if err := Post(context.Background(), redirect.Client(), redirect.URL, packet); err == nil {
		t.Fatal("redirect accepted")
	}
}

func repeatHex(value string) string {
	result := ""
	for i := 0; i < 32; i++ {
		result += value
	}
	return result
}
