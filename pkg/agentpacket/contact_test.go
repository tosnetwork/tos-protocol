package agentpacket

import (
	"crypto/ed25519"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

func TestContactCardIsFinalizedAndTimeBound(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	agent := "agent_" + repeatHex("ab")
	network := &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}
	now := time.Unix(1000, 0)
	card, err := SignContactAt(ContactCard{AgentID: agent, Network: network, Endpoint: "https://agent.example/packet", Capabilities: []string{"cap_" + repeatHex("cd")}, ExpiresAtUnix: 1500}, private, now)
	if err != nil {
		t.Fatal(err)
	}
	state := &nativev1.AgentStateV1{AgentId: agent, Policy: &nativev1.ControllerPolicyV1{Controllers: []*nativev1.ControllerV1{{Ed25519PublicKey: private.Public().(ed25519.PublicKey)}}}}
	if err := VerifyContact(resolver{agent: state}, card, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyContactForNetwork(resolver{agent: state}, &nativev1.NetworkDomain{NetworkId: "other", GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}, card, now); err == nil {
		t.Fatal("cross-network Contact Card accepted")
	}
	if err := VerifyContact(resolver{agent: state}, card, time.Unix(1500, 0)); err == nil {
		t.Fatal("expired Contact Card accepted")
	}
	card.Endpoint = "http://public.example/packet"
	if err := VerifyContact(resolver{agent: state}, card, now); err == nil {
		t.Fatal("plaintext public endpoint accepted")
	}
}

func TestContactCardJSONRoundTripIsStrict(t *testing.T) {
	private := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	card, err := SignContactAt(ContactCard{AgentID: "agent_" + repeatHex("ef"), Network: &nativev1.NetworkDomain{NetworkId: "test", GenesisRootHash: "sha256:" + repeatHex("01"), GenesisFileHash: "sha256:" + repeatHex("02")}, Endpoint: "https://agent.example", ExpiresAtUnix: 1500}, private, time.Unix(1000, 0))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeContactJSON(card)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeContactJSON(raw)
	if err != nil || decoded.AgentID != card.AgentID || string(decoded.Signature) != string(card.Signature) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	if _, err := DecodeContactJSON(append(raw, []byte("{}")...)); err == nil {
		t.Fatal("trailing Contact Card JSON accepted")
	}
}
