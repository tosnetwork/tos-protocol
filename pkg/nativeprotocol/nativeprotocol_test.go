package nativeprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

func fixture(t *testing.T) (NetworkDomain, ControllerPolicy, string, string, RegistryAction, ed25519.PrivateKey) {
	t.Helper()
	network := NetworkDomain{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	policy := ControllerPolicy{Threshold: 1, Controllers: []ControllerKey{{KeyID: "controller-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "recovery"}}}, RecoveryKeyIDs: []string{"controller-1"}, RecoveryTimelock: 86400}
	policyDigest, err := ControllerPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	agentID, err := AgentID(AgentBootstrap{Version: Version, Network: network, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), InitialControllerPolicy: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	capabilityID, err := CapabilityID(CapabilityBootstrap{Version: Version, Network: network, OwnerAgentID: agentID, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		t.Fatal(err)
	}
	actionNonce := make([]byte, 32)
	for i := range actionNonce {
		actionNonce[i] = byte(0x70 + i)
	}
	action := RegistryAction{Version: Version, Kind: ActionRegisterCapability, Network: network, AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, PolicyDigest: policyDigest, PayloadDigest: "sha256:" + strings.Repeat("33", 32), NonceBase64: base64.RawURLEncoding.EncodeToString(actionNonce)}
	return network, policy, agentID, capabilityID, action, privateKey
}

func TestNormativeVectors(t *testing.T) {
	_, policy, agentID, capabilityID, action, privateKey := fixture(t)
	policyDigest, _ := ControllerPolicyDigest(policy)
	actionDigest, err := ActionDigest(action)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(privateKey, "controller-1", action)
	if err != nil {
		t.Fatal(err)
	}
	event := RegistryEvent{Version: Version, Kind: action.Kind, Network: action.Network, ActionDigest: actionDigest, AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: action.CapabilityVersion, Generation: 1, Sequence: 1, FinalizedCheckpoint: 100, TransactionIndex: 2, EventIndex: 1}
	eventDigest, err := EventDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"agent":      "agent_1a45894ebff26b0ab94b5fa2c9d86152963da87e8d84f751bec19b5cebeb75da",
		"capability": "cap_7df2806b0666f81f4c4dfa4d03e7c431845c1e101c793a2db8b0eba58c91fda1",
		"policy":     "sha256:652986b9ba4701c2804fadef2a0ee157d70f81ca337c1ef279cc2804a7d977b5",
		"action":     "sha256:96039a44357f059de13cb9f547b8377d4fe75ee32cdd4c51c18c3320115f3eac",
		"canonical":  "rGRraW5kc3JlZ2lzdGVyX2NhcGFiaWxpdHlnbmV0d29ya6NqbmV0d29ya19pZGt0b3MtdGVzdG5ldHFnZW5lc2lzX2ZpbGVfaGFzaHhHc2hhMjU2OjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjJxZ2VuZXNpc19yb290X2hhc2h4R3NoYTI1NjoxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExZ3ZlcnNpb252dG9zX25hdGl2ZV9yZWdpc3RyeV92MWhhZ2VudF9pZHhGYWdlbnRfMWE0NTg5NGViZmYyNmIwYWI5NGI1ZmEyYzlkODYxNTI5NjNkYTg3ZThkODRmNzUxYmVjMTliNWNlYmViNzVkYWhzZXF1ZW5jZQFqZ2VuZXJhdGlvbgFtY2FwYWJpbGl0eV9pZHhEY2FwXzdkZjI4MDZiMDY2NmY4MWY0YzRkZmE0ZDAzZTdjNDMxODQ1YzFlMTAxYzc5M2EyZGI4YjBlYmE1OGM5MWZkYTFtcG9saWN5X2RpZ2VzdHhHc2hhMjU2OjY1Mjk4NmI5YmE0NzAxYzI4MDRmYWRlZjJhMGVlMTU3ZDcwZjgxY2EzMzdjMWVmMjc5Y2MyODA0YTdkOTc3YjVucGF5bG9hZF9kaWdlc3R4R3NoYTI1NjozMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzb25vbmNlX2Jhc2U2NHVybHgrY0hGeWMzUjFkbmQ0ZVhwN2ZIMS1mNENCZ29PRWhZYUhpSW1LaTR5TmpvOHJjYXBhYmlsaXR5X3ZlcnNpb25lMS4yLjN1cHJldmlvdXNfZXZlbnRfZGlnZXN0YA==",
		"signature":  "_4WC4R4BeUH0BRksKOYxq5LELLF3oAhkhlGeOUwbJjiO43eKd31rzRc6oSz15_EJlIMRKJ5AQedKp7azurgGCQ",
		"event":      "sha256:0ca9ed14a8f7f90bc8f62e35b867480251996ccd7fcd5b57fde2f888214caf7a",
	}
	got := map[string]string{"agent": agentID, "capability": capabilityID, "policy": policyDigest, "action": actionDigest, "canonical": base64.StdEncoding.EncodeToString(canonical), "signature": signature.SignatureBase64, "event": eventDigest}
	for key, value := range got {
		if value != want[key] {
			t.Fatalf("%s=%s want %s", key, value, want[key])
		}
	}
	if err := VerifyAction(privateKey.Public().(ed25519.PublicKey), action, signature); err != nil {
		t.Fatal(err)
	}
}

func TestIdentifiersAreNetworkBoundAndStableAcrossRotation(t *testing.T) {
	network, policy, agentID, _, _, _ := fixture(t)
	policyDigest, _ := ControllerPolicyDigest(policy)
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	bootstrap := AgentBootstrap{Version: Version, Network: network, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), InitialControllerPolicy: policyDigest}
	same, _ := AgentID(bootstrap)
	if same != agentID {
		t.Fatal("Agent ID changed without bootstrap change")
	}
	bootstrap.Network.NetworkID = "tos-mainnet"
	other, _ := AgentID(bootstrap)
	if other == agentID {
		t.Fatal("cross-network Agent ID collision")
	}
	uri, _ := AgentURI(agentID)
	kind, parsed, version, err := ParseURI(uri)
	if err != nil || kind != "agent" || parsed != agentID || version != "" {
		t.Fatalf("parse=%q %q %q err=%v", kind, parsed, version, err)
	}
	lineage, err := CapabilityLineageURI("cap_" + strings.Repeat("1", 64))
	if err != nil {
		t.Fatal(err)
	}
	kind, _, version, err = ParseURI(lineage)
	if err != nil || kind != "capability" || version != "" {
		t.Fatalf("lineage parse kind=%s version=%s err=%v", kind, version, err)
	}
}

func TestRejectsAliasesUnsortedPolicyAndPurposeReplay(t *testing.T) {
	_, policy, agentID, capabilityID, action, privateKey := fixture(t)
	policy.Controllers[0].Purposes = []string{"recovery", "agent_control"}
	if _, err := ControllerPolicyDigest(policy); err == nil {
		t.Fatal("unsorted purposes accepted")
	}
	for _, uri := range []string{"ATOS://agent/" + agentID, "atos://agent/" + strings.ToUpper(agentID), "atos://agent/" + agentID + "/", "atos://capability/" + capabilityID + "/versions/01.2.3", "atos://capability/" + capabilityID + "/versions/1.2.3-01", "atos://capability/" + capabilityID + "/versions/1.2.3+build", "atos://agent/" + agentID + "?x=1"} {
		if _, _, _, err := ParseURI(uri); err == nil {
			t.Fatalf("noncanonical URI accepted: %s", uri)
		}
	}
	signature, _ := SignAction(privateKey, "controller-1", action)
	action.Kind = ActionTransferCapability
	if err := VerifyAction(privateKey.Public().(ed25519.PublicKey), action, signature); ErrorCodeOf(err) != CodePolicyUnauthorized {
		t.Fatalf("cross-purpose signature replay err=%v", err)
	}
}

func TestRegistryOrderingAndFieldSeparation(t *testing.T) {
	_, _, agentID, capabilityID, action, _ := fixture(t)
	action.Sequence = 2
	if _, err := ActionDigest(action); err == nil {
		t.Fatal("missing previous event accepted")
	}
	action.Sequence = 1
	action.PreviousEventDigest = "sha256:" + strings.Repeat("44", 32)
	if _, err := ActionDigest(action); err == nil {
		t.Fatal("first action with predecessor accepted")
	}
	action.PreviousEventDigest = ""
	action.Kind = ActionRegisterAgent
	if _, err := ActionDigest(action); err == nil {
		t.Fatal("Agent action containing Capability fields accepted")
	}
	event := RegistryEvent{Version: Version, Kind: ActionRegisterCapability, Network: action.Network, ActionDigest: "sha256:" + strings.Repeat("55", 32), AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, FinalizedCheckpoint: 0}
	if _, err := EventDigest(event); err == nil {
		t.Fatal("zero-checkpoint event accepted")
	}
	event.FinalizedCheckpoint = 10
	action.Kind = ActionRegisterCapability
	action.CapabilityID = capabilityID
	action.CapabilityVersion = "1.2.3"
	event.ActionDigest, _ = ActionDigest(action)
	if err := ValidateEventForAction(action, event); err != nil {
		t.Fatal(err)
	}
	event.Network.NetworkID = "tos-mainnet"
	if err := ValidateEventForAction(action, event); ErrorCodeOf(err) != CodeCrossDomainReplay {
		t.Fatalf("cross-network event err=%v", err)
	}
}
