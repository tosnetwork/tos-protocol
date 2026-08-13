package nativeprotocol

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCheckedInVectorArtifact(t *testing.T) {
	data, err := os.ReadFile("testdata/native_registry_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Version  string `json:"version"`
		Positive struct {
			AgentID                string `json:"agent_id"`
			CapabilityID           string `json:"capability_id"`
			ControllerPolicyDigest string `json:"controller_policy_digest"`
			RegistryActionDigest   string `json:"registry_action_digest"`
			Signature              string `json:"signature_base64url"`
		} `json:"positive"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	_, policy, agentID, capabilityID, action, privateKey := fixture(t)
	policyDigest, _ := ControllerPolicyDigest(policy)
	actionDigest, _ := ActionDigest(action)
	signature, _ := SignAction(privateKey, "controller-1", action)
	if vector.Version != "tos_native_registry_vectors_v1" || vector.Positive.AgentID != agentID || vector.Positive.CapabilityID != capabilityID || vector.Positive.ControllerPolicyDigest != policyDigest || vector.Positive.RegistryActionDigest != actionDigest || vector.Positive.Signature != signature.SignatureBase64 {
		t.Fatalf("checked-in vector does not match implementation: %#v", vector)
	}
}
