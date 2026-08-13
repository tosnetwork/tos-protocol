package nativeprotocol

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
)

type negativeVector struct {
	Name          string          `json:"name"`
	Fixture       string          `json:"fixture"`
	Operation     vectorOperation `json:"operation"`
	ExpectedCode  string          `json:"expected_code"`
	ExpectedField string          `json:"expected_field"`
}
type vectorOperation struct {
	Op, Path string
	Value    any
}
type vectorDocument struct {
	Negative []negativeVector `json:"negative"`
}

// TestExecutableNegativeVectors deliberately applies every named normative
// mutation. A vector is not accepted merely because its metadata parses.
func TestExecutableNegativeVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/native_registry_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var document vectorDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	f := fixture(t)
	actionDigest, _ := ActionDigest(f.action)
	event := RegistryEvent{Version: Version, Kind: f.action.Kind, Network: f.network, ActionDigest: actionDigest, AgentID: f.agentID, CapabilityID: f.capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, StateDigest: "sha256:" + strings.Repeat("55", 32)}
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: mustEventDigest(t, event), Reference: ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("66", 32), LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("77", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), EventIndex: 1}, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: 1800000000, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	signature, _ := SignAction(f.privateKey, "controller-1", f.action)
	seen := map[string]bool{}
	for _, vector := range document.Negative {
		var got error
		switch vector.Name {
		case "signature_key_id_substitution":
			var wrapper struct {
				Signature Signature `json:"signature"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"signature": signature}, vector.Operation)
			changed := wrapper.Signature
			got = VerifyAction(f.privateKey.Public().(ed25519.PublicKey), f.action, changed)
		case "duplicate_controller_public_key":
			base := mustJSONMap(t, map[string]any{"policy": f.policy})
			value := vector.Operation.Value.(map[string]any)
			value["public_key_base64url"] = f.policy.Controllers[0].PublicKeyBase64
			delete(value, "public_key_source")
			vector.Operation.Value = value
			var wrapper struct {
				Policy ControllerPolicy `json:"policy"`
			}
			applyVectorMutation(t, &wrapper, base, vector.Operation)
			changed := wrapper.Policy
			got = ValidateControllerPolicy(changed)
		case "duplicate_signature_weight":
			var wrapper struct {
				Signatures []Signature `json:"signatures"`
			}
			operation := vector.Operation
			operation.Value = signature
			applyVectorMutation(t, &wrapper, map[string]any{"signatures": []Signature{signature}}, operation)
			got = VerifyAuthorization(f.action, f.policy, wrapper.Signatures)
		case "agent_event_capability_version":
			base := event
			base.Kind = ActionRegisterAgent
			base.CapabilityID = ""
			base.CapabilityVersion = ""
			var wrapper struct {
				Event RegistryEvent `json:"event"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"event": base}, vector.Operation)
			changed := wrapper.Event
			_, got = EventDigest(changed)
		case "agent_event_capability_garbage":
			base := event
			base.Kind = ActionRegisterAgent
			base.CapabilityID = ""
			base.CapabilityVersion = ""
			var wrapper struct {
				Event RegistryEvent `json:"event"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"event": base}, vector.Operation)
			changed := wrapper.Event
			_, got = EventDigest(changed)
		case "revoke_capability_bad_version":
			base := event
			base.Kind = ActionRevokeCapability
			var wrapper struct {
				Event RegistryEvent `json:"event"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"event": base}, vector.Operation)
			changed := wrapper.Event
			_, got = EventDigest(changed)
		case "missing_transaction_hash":
			var wrapper struct {
				Observation EventObservation `json:"observation"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"observation": observation}, vector.Operation)
			changed := wrapper.Observation
			_, got = ObservationDigest(changed)
		case "zero_finality":
			var wrapper struct {
				Observation EventObservation `json:"observation"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"observation": observation}, vector.Operation)
			changed := wrapper.Observation
			_, got = ObservationDigest(changed)
		case "noncanonical_payload_cbor":
			var wrapper struct {
				Action RegistryAction `json:"action"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"action": f.action}, vector.Operation)
			changed := wrapper.Action
			_, got = ActionDigest(changed)
		case "network_leading_hyphen":
			var wrapper struct {
				Network NetworkDomain `json:"network"`
			}
			applyVectorMutation(t, &wrapper, map[string]any{"network": f.network}, vector.Operation)
			changed := wrapper.Network
			got = changed.Validate()
		default:
			t.Fatalf("normative mutation %q has no executor", vector.Name)
		}
		protocolErr, ok := got.(*ProtocolError)
		if !ok || string(protocolErr.Code) != vector.ExpectedCode || protocolErr.Field != vector.ExpectedField {
			t.Fatalf("%s: got %#v want %s/%s", vector.Name, got, vector.ExpectedCode, vector.ExpectedField)
		}
		seen[vector.Name] = true
	}
	if len(seen) != len(document.Negative) || len(seen) < 10 {
		t.Fatalf("executed %d vectors", len(seen))
	}
}

func mustJSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(value)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func applyVectorMutation(t *testing.T, output any, base map[string]any, operation vectorOperation) {
	t.Helper()
	document := mustJSONMap(t, base)
	parts := strings.Split(strings.TrimPrefix(operation.Path, "/"), "/")
	patched := patchVectorNode(t, document, parts, operation.Op, operation.Value)
	document = patched.(map[string]any)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, output); err != nil {
		t.Fatal(err)
	}
}
func patchVectorNode(t *testing.T, node any, parts []string, operation string, value any) any {
	t.Helper()
	key := strings.ReplaceAll(strings.ReplaceAll(parts[0], "~1", "/"), "~0", "~")
	if len(parts) == 1 {
		if values, ok := node.([]any); ok {
			index, err := strconv.Atoi(key)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "add" {
				values = append(values, nil)
				copy(values[index+1:], values[index:])
				values[index] = value
			} else {
				values[index] = value
			}
			return values
		}
		node.(map[string]any)[key] = value
		return node
	}
	if values, ok := node.([]any); ok {
		index, err := strconv.Atoi(key)
		if err != nil {
			t.Fatal(err)
		}
		values[index] = patchVectorNode(t, values[index], parts[1:], operation, value)
		return values
	}
	object := node.(map[string]any)
	object[key] = patchVectorNode(t, object[key], parts[1:], operation, value)
	return object
}

func mustEventDigest(t *testing.T, event RegistryEvent) string {
	t.Helper()
	digest, err := EventDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}
