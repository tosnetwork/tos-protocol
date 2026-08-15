package nativecore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/proto"
)

type frozenVectorSet struct {
	Schema                 string                       `json:"schema"`
	Protocol               string                       `json:"protocol"`
	ContractCodeHash       string                       `json:"contract_code_hash"`
	ContractCodeBOCBase64  string                       `json:"contract_code_boc_base64"`
	Network                frozenNetwork                `json:"network"`
	AgentRegistration      frozenAgentRegistration      `json:"agent_registration"`
	CapabilityRegistration frozenCapabilityRegistration `json:"capability_registration"`
	NegativeMutations      []frozenNegativeMutation     `json:"negative_mutations"`
}

type frozenNetwork struct {
	NetworkID       string `json:"network_id"`
	GenesisRootHash string `json:"genesis_root_hash"`
	GenesisFileHash string `json:"genesis_file_hash"`
}

type frozenController struct {
	PublicKeyHex string `json:"public_key_hex"`
	Weight       uint32 `json:"weight"`
	PurposeMask  uint32 `json:"purpose_mask"`
	Recovery     bool   `json:"recovery"`
}

type frozenPolicy struct {
	Threshold               uint32             `json:"threshold"`
	RecoveryThreshold       uint32             `json:"recovery_threshold"`
	RecoveryTimelockSeconds uint64             `json:"recovery_timelock_seconds"`
	Controllers             []frozenController `json:"controllers"`
}

type frozenExpected struct {
	ObjectID        string `json:"object_id"`
	ContractAddress string `json:"contract_address"`
	ActionHash      string `json:"action_hash"`
	ActionBOCBase64 string `json:"action_boc_base64"`
	SignatureHex    string `json:"signature_hex"`
}

type frozenAgentRegistration struct {
	PrivateSeedHex string         `json:"private_seed_hex"`
	ObjectNonceHex string         `json:"object_nonce_hex"`
	ActionNonceHex string         `json:"action_nonce_hex"`
	Policy         frozenPolicy   `json:"policy"`
	Expected       frozenExpected `json:"expected"`
}

type frozenCapabilityRegistration struct {
	OwnerAgentID   string         `json:"owner_agent_id"`
	ObjectNonceHex string         `json:"object_nonce_hex"`
	ActionNonceHex string         `json:"action_nonce_hex"`
	Version        string         `json:"version"`
	ManifestDigest string         `json:"manifest_digest"`
	Expected       frozenExpected `json:"expected"`
}

type frozenNegativeMutation struct {
	Registration string    `json:"registration"`
	Mutation     string    `json:"mutation"`
	ExpectedCode ErrorCode `json:"expected_code"`
}

func TestFrozenRegistrationVectors(t *testing.T) {
	vectors := loadFrozenVectors(t)
	network := vectorNetwork(vectors.Network)
	policy, key := vectorPolicy(t, vectors.AgentRegistration)

	agent := vectorAgentAction(t, vectors, network, policy)
	assertFrozenAction(t, "Agent", agent, vectors.AgentRegistration.Expected)
	assertFrozenLocation(t, vectors, network, vectors.AgentRegistration.Expected)
	assertFrozenSignature(t, key, policy.Controllers[0].KeyId, agent, vectors.AgentRegistration.Expected.SignatureHex)

	capability := vectorCapabilityAction(t, vectors, network)
	assertFrozenAction(t, "Capability", capability, vectors.CapabilityRegistration.Expected)
	assertFrozenLocation(t, vectors, network, vectors.CapabilityRegistration.Expected)
	assertFrozenSignature(t, key, policy.Controllers[0].KeyId, capability, vectors.CapabilityRegistration.Expected.SignatureHex)
}

func assertFrozenLocation(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, expected frozenExpected) {
	t.Helper()
	locator, err := NewLocator(network, 0, vectors.ContractCodeBOCBase64, vectors.ContractCodeHash)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := locator.Locate(expected.ObjectID)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Address != expected.ContractAddress {
		t.Fatalf("contract address = %q", identity.Address)
	}
}

func TestFrozenNegativeRegistrationMutations(t *testing.T) {
	vectors := loadFrozenVectors(t)
	network := vectorNetwork(vectors.Network)
	policy, _ := vectorPolicy(t, vectors.AgentRegistration)
	agent := vectorAgentProto(t, vectors, network, policy)
	capability := vectorCapabilityProto(t, vectors, network)

	for _, mutation := range vectors.NegativeMutations {
		mutation := mutation
		t.Run(mutation.Registration+"/"+mutation.Mutation, func(t *testing.T) {
			var action *nativev1.NativeActionV1
			switch mutation.Registration {
			case "agent":
				action = proto.Clone(agent).(*nativev1.NativeActionV1)
			case "capability":
				action = proto.Clone(capability).(*nativev1.NativeActionV1)
			default:
				t.Fatalf("unknown registration %q", mutation.Registration)
			}
			applyFrozenMutation(t, action, mutation.Mutation)
			_, err := BuildAction(action)
			if err == nil {
				t.Fatal("negative mutation was accepted")
			}
			code, ok := ErrorCodeOf(err)
			if !ok || code != mutation.ExpectedCode {
				t.Fatalf("error = %v, code = %v, want %v", err, code, mutation.ExpectedCode)
			}
		})
	}
}

func loadFrozenVectors(t *testing.T) frozenVectorSet {
	t.Helper()
	raw, err := os.ReadFile("testdata/native_registry_v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors frozenVectorSet
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Protocol != Protocol {
		t.Fatalf("protocol = %q", vectors.Protocol)
	}
	return vectors
}

func vectorNetwork(network frozenNetwork) *nativev1.NetworkDomain {
	return &nativev1.NetworkDomain{NetworkId: network.NetworkID, GenesisRootHash: network.GenesisRootHash, GenesisFileHash: network.GenesisFileHash}
}

func vectorPolicy(t *testing.T, registration frozenAgentRegistration) (*nativev1.ControllerPolicyV1, ed25519.PrivateKey) {
	t.Helper()
	seed := mustVectorHex(t, registration.PrivateSeedHex)
	key := ed25519.NewKeyFromSeed(seed)
	policy := &nativev1.ControllerPolicyV1{Threshold: registration.Policy.Threshold, RecoveryThreshold: registration.Policy.RecoveryThreshold,
		RecoveryTimelockSeconds: registration.Policy.RecoveryTimelockSeconds}
	for _, controller := range registration.Policy.Controllers {
		publicKey := mustVectorHex(t, controller.PublicKeyHex)
		policy.Controllers = append(policy.Controllers, &nativev1.ControllerV1{KeyId: "ed25519:" + controller.PublicKeyHex,
			Ed25519PublicKey: publicKey, Weight: controller.Weight, PurposeMask: controller.PurposeMask, Recovery: controller.Recovery})
	}
	if len(policy.Controllers) != 1 || !strings.EqualFold(hex.EncodeToString(key.Public().(ed25519.PublicKey)), registration.Policy.Controllers[0].PublicKeyHex) {
		t.Fatal("frozen private seed does not match controller")
	}
	return policy, key
}

func vectorAgentProto(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, policy *nativev1.ControllerPolicyV1) *nativev1.NativeActionV1 {
	t.Helper()
	objectNonce := mustVectorHex(t, vectors.AgentRegistration.ObjectNonceHex)
	id, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	if id != vectors.AgentRegistration.Expected.ObjectID {
		t.Fatalf("Agent object ID = %q", id)
	}
	return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: vectors.ContractCodeHash, Generation: 1, Sequence: 1,
		Nonce:   mustVectorHex(t, vectors.AgentRegistration.ActionNonceHex),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
}

func vectorCapabilityProto(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain) *nativev1.NativeActionV1 {
	t.Helper()
	registration := vectors.CapabilityRegistration
	objectNonce := mustVectorHex(t, registration.ObjectNonceHex)
	version := &nativev1.CapabilityVersionV1{Version: registration.Version, ManifestDigest: registration.ManifestDigest}
	id, err := DeriveCapabilityID(network, objectNonce, registration.OwnerAgentID, version)
	if err != nil {
		t.Fatal(err)
	}
	if id != registration.Expected.ObjectID {
		t.Fatalf("Capability object ID = %q", id)
	}
	return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: vectors.ContractCodeHash, Generation: 1, Sequence: 1,
		Nonce: mustVectorHex(t, registration.ActionNonceHex),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: objectNonce, OwnerAgentId: registration.OwnerAgentID, InitialVersion: version}}}
}

func vectorAgentAction(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain, policy *nativev1.ControllerPolicyV1) BuiltAction {
	t.Helper()
	built, err := BuildAction(vectorAgentProto(t, vectors, network, policy))
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func vectorCapabilityAction(t *testing.T, vectors frozenVectorSet, network *nativev1.NetworkDomain) BuiltAction {
	t.Helper()
	built, err := BuildAction(vectorCapabilityProto(t, vectors, network))
	if err != nil {
		t.Fatal(err)
	}
	return built
}

func assertFrozenAction(t *testing.T, name string, built BuiltAction, expected frozenExpected) {
	t.Helper()
	prefix := map[uint8]string{1: "agent_", 2: "cap_"}[built.TargetKind]
	if !strings.HasPrefix(expected.ObjectID, prefix) {
		t.Fatalf("%s object ID = %q", name, expected.ObjectID)
	}
	if built.HashString != expected.ActionHash {
		t.Fatalf("%s action hash = %q", name, built.HashString)
	}
	if boc := base64.StdEncoding.EncodeToString(built.Cell.ToBOC()); boc != expected.ActionBOCBase64 {
		t.Fatalf("%s action BOC = %q", name, boc)
	}
}

func assertFrozenSignature(t *testing.T, key ed25519.PrivateKey, keyID string, built BuiltAction, expected string) {
	t.Helper()
	signature, err := SignAction(key, keyID, built)
	if err != nil {
		t.Fatal(err)
	}
	actual := hex.EncodeToString(signature.Ed25519Signature)
	if actual != expected {
		t.Fatalf("signature = %q", actual)
	}
}

func applyFrozenMutation(t *testing.T, action *nativev1.NativeActionV1, mutation string) {
	t.Helper()
	switch mutation {
	case "wrong_protocol":
		action.Protocol = "tos_service_v0"
	case "empty_network_id":
		action.Network.NetworkId = ""
	case "zero_genesis_root":
		action.Network.GenesisRootHash = "sha256:" + strings.Repeat("00", 32)
	case "wrong_contract_hash":
		action.TargetContractCodeHash = "sha256:" + strings.Repeat("44", 32)
	case "zero_action_nonce":
		action.Nonce = make([]byte, 32)
	case "zero_target_id":
		prefix := "agent_"
		if action.GetRegisterCapability() != nil {
			prefix = "cap_"
		}
		action.TargetObjectId = prefix + strings.Repeat("00", 32)
	case "zero_object_nonce":
		if registration := action.GetRegisterAgent(); registration != nil {
			registration.ObjectNonce = make([]byte, 32)
		} else {
			action.GetRegisterCapability().ObjectNonce = make([]byte, 32)
		}
	case "unattainable_policy":
		action.GetRegisterAgent().InitialPolicy.Threshold = 2
	case "caller_selected_id":
		prefix := "agent_"
		if action.GetRegisterCapability() != nil {
			prefix = "cap_"
		}
		action.TargetObjectId = prefix + strings.Repeat("33", 32)
	case "generation_zero":
		action.Generation = 0
	case "registration_generation_two":
		action.Generation = 2
	case "wrong_owner_kind":
		action.GetRegisterCapability().OwnerAgentId = "cap_" + strings.Repeat("44", 32)
	case "revoked_initial_version":
		action.GetRegisterCapability().InitialVersion.Revoked = true
	case "version_too_long":
		action.GetRegisterCapability().InitialVersion.Version = strings.Repeat("v", 129)
	case "version_non_printable":
		action.GetRegisterCapability().InitialVersion.Version = "1.0.0\n"
	case "registration_sequence_two":
		action.Sequence = 2
		action.PredecessorTvmStateHash = "tvm-cell-sha256:" + strings.Repeat("33", 32)
	default:
		t.Fatalf("unknown mutation %q", mutation)
	}
}

func mustVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
