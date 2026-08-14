package nativecore

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

func testPolicy(t *testing.T) (*nativev1.ControllerPolicyV1, ed25519.PrivateKey) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 60,
		Controllers: []*nativev1.ControllerV1{{KeyId: "ed25519:" + fmt.Sprintf("%x", pub), Ed25519PublicKey: pub, Weight: 1,
			PurposeMask: PurposeAgentControl | PurposeDelegation | PurposeRecovery | PurposeCapabilityControl, Recovery: true}}}, privateKey
}

func TestBuildSignAndVerifyDirectNativeAction(t *testing.T) {
	policy, privateKey := testPolicy(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	agentID, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        network,
		TargetObjectId: agentID, TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32),
		Generation: 1, Sequence: 1, Nonce: []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(privateKey, policy.Controllers[0].KeyId, built)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignatures(policy, []*nativev1.SignatureV1{signature}, PurposeAgentControl, false, built.Hash); err != nil {
		t.Fatal(err)
	}
	body, err := MessageBody(built, []*nativev1.SignatureV1{signature}, nil, 7)
	if err != nil || len(body.ToBOC()) == 0 {
		t.Fatalf("body: %v", err)
	}
}

func TestNativePolicyEncodingIsIndependentOfInputOrder(t *testing.T) {
	pubA, _, _ := ed25519.GenerateKey(rand.Reader)
	pubB, _, _ := ed25519.GenerateKey(rand.Reader)
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{
		{KeyId: "ed25519:" + fmt.Sprintf("%x", pubA), Ed25519PublicKey: pubA, Weight: 1, PurposeMask: knownPurposeMask, Recovery: true},
		{KeyId: "ed25519:" + fmt.Sprintf("%x", pubB), Ed25519PublicKey: pubB, Weight: 1, PurposeMask: knownPurposeMask, Recovery: true},
	}}
	first, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.Controllers[0], policy.Controllers[1] = policy.Controllers[1], policy.Controllers[0]
	second, err := PolicyCell(policy)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Hash()) != string(second.Hash()) {
		t.Fatal("policy input order changed canonical Cell")
	}
}

func TestNativePolicyHasOneNormalAuthorityAndExplicitRecoverySubset(t *testing.T) {
	policy, _ := testPolicy(t)
	controller := policy.Controllers[0]
	controller.PurposeMask &^= PurposeCapabilityControl
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("split normal-purpose controller was accepted")
	}
	controller.PurposeMask |= PurposeCapabilityControl
	controller.Recovery = false
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("recovery purpose without recovery designation was accepted")
	}
	controller.PurposeMask &^= PurposeRecovery
	controller.Recovery = true
	if _, err := PolicyCell(policy); err == nil {
		t.Fatal("recovery designation without recovery purpose was accepted")
	}
}

func TestRegistrationRejectsCallerSelectedIdentity(t *testing.T) {
	policy, _ := testPolicy(t)
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		TargetObjectId: "agent_" + strings.Repeat("33", 32), TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32),
		Generation: 1, Sequence: 1, Nonce: []byte(strings.Repeat("n", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: []byte(strings.Repeat("o", 32)), InitialPolicy: policy}}}
	if _, err := BuildAction(action); err == nil {
		t.Fatal("caller-selected registration identity accepted")
	}
}

func TestGenerationResetRetainsNonzeroPredecessor(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	base := func(target string) *nativev1.NativeActionV1 {
		return &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: target,
			TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 2, Sequence: 1,
			PredecessorTvmStateHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), Nonce: []byte(strings.Repeat("n", 32))}
	}
	recovery := base("agent_" + strings.Repeat("33", 32))
	recovery.Payload = &nativev1.NativeActionV1_CompleteRecovery{CompleteRecovery: &nativev1.CompleteRecoveryV1{InitiationActionHash: "sha256:" + strings.Repeat("66", 32)}}
	if _, err := BuildAction(recovery); err != nil {
		t.Fatalf("canonical recovery reset rejected: %v", err)
	}
	recovery.PredecessorTvmStateHash = ""
	if _, err := BuildAction(recovery); err == nil {
		t.Fatal("recovery reset with zero predecessor was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadPredecessor {
		t.Fatalf("recovery reset with zero predecessor error = %v", err)
	}
	transfer := base("cap_" + strings.Repeat("77", 32))
	transfer.Payload = &nativev1.NativeActionV1_TransferCapability{TransferCapability: &nativev1.TransferCapabilityV1{
		CurrentOwnerAgentId: "agent_" + strings.Repeat("88", 32), NewOwnerAgentId: "agent_" + strings.Repeat("99", 32)}}
	if _, err := BuildAction(transfer); err != nil {
		t.Fatalf("canonical transfer reset rejected: %v", err)
	}
}

func TestMutationPredecessorRules(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: "agent_" + strings.Repeat("33", 32),
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 2,
		Nonce: []byte(strings.Repeat("n", 32)), Payload: &nativev1.NativeActionV1_DelegateAgent{DelegateAgent: &nativev1.DelegateAgentV1{DelegationDigest: "sha256:" + strings.Repeat("66", 32)}}}
	if _, err := BuildAction(action); err == nil {
		t.Fatal("ordinary mutation without predecessor was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadPredecessor {
		t.Fatalf("ordinary mutation without predecessor error = %v", err)
	}
	action.PredecessorTvmStateHash = "tvm-cell-sha256:" + strings.Repeat("55", 32)
	action.Sequence = 1
	if _, err := BuildAction(action); err == nil {
		t.Fatal("ordinary mutation with reset sequence was accepted")
	} else if code, ok := ErrorCodeOf(err); !ok || code != ErrBadSequence {
		t.Fatalf("ordinary mutation with reset sequence error = %v", err)
	}
}

func TestCapabilityRegistrationFitsCanonicalCellAndUsesDerivedID(t *testing.T) {
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	version := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	owner := "agent_" + strings.Repeat("66", 32)
	objectNonce := []byte(strings.Repeat("c", 32))
	id, err := DeriveCapabilityID(network, objectNonce, owner, version)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("a", 32)), Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: objectNonce, OwnerAgentId: owner, InitialVersion: version}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	if built.Cell.BitsSize() > 1023 {
		t.Fatalf("action root exceeds TVM Cell limit: %d", built.Cell.BitsSize())
	}
}

func TestNativeActionHasNoAnchorOrPortableStateCommitment(t *testing.T) {
	policy, _ := testPolicy(t)
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	agentID, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol,
		Network:        network,
		TargetObjectId: agentID, TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("n", 32)), Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	s := built.Cell.BeginParse()
	if s.RefsNum() != 2 {
		t.Fatalf("action refs = %d, want domain+payload only", s.RefsNum())
	}
}
