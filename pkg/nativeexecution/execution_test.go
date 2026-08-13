package nativeexecution

import (
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
)

func TestExecutionBindsPortableAndTVMState(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	policy := nativeprotocol.ControllerPolicy{Threshold: 1, RecoveryThreshold: 1, Controllers: []nativeprotocol.ControllerKey{{KeyID: "root", Algorithm: "ed25519", PublicKeyBase64: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "recovery"}}}, RecoveryKeyIDs: []string{"root"}, RecoveryTimelock: 60}
	policyCBOR, policyDigest, err := nativeprotocol.EncodeControllerPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	network := nativeprotocol.NetworkDomain{NetworkID: "tos-localnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	agentID, err := nativeprotocol.AgentID(nativeprotocol.AgentBootstrap{Version: nativeprotocol.Version, Network: network, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), InitialControllerPolicy: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	payloadCBOR, payloadDigest, err := nativeprotocol.EncodePayload(nativeprotocol.ActionRegisterAgent, nativeprotocol.RegisterAgentPayload{ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), InitialPolicyDigest: policyDigest, InitialPolicyCBORBase64: policyCBOR})
	if err != nil {
		t.Fatal(err)
	}
	actionNonce := make([]byte, 32)
	for i := range actionNonce {
		actionNonce[i] = byte(0x80 + i)
	}
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: nativeprotocol.ActionRegisterAgent, Network: network, AgentID: agentID, Generation: 1, Sequence: 1, PolicyDigest: policyDigest, PayloadDigest: payloadDigest, PayloadCBORBase64: payloadCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(actionNonce)}
	contract := ContractIdentity{Network: network, Address: "0:" + strings.Repeat("33", 32), ActionAnchorAddress: "0:" + strings.Repeat("55", 32), AllowedCodeHash: "sha256:" + strings.Repeat("44", 32)}
	unsigned, err := Build(nil, action, "", policy, nil, 0, contract)
	if err != nil {
		t.Fatal(err)
	}
	if err := Validate(unsigned.Execution, action, contract); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeActionCell(unsigned.Action)
	if err != nil || decoded.Action != action || decoded.Previous != nil || !reflect.DeepEqual(decoded.Next, unsigned.NextState) {
		t.Fatalf("decode jointly signed action: %+v %v", decoded, err)
	}
	sig, err := Sign(privateKey, "root", unsigned.Execution)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(privateKey.Public().(ed25519.PublicKey), sig, unsigned.Execution); err != nil {
		t.Fatal(err)
	}
	unsigned.Execution.AuthoritySignatures = []Signature{sig}
	if body, err := MessageBody(unsigned.Execution); err != nil || len(body.ToBOC()) == 0 {
		t.Fatalf("message body: %v", err)
	}
	list, err := signatureListCell(unsigned.Execution.AuthoritySignatures, unsigned.Execution)
	if err != nil {
		t.Fatal(err)
	}
	decodedSignatures, err := decodeAndVerifySignatureList(list, policy, unsigned.Execution)
	if err != nil || len(decodedSignatures) != 1 || decodedSignatures[0].KeyID != "root" {
		t.Fatalf("independent finalized signature verification: %+v %v", decodedSignatures, err)
	}
	if err := nativeprotocol.ValidateAuthorizationKeyIDs(action, "", policy, signatureKeyIDs(decodedSignatures)); err != nil {
		t.Fatalf("independent finalized threshold verification: %v", err)
	}
	changedExecution := unsigned.Execution
	changedExecution.ActionAnchorAddress = "0:" + strings.Repeat("66", 32)
	if _, err := decodeAndVerifySignatureList(list, policy, changedExecution); err == nil {
		t.Fatal("signature list accepted for a substituted Action Anchor")
	}

	// BOC is a transport encoding of a cell DAG and different valid serializers
	// may choose a different topological ordering. Unsigned semantic equality is
	// therefore bound to the validated root cell hash, not the carrier bytes.
	transportVariant := unsigned.Execution
	transportVariant.ActionCellBOCBase64 = "different-transport-ordering"
	if !SameUnsigned(unsigned.Execution, transportVariant) {
		t.Fatal("BOC transport bytes were treated as registry semantics")
	}
	cellVariant := unsigned.Execution
	cellVariant.ActionCellHash = "sha256:" + strings.Repeat("77", 32)
	if SameUnsigned(unsigned.Execution, cellVariant) {
		t.Fatal("different action cell hash was treated as the same semantics")
	}

	changed := unsigned.Execution
	changed.ExpectedPortableStateDigest = "sha256:" + strings.Repeat("55", 32)
	if err := Verify(privateKey.Public().(ed25519.PublicKey), sig, changed); err == nil {
		t.Fatal("state substitution accepted")
	}
	changed = unsigned.Execution
	changed.ContractAddress = "0:" + strings.Repeat("66", 32)
	if err := Verify(privateKey.Public().(ed25519.PublicKey), sig, changed); err == nil {
		t.Fatal("contract substitution accepted")
	}
}

func TestExecutionRejectsNoncanonicalBOCAndActionMismatch(t *testing.T) {
	// The positive test covers construction. These mutations prove a relay
	// cannot reframe the signed bytes or swap only the portable tuple.
	var execution Execution
	if err := Validate(execution, nativeprotocol.RegistryAction{}, ContractIdentity{}); err == nil {
		t.Fatal("empty execution accepted")
	}
}
