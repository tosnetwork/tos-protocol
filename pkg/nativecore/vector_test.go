package nativecore

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

func TestFrozenAgentRegistrationVector(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	publicKey := key.Public().(ed25519.PublicKey)
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, RecoveryTimelockSeconds: 86400,
		Controllers: []*nativev1.ControllerV1{{KeyId: "ed25519:" + hex.EncodeToString(publicKey), Ed25519PublicKey: publicKey,
			Weight: 1, PurposeMask: 15, Recovery: true}}}
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	id, err := DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	if id != "agent_c082c865f6c332e53615a84da797c1b1f2e993779b7aae191e4f30be5661526f" {
		t.Fatalf("Agent ID = %s", id)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:c4af55e476c296c8a1dc7985e82db42218475b9e3864b7c733351bab526ab23d",
		Generation:             1, Sequence: 1, Nonce: []byte(strings.Repeat("a", 32)),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	if built.HashString != "sha256:5e435e54f62733af27387165071d1e95c3b8e1020c8628bd8d4c41ed72533bc3" {
		t.Fatalf("action hash = %s", built.HashString)
	}
	signature, err := SignAction(key, policy.Controllers[0].KeyId, built)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(signature.Ed25519Signature) != "c48d93bad4ebdcde8d9aac607cb09a57ea7cd3ab394986eb95938d2374a70a0d92610b82fdba02e94913ee114469fdf34efd0f5e8eae1ded28b173bd29fae404" {
		t.Fatal("signature vector changed")
	}
	if base64.StdEncoding.EncodeToString(built.Cell.ToBOC()) != "te6cckECBgEAAYcAAvBOVkExAAEBAQAAAAAAAAABAAAAAAAAAAHAgshl9sMy5TYVqE2nl8Gx8umTd5t6rhkeTzC+VmFSbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWEBAgHAEREREREREREREREREREREREREREREREREREREREREREiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIgDrh8YJb1Wg10F1mJNMg5RCHonvnLj4jnmxuLXmI8jBAwFAb29vb29vb29vb29vb29vb29vb29vb29vb29vb29vb28EAEDEr1XkdsKWyKHceYXoLbQiGEdbnjhkt8czNRurUmqyPQEuTlZQMQABAAAAAQAAAAEAAAAAAAFRgAEFAI15tVYuj+ZU+UB4sRLoqYunkB+FOuaVvtfg45ELrQSWZHm1Vi6P5lT5QHixEuipi6eQH4U65pW+1+DjkQutBJZkAAAAAQAPwLDZkYs=" {
		t.Fatal("action Cell BOC vector changed")
	}
}
