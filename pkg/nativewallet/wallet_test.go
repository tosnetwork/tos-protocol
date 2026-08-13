package nativewallet

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
)

func TestLoadReviewConfirmAndSign(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "controller.json")
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	content := `{"schema":"atos.native.wallet-key.v1","private_seed_hex":"` + hex.EncodeToString(seed) + `"}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	policy := &nativev1.ControllerPolicyV1{Threshold: 1, RecoveryThreshold: 1, Controllers: []*nativev1.ControllerV1{{
		KeyId: "ed25519:" + hex.EncodeToString(public), Ed25519PublicKey: public, Weight: 1,
		PurposeMask: 15, Recovery: true,
	}}}
	network := &nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	objectNonce := []byte(strings.Repeat("o", 32))
	id, err := nativecore.DeriveAgentID(network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: nativecore.Protocol, Network: network, TargetObjectId: id,
		TargetContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32), Generation: 1, Sequence: 1,
		Nonce: []byte(strings.Repeat("a", 32)), Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{
			ObjectNonce: objectNonce, InitialPolicy: policy}}}
	review, built, err := ReviewAction(action)
	if err != nil || review.Action != "register_agent" || review.ActionHash != built.HashString {
		t.Fatalf("review = %+v, err = %v", review, err)
	}
	if err := ConfirmHash(bufio.NewReader(strings.NewReader(review.ActionHash+"\n")), review.ActionHash); err != nil {
		t.Fatal(err)
	}
	signatures, err := Sign(built, []*Key{key})
	if err != nil || len(signatures) != 1 || len(signatures[0].Ed25519Signature) != ed25519.SignatureSize {
		t.Fatalf("signatures = %v, err = %v", signatures, err)
	}
}

func TestKeyFileAndConfirmationFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, []byte(`{"schema":"atos.native.wallet-key.v1","private_seed_hex":"`+strings.Repeat("11", 32)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKey(path); err == nil {
		t.Fatal("world-readable key was accepted")
	}
	if err := ConfirmHash(bufio.NewReader(strings.NewReader("sha256:wrong\n")), "sha256:expected"); err == nil {
		t.Fatal("wrong semantic confirmation was accepted")
	}
}
