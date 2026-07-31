package identity

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

type signedEnvelopeVector struct {
	Version            uint8    `json:"version"`
	PrivateKeySeedHex  string   `json:"privateKeySeedHex"`
	PublicKeyBase64URL string   `json:"publicKeyBase64Url"`
	Envelope           Envelope `json:"envelope"`
}

func TestSignedEnvelopeVector(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate signed envelope vector")
	}
	path := filepath.Join(
		filepath.Dir(filename), "..", "..", "spec", "base", "test-vectors", "signed-envelope-v1.json",
	)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector signedEnvelopeVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.PrivateKeySeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("invalid test seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicKeyText := base64.RawURLEncoding.EncodeToString(publicKey)
	signatureText := base64.RawURLEncoding.EncodeToString(
		ed25519.Sign(privateKey, vector.Envelope.signingMessage()),
	)
	if publicKeyText != vector.PublicKeyBase64URL || signatureText != vector.Envelope.Signature {
		t.Fatalf("vector mismatch\npublicKeyBase64Url: %s\nsignature: %s", publicKeyText, signatureText)
	}
	now := time.UnixMilli(vector.Envelope.IssuedAt + 1)
	if err := vector.Envelope.Verify(publicKey, vector.Envelope.Domain, now); err != nil {
		t.Fatal(err)
	}
	var payload map[string]interface{}
	if err := codec.Unmarshal(vector.Envelope.Payload, &payload); err != nil {
		t.Fatalf("vector payload is not canonical: %v", err)
	}
}
