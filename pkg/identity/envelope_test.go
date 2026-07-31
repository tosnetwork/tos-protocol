package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"math"
	"testing"
	"time"
)

func TestEnvelopeSignVerifyAndDomainSeparation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	env, err := Sign(privateKey, "tos.quote.v1", "runtime-key-1", []byte("payload"), now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Verify(publicKey, "tos.quote.v1", now); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if err := env.Verify(publicKey, "tos.receipt.v1", now); err == nil {
		t.Fatal("cross-domain replay accepted")
	}
	env.Payload[0] ^= 1
	if err := env.Verify(publicKey, "tos.quote.v1", now); err == nil {
		t.Fatal("modified payload accepted")
	}
}

func TestEnvelopeRejectsLifetimeOverflow(t *testing.T) {
	env := Envelope{
		Version: Version, Domain: "tos.quote.v1", KeyID: "runtime-key-1",
		IssuedAt: math.MinInt64, ExpiresAt: math.MaxInt64,
		Nonce: base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
	}
	if err := env.validateStructure(); err == nil {
		t.Fatal("overflowing envelope lifetime accepted")
	}
}
