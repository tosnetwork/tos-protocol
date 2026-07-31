package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

type canonicalMessage struct {
	RequestID string `json:"requestId"`
	Limit     uint64 `json:"limit"`
}

func TestSignAndVerifyCanonical(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	input := canonicalMessage{RequestID: "request-0001", Limit: 42}
	envelope, err := SignCanonical(privateKey, "tos.quote.v1", "runtime-key-1", input, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	var output canonicalMessage
	if err := envelope.VerifyCanonical(publicKey, "tos.quote.v1", now, &output); err != nil {
		t.Fatal(err)
	}
	if output != input {
		t.Fatalf("output = %#v", output)
	}
}
