package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDecodeEnvelopeJSONIsStrictAndDomainBound(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	envelope, err := Sign(privateKey, "tos.manifest.v1", "controller", []byte("payload"), now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeEnvelopeJSON(document, "tos.manifest.v1")
	if err != nil || string(decoded.Payload) != "payload" {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := DecodeEnvelopeJSON(document, "tos.quote.v1"); err == nil {
		t.Fatal("wrong envelope domain was accepted")
	}
	duplicate := strings.Replace(string(document), `"domain":"tos.manifest.v1"`,
		`"domain":"tos.manifest.v1","domain":"tos.quote.v1"`, 1)
	if _, err := DecodeEnvelopeJSON([]byte(duplicate), "tos.manifest.v1"); err == nil {
		t.Fatal("duplicate envelope field was accepted")
	}
}
