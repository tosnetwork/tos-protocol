package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeServiceDescriptorJSONIsStrict(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	document := `{
  "protocolVersion":"0.1","serviceId":"tos.ai.mock","displayName":"AI",
  "controller":"0:` + strings.Repeat("1", 64) + `","network":"tos-local",
  "revision":"one","expiresAt":"2027-01-16T08:01:00Z",
  "profiles":[{"id":"tos.ai.text-generation","version":"0.1.0",
  "mediaType":"application/json","url":"https://edge.example/profile.json",
  "digest":"sha256:` + strings.Repeat("2", 64) + `"}]}`
	if _, err := DecodeServiceDescriptorJSON([]byte(document), now); err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(document, `"network":"tos-local"`,
		`"network":"tos-local","network":"other"`, 1)
	if _, err := DecodeServiceDescriptorJSON([]byte(duplicate), now); err == nil {
		t.Fatal("duplicate descriptor field was accepted")
	}
	unknown := strings.Replace(document, `"revision":"one"`,
		`"revision":"one","privateKey":"secret"`, 1)
	if _, err := DecodeServiceDescriptorJSON([]byte(unknown), now); err == nil {
		t.Fatal("unknown descriptor field was accepted")
	}
}
