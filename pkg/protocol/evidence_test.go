package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestEvidenceBundleValidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	bundle := EvidenceBundle{
		Version:   BaseEnvelopeVersion,
		BundleID:  "evidence-0001",
		RequestID: "request-0001",
		Claims: []EvidenceClaim{{
			Type:        "tos.ai.model",
			Level:       EvidenceAttested,
			Subject:     "model:qwen",
			Issuer:      "attestor-key-1",
			CollectedAt: now.Add(-time.Minute),
			ExpiresAt:   now.Add(time.Hour),
			Digest:      "sha256:" + strings.Repeat("b", 64),
		}},
	}
	if err := bundle.Validate(now); err != nil {
		t.Fatal(err)
	}
	tooLong := bundle
	tooLong.Claims = append([]EvidenceClaim(nil), bundle.Claims...)
	tooLong.Claims[0].ExpiresAt = tooLong.Claims[0].CollectedAt.Add(MaxEvidenceLifetime + time.Second)
	if err := tooLong.Validate(now); err == nil {
		t.Fatal("unbounded evidence lifetime accepted")
	}
	bundle.Claims[0].Level = EvidenceLevel("trusted")
	if err := bundle.Validate(now); err == nil {
		t.Fatal("unknown evidence level accepted")
	}
}
