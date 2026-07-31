package protocol

import (
	"strings"
	"testing"
	"time"
)

func validDescriptor(now time.Time) ServiceDescriptor {
	return ServiceDescriptor{
		ProtocolVersion: DescriptorVersion,
		ServiceID:       "edge.example.ai",
		DisplayName:     "Example edge terminal",
		Controller:      "tos:test:controller",
		Network:         "testnet",
		Revision:        "rev-1",
		ExpiresAt:       now.Add(time.Hour),
		Profiles: []ProfileReference{{
			ID:        "tos.ai.inference",
			Version:   "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://edge.example/.well-known/tos-inference.json",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
}

func TestServiceDescriptorValidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := validDescriptor(now).Validate(now); err != nil {
		t.Fatalf("valid descriptor rejected: %v", err)
	}

	expired := validDescriptor(now)
	expired.ExpiresAt = now
	if err := expired.Validate(now); err == nil {
		t.Fatal("expired descriptor accepted")
	}

	duplicate := validDescriptor(now)
	duplicate.Profiles = append(duplicate.Profiles, duplicate.Profiles[0])
	if err := duplicate.Validate(now); err == nil {
		t.Fatal("duplicate profile accepted")
	}
}
