package protocol

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func validManifest(now time.Time) ServiceManifest {
	return ServiceManifest{
		Version:    ManifestVersion,
		ManifestID: "manifest-0001",
		ServiceID:  "edge.example.ai",
		Controller: "tos:test:controller",
		Network:    "testnet",
		Revision:   "manifest-revision-1",
		IssuedAt:   now.Add(-time.Minute),
		ExpiresAt:  now.Add(time.Hour),
		RuntimeKeys: []RuntimeKey{{
			KeyID:     "runtime-key-1",
			Algorithm: "Ed25519",
			PublicKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			Roles: []string{
				RuntimeRoleAuthenticate, RuntimeRoleQuote, RuntimeRoleReceipt,
			},
			NotBefore: now.Add(-time.Minute),
			NotAfter:  now.Add(time.Hour),
		}},
		Endpoints: []ServiceEndpoint{{
			Transport: "https",
			Audience:  "authenticated",
			URL:       "https://edge.example/v1",
		}},
		Profiles: []ProfileReference{{
			ID:        "tos.ai.inference",
			Version:   "0.1.0",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://edge.example/.well-known/tos-inference.json",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
		Capabilities: []CapabilityClaim{{
			ID:       "tos.ai.generate",
			Revision: "model-1",
			Evidence: EvidenceObserved,
			Attributes: map[string]string{
				"runtime": "ollama",
			},
		}},
	}
}

func TestServiceManifestValidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := validManifest(now).Validate(now); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	duplicateKey := validManifest(now)
	duplicateKey.RuntimeKeys = append(duplicateKey.RuntimeKeys, duplicateKey.RuntimeKeys[0])
	if err := duplicateKey.Validate(now); err == nil {
		t.Fatal("duplicate runtime key accepted")
	}
	tooLong := validManifest(now)
	tooLong.ExpiresAt = tooLong.IssuedAt.Add(MaxManifestLifetime + time.Second)
	tooLong.RuntimeKeys[0].NotAfter = tooLong.ExpiresAt
	if err := tooLong.Validate(now); err == nil {
		t.Fatal("overlong manifest accepted")
	}
	duplicateEndpoint := validManifest(now)
	duplicateEndpoint.Endpoints = append(duplicateEndpoint.Endpoints, duplicateEndpoint.Endpoints[0])
	if err := duplicateEndpoint.Validate(now); err == nil {
		t.Fatal("duplicate endpoint accepted")
	}
}

func TestServiceEndpointTransportSeparation(t *testing.T) {
	endpoint := ServiceEndpoint{
		Transport:   "https",
		Audience:    "public",
		URL:         "https://edge.example",
		ADNLAddress: "forbidden",
	}
	if err := endpoint.Validate(); err == nil {
		t.Fatal("mixed HTTPS and ADNL endpoint accepted")
	}
}
