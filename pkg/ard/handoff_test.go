package ard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func handoffDescriptor(now time.Time) protocol.ServiceDescriptor {
	return protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion, ServiceID: "edge.example.ai",
		DisplayName: "Example edge", Controller: "tos:test:controller",
		Network: "testnet", Revision: "descriptor-1", ExpiresAt: now.Add(time.Hour),
		ARDIdentifier: "urn:air:edge.example:tos:terminal",
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1.0",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://edge.example/inference.json",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
}

func TestParseEmbeddedServiceHandoff(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	data, err := json.Marshal(handoffDescriptor(now))
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := ParseServiceHandoff(Entry{
		Identifier:  "urn:air:edge.example:tos:terminal",
		DisplayName: "Example edge", Type: TOSServiceDescriptorMediaType, Data: data,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if handoff.Publisher != "edge.example" || handoff.EmbeddedDescriptor == nil {
		t.Fatalf("unexpected handoff: %#v", handoff)
	}
}

func TestServiceHandoffRejectsInsecureURLAndIdentitySubstitution(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	entry := Entry{
		Identifier:  "urn:air:edge.example:tos:terminal",
		DisplayName: "Example edge", Type: TOSServiceDescriptorMediaType,
		URL: "http://edge.example/.well-known/tos-service.json",
	}
	if _, err := ParseServiceHandoff(entry, now); err == nil {
		t.Fatal("insecure public descriptor URL accepted")
	}
	entry.URL = "https://edge.example/.well-known/tos-service.json"
	handoff, err := ParseServiceHandoff(entry, now)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := handoffDescriptor(now)
	descriptor.ARDIdentifier = "urn:air:attacker.example:tos:terminal"
	if err := handoff.VerifyDescriptor(descriptor, now); err == nil {
		t.Fatal("substituted ARD identifier accepted")
	}
}
