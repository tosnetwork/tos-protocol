package ard

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestBuildWorkerCatalogIsDeterministicPrivateAndHandoffSafe(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	response := testWorkerCatalogResponse(now)
	response.Resources = []*edgev1.ResourceClaim{{
		Id:            "memory.vram",
		ResourceClass: edgev1.ResourceClass_RESOURCE_CLASS_ACCELERATOR,
		Unit:          edgev1.ResourceUnit_RESOURCE_UNIT_BYTES,
		Total:         24 << 30, AvailableExternal: 12 << 30,
		Revision: "capacity-revision-1",
		Attributes: map[string]string{
			"gpu_uuid": "GPU-private-uuid",
			"hostname": "private-hostname",
		},
		Evidence: &edgev1.ClaimEvidence{
			Level:               edgev1.EvidenceLevel_EVIDENCE_LEVEL_DECLARED,
			Issuer:              "worker-private-issuer",
			CollectedUnixMillis: now.UnixMilli(),
			ExpiresUnixMillis:   now.Add(time.Minute).UnixMilli(),
		},
	}}
	config := testWorkerCatalogConfig()
	first, err := BuildWorkerCatalog(config, response, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildWorkerCatalog(config, response, now)
	if err != nil {
		t.Fatal(err)
	}
	firstJSON, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	secondJSON, err := json.Marshal(second)
	if err != nil || string(firstJSON) != string(secondJSON) {
		t.Fatalf("catalog is not deterministic: %s != %s err=%v", firstJSON, secondJSON, err)
	}
	if first.SpecVersion != SpecVersion || first.Host == nil ||
		first.Host.Identifier != "did:web:edge.example" || len(first.Entries) != 1 {
		t.Fatalf("catalog=%#v", first)
	}
	entry := first.Entries[0]
	if entry.Identifier != config.ServiceIdentifier ||
		entry.Metadata["capabilityCount"] != "2" {
		t.Fatalf("entry does not preserve the service identity: %#v", entry)
	}
	var extension WorkerCatalogExtension
	if err := json.Unmarshal(entry.Extensions[WorkerCatalogExtensionName], &extension); err != nil {
		t.Fatal(err)
	}
	if extension.Version != WorkerCatalogExtensionVersion ||
		extension.TerminalRevision != response.TerminalRevision ||
		len(extension.Capabilities) != 2 ||
		extension.Capabilities[0].ServiceID != "edge.example.alpha" ||
		extension.Capabilities[1].ServiceID != "edge.example.zeta" {
		t.Fatalf("Worker extension is not stable and sorted: %#v", extension)
	}
	lower := strings.ToLower(string(firstJSON))
	for _, forbidden := range []string{
		"gpu-private-uuid", "private-hostname", "gpu_uuid",
		"availableexternal", "capacity-revision-1", "worker-private-issuer",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("private or dynamic Worker data leaked into ARD catalog: %s", firstJSON)
		}
	}
	if err := first.Validate(DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	handoff, err := ParseServiceHandoff(entry, now)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.service",
		DisplayName:     config.ServiceDisplayName,
		Controller:      "0:example-controller",
		Network:         "tos-testnet",
		Revision:        "descriptor-revision-1",
		ExpiresAt:       now.Add(time.Hour),
		ARDIdentifier:   config.ServiceIdentifier,
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1",
			MediaType: "application/json",
			URL:       "https://edge.example/profiles/inference.json",
			Digest:    "sha256:" + strings.Repeat("b", 64),
		}},
	}
	if err := handoff.VerifyDescriptor(descriptor, now); err != nil {
		t.Fatalf("generated entry cannot hand off to its descriptor: %v", err)
	}
}

func TestBuildWorkerCatalogRejectsUnsafeOrUnpublishableInput(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	validConfig := testWorkerCatalogConfig()
	tests := []struct {
		name   string
		mutate func(*WorkerCatalogConfig, *edgev1.GetCapabilitiesResponse)
	}{
		{"http URL", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceURL = "http://edge.example/tos-service.json"
		}},
		{"userinfo URL", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceURL = "https://user@edge.example/tos-service.json"
		}},
		{"IP publisher", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceIdentifier = "urn:air:127.0.0.1:tos:terminal"
		}},
		{"noncanonical publisher", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceIdentifier = "urn:air:edge-.example:tos:terminal"
		}},
		{"uppercase publisher", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceIdentifier = "urn:air:EDGE.EXAMPLE:tos:terminal"
		}},
		{"publisher trailing dot", func(config *WorkerCatalogConfig, _ *edgev1.GetCapabilitiesResponse) {
			config.ServiceIdentifier = "urn:air:edge.example.:tos:terminal"
		}},
		{"stale", func(_ *WorkerCatalogConfig, response *edgev1.GetCapabilitiesResponse) {
			response.ExpiresUnixMillis = now.Add(-time.Second).UnixMilli()
		}},
		{"invalid model digest", func(_ *WorkerCatalogConfig, response *edgev1.GetCapabilitiesResponse) {
			response.Capabilities[0].ModelDigest = "declared-model"
		}},
		{"owner only", func(_ *WorkerCatalogConfig, response *edgev1.GetCapabilitiesResponse) {
			for _, capability := range response.Capabilities {
				capability.AcceptedPriorities = []edgev1.Priority{
					edgev1.Priority_PRIORITY_LOCAL_ASYNC,
				}
			}
		}},
		{"duplicate", func(_ *WorkerCatalogConfig, response *edgev1.GetCapabilitiesResponse) {
			response.Capabilities = append(
				response.Capabilities, response.Capabilities[0],
			)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig
			response := testWorkerCatalogResponse(now)
			test.mutate(&config, response)
			if _, err := BuildWorkerCatalog(config, response, now); err == nil {
				t.Fatal("unsafe Worker catalog input was accepted")
			}
		})
	}
}

func testWorkerCatalogConfig() WorkerCatalogConfig {
	return WorkerCatalogConfig{
		ServiceIdentifier:  "urn:air:edge.example:tos:ai-terminal",
		ServiceDisplayName: "Example TOS AI Edge Terminal",
		HostDisplayName:    "Example Edge Operator",
		HostIdentifier:     "did:web:edge.example",
		ServiceURL:         "https://edge.example/.well-known/tos-service.json",
		EntryVersion:       "0.1.0",
	}
}

func testWorkerCatalogResponse(now time.Time) *edgev1.GetCapabilitiesResponse {
	capability := func(service, model string, priorities ...edgev1.Priority) *edgev1.Capability {
		return &edgev1.Capability{
			ServiceId: service, Operation: "generate", Model: model,
			ModelDigest: "sha256:" + strings.Repeat("a", 64),
			Runtime:     "ollama", RuntimeRevision: "ollama-v1",
			MaxInputBytes: 1 << 20, MaxOutputBytes: 1 << 20,
			AcceptedPriorities: priorities,
		}
	}
	return &edgev1.GetCapabilitiesResponse{
		Capabilities: []*edgev1.Capability{
			capability(
				"edge.example.zeta", "zeta-model",
				edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
			),
			capability(
				"edge.example.owner", "owner-model",
				edgev1.Priority_PRIORITY_LOCAL_ASYNC,
			),
			capability(
				"edge.example.alpha", "alpha-model",
				edgev1.Priority_PRIORITY_EXTERNAL_SERVICE,
			),
		},
		CapacityRevision:    "capacity-revision-1",
		TerminalRevision:    "terminal-revision-1",
		CollectedUnixMillis: now.UnixMilli(),
		ExpiresUnixMillis:   now.Add(time.Minute).UnixMilli(),
	}
}
