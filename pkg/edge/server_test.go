package edge

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestServerHasDiscoveryButNoInvocation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.ai",
		DisplayName:     "Edge",
		Controller:      "tos:test:controller",
		Network:         "testnet",
		Revision:        "1",
		ExpiresAt:       now.Add(time.Hour),
		Profiles: []protocol.ProfileReference{{
			ID:        "tos.ai.inference",
			Version:   "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
	catalog := ard.Catalog{
		SpecVersion: ard.SpecVersion,
		Entries: []ard.Entry{{
			Identifier:  "urn:air:example.com:tos:edge",
			DisplayName: "Edge",
			Type:        "application/vnd.tos.service+json",
			URL:         "https://example.com/.well-known/tos-service.json",
		}},
	}
	server, err := NewServer(descriptor, catalog, now)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Routes())
	defer httpServer.Close()

	response, err := http.Get(httpServer.URL + "/.well-known/tos-service.json")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("descriptor status = %d", response.StatusCode)
	}
	if contentType := response.Header.Get("Content-Type"); contentType != ard.TOSServiceDescriptorMediaType {
		t.Fatalf("descriptor Content-Type = %q", contentType)
	}

	response, err = http.Post(httpServer.URL+"/v1/invoke", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("public invocation unexpectedly exposed: %d", response.StatusCode)
	}
}

func TestServerStopsServingExpiredDescriptor(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.ai",
		DisplayName:     "Edge",
		Controller:      "tos:test:controller",
		Network:         "testnet",
		Revision:        "1",
		ExpiresAt:       now.Add(time.Minute),
		Profiles: []protocol.ProfileReference{{
			ID:        "tos.ai.inference",
			Version:   "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
	catalog := ard.Catalog{SpecVersion: ard.SpecVersion}
	server, err := NewServer(descriptor, catalog, now)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return descriptor.ExpiresAt }

	request := httptest.NewRequest(http.MethodGet, "/.well-known/tos-service.json", nil)
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("expired response cache policy = %q", response.Header().Get("Cache-Control"))
	}
}

func TestServerHealthFailsClosedWhenRequestJournalFails(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.ai",
		DisplayName:     "Edge",
		Controller:      "tos:test:controller",
		Network:         "testnet",
		Revision:        "1",
		ExpiresAt:       now.Add(time.Hour),
		Profiles: []protocol.ProfileReference{{
			ID:        "tos.ai.inference",
			Version:   "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
	catalog := ard.Catalog{SpecVersion: ard.SpecVersion}
	coreConfig := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	coreConfig.CleanupInterval = time.Hour
	core, err := openCore(coreConfig, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	server, err := NewServerWithCore(descriptor, catalog, now, core)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.requests.Close(); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(response.Body.String(), `"component":"request-journal"`) {
		t.Fatalf("unexpected health response: %s", response.Body.String())
	}
}
