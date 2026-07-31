package edge

import (
	"net/http"
	"net/http/httptest"
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

	response, err = http.Post(httpServer.URL+"/v1/invoke", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("public invocation unexpectedly exposed: %d", response.StatusCode)
	}
}
