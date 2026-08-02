package registry

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

func federationCatalog(id string) []byte {
	encoded, _ := json.Marshal(ard.Catalog{SpecVersion: ard.SpecVersion, Entries: []ard.Entry{{
		Identifier: id, DisplayName: id, Type: "application/vnd.tos.service+json",
		URL: "https://service.example/invoke", Tags: []string{"federated"},
	}}})
	return encoded
}

func federationConfig(root, origin string) FederationConfig {
	config := DefaultFederationConfig()
	config.Roots = []string{root}
	config.AllowedOrigins = []string{origin}
	config.AllowPrivateOrigins = true
	config.MinimumTTL = time.Second
	config.MaximumTTL = time.Minute
	return config
}

func TestFederationCrawlCycleCachedSearchAndExpiry(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "max-age=2")
		if request.URL.Path == "/a" {
			writer.Header().Set("Link", "<"+server.URL+"/b>; rel=\"ard-registry\"")
			_, _ = writer.Write(federationCatalog("urn:air:one.example:agent:a"))
			return
		}
		writer.Header().Set("Link", "<"+server.URL+"/a>; rel=\"ard-registry\"")
		_, _ = writer.Write(federationCatalog("urn:air:two.example:agent:b"))
	}))
	defer server.Close()
	index, _ := NewIndex(DefaultLimits())
	federation, err := NewFederation(index, server.Client(), federationConfig(server.URL+"/a", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	if err := federation.Refresh(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	status := federation.Status()
	if status.Sources != 2 || status.Generation != 1 || !status.ExpiresAt.Equal(now.Add(2*time.Second)) {
		t.Fatalf("unexpected status: %#v", status)
	}
	response, err := index.Search(SearchRequest{Query: QueryModel{Text: "federated"}, Federation: "cached"}, "https://registry.example")
	if err != nil || len(response.Results) != 2 {
		t.Fatalf("search=%#v err=%v", response, err)
	}
	if expired, err := federation.Expire(now.Add(3 * time.Second)); err != nil || !expired {
		t.Fatalf("expired=%v err=%v", expired, err)
	}
	response, _ = index.Search(SearchRequest{Query: QueryModel{Text: "federated"}, Federation: "cached"}, "https://registry.example")
	if len(response.Results) != 0 {
		t.Fatal("expired federation remained searchable")
	}
}

func TestFederationFailurePreservesAtomicGeneration(t *testing.T) {
	var broken atomic.Bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if broken.Load() {
			http.Error(writer, "broken", http.StatusBadGateway)
			return
		}
		_, _ = writer.Write(federationCatalog("urn:air:stable.example:agent:one"))
	}))
	defer server.Close()
	index, _ := NewIndex(DefaultLimits())
	federation, err := NewFederation(index, server.Client(), federationConfig(server.URL+"/catalog", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	if err := federation.Refresh(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	if err := federation.Refresh(context.Background(), now.Add(time.Second)); err == nil {
		t.Fatal("broken refresh succeeded")
	}
	response, _ := index.Search(SearchRequest{Query: QueryModel{Text: "stable"}}, "https://registry.example")
	if len(response.Results) != 1 || federation.Status().Generation != 1 || federation.Status().LastError != "refresh_failed" {
		t.Fatalf("atomic generation was not preserved: %#v %#v", response, federation.Status())
	}
}

func TestFederationRejectsRedirectOutsideAllowlist(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Location", "https://metadata.google.internal/latest")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	index, _ := NewIndex(DefaultLimits())
	federation, err := NewFederation(index, server.Client(), federationConfig(server.URL+"/catalog", server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := federation.Refresh(context.Background(), time.Now()); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("unsafe redirect error=%v", err)
	}
}

func TestFederationRejectsPrivateAddressByDefault(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(federationCatalog("urn:air:private.example:agent:one"))
	}))
	defer server.Close()
	index, _ := NewIndex(DefaultLimits())
	config := federationConfig(server.URL+"/catalog", server.URL)
	config.AllowPrivateOrigins = false
	federation, err := NewFederation(index, server.Client(), config)
	if err != nil {
		t.Fatal(err)
	}
	if err := federation.Refresh(context.Background(), time.Now()); err == nil || !strings.Contains(err.Error(), "disallowed address space") {
		t.Fatalf("private SSRF destination error=%v", err)
	}
}

func TestFederationRejectsGzipExpansionAndDepthOverflow(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/bomb" {
			var compressed bytes.Buffer
			archive := gzip.NewWriter(&compressed)
			_, _ = archive.Write(bytes.Repeat([]byte("x"), 4096))
			_ = archive.Close()
			writer.Header().Set("Content-Encoding", "gzip")
			_, _ = writer.Write(compressed.Bytes())
			return
		}
		writer.Header().Set("Link", "<"+server.URL+"/next>; rel=\"ard-registry\"")
		_, _ = writer.Write(federationCatalog("urn:air:depth.example:agent:one"))
	}))
	defer server.Close()
	index, _ := NewIndex(DefaultLimits())
	config := federationConfig(server.URL+"/bomb", server.URL)
	config.MaxDecodedBytes = 128
	federation, _ := NewFederation(index, server.Client(), config)
	if err := federation.Refresh(context.Background(), time.Now()); err == nil || !strings.Contains(err.Error(), "decoded byte limit") {
		t.Fatalf("gzip bomb error=%v", err)
	}
	config = federationConfig(server.URL+"/root", server.URL)
	config.MaxDepth = 0
	federation, _ = NewFederation(index, server.Client(), config)
	if err := federation.Refresh(context.Background(), time.Now()); err == nil || !strings.Contains(err.Error(), "depth limit") {
		t.Fatalf("depth error=%v", err)
	}
}
