package edge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type testReadinessChecker struct {
	err   error
	calls int
}

type blockingReadinessChecker struct {
	calls   atomic.Int32
	entered chan struct{}
	release chan struct{}
}

func (checker *blockingReadinessChecker) CheckReady(ctx context.Context) error {
	checker.calls.Add(1)
	close(checker.entered)
	select {
	case <-checker.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (checker *testReadinessChecker) CheckReady(context.Context) error {
	checker.calls++
	return checker.err
}

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

func TestPaymentReconciliationFailureDegradesReadinessNotLiveness(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.ai", DisplayName: "Edge",
		Controller: "tos:test:controller", Network: "testnet", Revision: "1",
		ExpiresAt: now.Add(time.Hour),
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference", Digest: "sha256:" + strings.Repeat("a", 64),
		}},
	}
	coreConfig := DefaultCoreConfig(filepath.Join(t.TempDir(), "requests.db"))
	coreConfig.CleanupInterval = time.Hour
	core, err := openCore(coreConfig, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	core.recordPaymentReconciliation(
		PaymentReconciliationReport{Failed: 1}, nil,
	)
	server, err := NewServerWithCore(
		descriptor, ard.Catalog{SpecVersion: ard.SpecVersion}, now, core,
	)
	if err != nil {
		t.Fatal(err)
	}

	health := httptest.NewRecorder()
	server.Routes().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("external failure changed liveness: %d %s", health.Code, health.Body.String())
	}
	ready := httptest.NewRecorder()
	server.Routes().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable ||
		!strings.Contains(ready.Body.String(), `"component":"edge-core"`) ||
		strings.Contains(ready.Body.String(), "failed entries") {
		t.Fatalf("unexpected reconciliation readiness: %d %s", ready.Code, ready.Body.String())
	}
}

func TestServerSeparatesLivenessFromChainReadiness(t *testing.T) {
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
			ID: "tos.ai.inference", Version: "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference", Digest: "sha256:" + strings.Repeat("a", 64),
		}},
	}
	catalog := ard.Catalog{SpecVersion: ard.SpecVersion}
	checker := &testReadinessChecker{err: errors.New("private endpoint detail")}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now,
		ServerDependencies{ChainReadiness: checker},
	)
	if err != nil {
		t.Fatal(err)
	}
	probeNow := now
	server.now = func() time.Time { return probeNow }

	healthResponse := httptest.NewRecorder()
	server.Routes().ServeHTTP(
		healthResponse, httptest.NewRequest(http.MethodGet, "/healthz", nil),
	)
	if healthResponse.Code != http.StatusOK || checker.calls != 0 {
		t.Fatalf("liveness depended on chain: status=%d calls=%d", healthResponse.Code, checker.calls)
	}

	readyResponse := httptest.NewRecorder()
	server.Routes().ServeHTTP(
		readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil),
	)
	if readyResponse.Code != http.StatusServiceUnavailable || checker.calls != 1 ||
		!strings.Contains(readyResponse.Body.String(), `"component":"tos-chain"`) ||
		strings.Contains(readyResponse.Body.String(), "private endpoint detail") {
		t.Fatalf("unexpected degraded readiness: %d %s", readyResponse.Code, readyResponse.Body.String())
	}

	checker.err = nil
	probeNow = probeNow.Add(readinessCacheTTL)
	readyResponse = httptest.NewRecorder()
	server.Routes().ServeHTTP(
		readyResponse, httptest.NewRequest(http.MethodGet, "/readyz", nil),
	)
	if readyResponse.Code != http.StatusOK || checker.calls != 2 ||
		!strings.Contains(readyResponse.Body.String(), `"status":"ready"`) {
		t.Fatalf("unexpected healthy readiness: %d %s", readyResponse.Code, readyResponse.Body.String())
	}
}

func TestServerReportsReceiptSignerReadinessWithoutLeakingDetail(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	descriptor := protocol.ServiceDescriptor{
		ProtocolVersion: protocol.DescriptorVersion,
		ServiceID:       "edge.example.ai", DisplayName: "Edge",
		Controller: "tos:test:controller", Network: "testnet",
		Revision: "1", ExpiresAt: now.Add(time.Hour),
		Profiles: []protocol.ProfileReference{{
			ID: "tos.ai.inference", Version: "0.1",
			MediaType: "application/vnd.tos.ai-inference+json",
			URL:       "https://example.com/inference",
			Digest:    "sha256:" + strings.Repeat("a", 64),
		}},
	}
	checker := &testReadinessChecker{err: errors.New("private signer detail")}
	server, err := NewServerWithDependencies(
		descriptor, ard.Catalog{SpecVersion: ard.SpecVersion}, now,
		ServerDependencies{ReceiptSignerReadiness: checker},
	)
	if err != nil {
		t.Fatal(err)
	}
	server.now = func() time.Time { return now }
	health := httptest.NewRecorder()
	server.Routes().ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if health.Code != http.StatusOK || checker.calls != 0 {
		t.Fatalf("liveness used signer readiness: status=%d calls=%d", health.Code, checker.calls)
	}
	ready := httptest.NewRecorder()
	server.Routes().ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if ready.Code != http.StatusServiceUnavailable || checker.calls != 1 ||
		!strings.Contains(ready.Body.String(), `"component":"receipt-signer"`) ||
		strings.Contains(ready.Body.String(), "private signer detail") {
		t.Fatalf("unexpected signer readiness: %d %s", ready.Code, ready.Body.String())
	}
}

func TestReadinessGateBoundsConcurrentChainProbes(t *testing.T) {
	checker := &blockingReadinessChecker{
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	gate := newReadinessGate(checker)
	result := make(chan error, 1)
	now := time.Unix(1_800_000_000, 0)
	go func() {
		result <- gate.check(context.Background(), now)
	}()
	<-checker.entered
	if err := gate.check(context.Background(), now); !errors.Is(err, errReadinessProbeBusy) {
		t.Fatalf("concurrent readiness probe was not bounded: %v", err)
	}
	if calls := checker.calls.Load(); calls != 1 {
		t.Fatalf("chain readiness calls=%d, want 1", calls)
	}
	close(checker.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if err := gate.check(context.Background(), now.Add(readinessCacheTTL/2)); err != nil {
		t.Fatalf("cached successful readiness failed: %v", err)
	}
	if calls := checker.calls.Load(); calls != 1 {
		t.Fatalf("cached readiness reached chain: calls=%d", calls)
	}
}
