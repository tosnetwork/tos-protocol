package edge

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/journal"
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

type panickingReadinessChecker struct{}

func (panickingReadinessChecker) CheckReady(context.Context) error {
	panic("readiness panic")
}

func TestServerRejectsTypedNilInterfaceDependency(t *testing.T) {
	now, descriptor, catalog, _, _, _ := receiptDeliveryFixture(t)
	var checker *testReadinessChecker
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{ChainReadiness: checker},
	)
	if err == nil || server != nil {
		t.Fatal("typed-nil Edge dependency accepted")
	}
}

type testReceiptAuthorizer struct {
	scope journal.Scope
	err   error
	panic bool
	calls int
	bound bool
}

func (authorizer *testReceiptAuthorizer) AuthorizeReceiptAccess(
	ctx context.Context,
	request *http.Request,
	_ string,
) (journal.Scope, error) {
	authorizer.calls++
	_, contextBound := ctx.Deadline()
	_, requestBound := request.Context().Deadline()
	authorizer.bound = contextBound && requestBound
	if authorizer.panic {
		panic("private receipt authorizer failure")
	}
	return authorizer.scope, authorizer.err
}

type testReceiptSource struct {
	receipt journal.ReceiptRecord
	err     error
	panic   bool
	calls   int
}

type testActionStatusAuthorizer struct {
	scope journal.Scope
	err   error
	panic bool
	calls int
	bound bool
}

type testPaidActionErrorReporter struct {
	stage string
	err   error
	panic bool
}

func (reporter *testPaidActionErrorReporter) ReportPaidActionError(
	_ context.Context,
	stage string,
	err error,
) {
	if reporter.panic {
		panic("reporter panic")
	}
	reporter.stage = stage
	reporter.err = err
}

func TestPaidActionErrorReporterIsServerSideAndPanicContained(t *testing.T) {
	reporter := &testPaidActionErrorReporter{}
	server := &Server{paidActionErrors: reporter}
	expected := errors.New("internal failure")
	server.reportPaidActionError(context.Background(), "process", expected)
	if reporter.stage != "process" || !errors.Is(reporter.err, expected) {
		t.Fatalf("unexpected diagnostic: stage=%q err=%v", reporter.stage, reporter.err)
	}
	reporter.panic = true
	server.reportPaidActionError(context.Background(), "process", expected)
}

func (authorizer *testActionStatusAuthorizer) AuthorizeActionStatus(
	ctx context.Context,
	request *http.Request,
	_ string,
) (journal.Scope, error) {
	authorizer.calls++
	_, contextBound := ctx.Deadline()
	_, requestBound := request.Context().Deadline()
	authorizer.bound = contextBound && requestBound
	if authorizer.panic {
		panic("private action status authorization failure")
	}
	return authorizer.scope, authorizer.err
}

func (source *testReceiptSource) Receipt(journal.Scope) (journal.ReceiptRecord, error) {
	source.calls++
	if source.panic {
		panic("private receipt source failure")
	}
	return source.receipt, source.err
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
	response, err = http.Post(
		httpServer.URL+"/tos/v1/actions", "application/json",
		strings.NewReader(`{}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("paid action unexpectedly exposed: %d", response.StatusCode)
	}

	response, err = http.Get(httpServer.URL + "/tos/v1/receipts/receipt-0001")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("receipt delivery unexpectedly exposed: %d", response.StatusCode)
	}
	response, err = http.Get(httpServer.URL + "/tos/v1/actions/request-0001")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		t.Fatalf("action status unexpectedly exposed: %d", response.StatusCode)
	}
}

func TestActionStatusRequiresCoreAndReturnsBoundedPendingState(t *testing.T) {
	now, descriptor, catalog, scope, _, _ := receiptDeliveryFixture(t)
	authorizer := &testActionStatusAuthorizer{scope: scope}
	if _, err := NewServerWithDependencies(
		descriptor, catalog, now,
		ServerDependencies{ActionStatusAuthorizer: authorizer},
	); err == nil {
		t.Fatal("action status authorizer without Edge Core was accepted")
	}
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "action-status.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	if _, _, err := core.BeginRequest(
		scope, "sha256:"+strings.Repeat("a", 64), now.Add(time.Hour),
	); err != nil {
		t.Fatal(err)
	}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			Core: core, ActionStatusAuthorizer: authorizer,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/tos/v1/actions/"+scope.RequestID, nil,
	))
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != ActionStatusMediaType ||
		response.Header().Get("Cache-Control") != "no-store" ||
		authorizer.calls != 1 || !authorizer.bound {
		t.Fatalf(
			"pending action status=%d headers=%v auth=%d/%v body=%s",
			response.Code, response.Header(), authorizer.calls,
			authorizer.bound, response.Body.String(),
		)
	}
	var status publicActionStatus
	if err := json.Unmarshal(response.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.Version != protocol.BaseEnvelopeVersion ||
		status.ActionID != scope.RequestID || status.Status != journal.StatePending ||
		status.Receipt != nil {
		t.Fatalf("unexpected pending action status: %#v", status)
	}
	for _, target := range []string{
		"/tos/v1/actions/short",
		"/tos/v1/actions/" + scope.RequestID + "?detail=1",
	} {
		before := authorizer.calls
		blocked := httptest.NewRecorder()
		server.Routes().ServeHTTP(blocked, httptest.NewRequest(
			http.MethodGet, target, nil,
		))
		if blocked.Code != http.StatusNotFound || authorizer.calls != before {
			t.Fatalf("malformed action status reached authorization: %s %#v", target, blocked)
		}
	}
}

func TestActionStatusHidesAuthorizationAndLookupFailures(t *testing.T) {
	now, descriptor, catalog, scope, _, _ := receiptDeliveryFixture(t)
	config := DefaultCoreConfig(filepath.Join(t.TempDir(), "action-status.db"))
	config.CleanupInterval = time.Hour
	core, err := openCore(config, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer core.Close()
	wrong := scope
	wrong.RequestID = "request-other"
	for name, authorizer := range map[string]*testActionStatusAuthorizer{
		"denied":   {scope: scope, err: errors.New("private denial")},
		"panicked": {scope: scope, panic: true},
		"mismatch": {scope: wrong},
	} {
		t.Run(name, func(t *testing.T) {
			server, serverErr := NewServerWithDependencies(
				descriptor, catalog, now, ServerDependencies{
					Core: core, ActionStatusAuthorizer: authorizer,
				},
			)
			if serverErr != nil {
				t.Fatal(serverErr)
			}
			response := httptest.NewRecorder()
			server.Routes().ServeHTTP(response, httptest.NewRequest(
				http.MethodGet, "/tos/v1/actions/"+scope.RequestID, nil,
			))
			if response.Code != http.StatusNotFound ||
				strings.Contains(response.Body.String(), "private") {
				t.Fatalf("action status authorization leaked: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestReceiptDeliveryRequiresCompleteExplicitDependencies(t *testing.T) {
	now, descriptor, catalog, scope, _, _ := receiptDeliveryFixture(t)
	for name, dependencies := range map[string]ServerDependencies{
		"authorizer-only": {ReceiptAuthorizer: &testReceiptAuthorizer{scope: scope}},
		"source-only":     {ReceiptSource: &testReceiptSource{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewServerWithDependencies(
				descriptor, catalog, now, dependencies,
			); err == nil {
				t.Fatal("partial receipt delivery dependencies accepted")
			}
		})
	}
}

func TestReceiptDeliveryReturnsOnlyExactSignedEnvelope(t *testing.T) {
	now, descriptor, catalog, scope, receipt, envelope := receiptDeliveryFixture(t)
	authorizer := &testReceiptAuthorizer{scope: scope}
	source := &testReceiptSource{receipt: receipt}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			ReceiptAuthorizer: authorizer, ReceiptSource: source,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(
		http.MethodGet, "/tos/v1/receipts/"+receipt.ReceiptID, nil,
	)
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		response.Header().Get("Content-Type") != SignedEnvelopeMediaType ||
		response.Header().Get("Cache-Control") != "no-store" ||
		authorizer.calls != 1 || !authorizer.bound || source.calls != 1 {
		t.Fatalf(
			"unexpected receipt delivery: status=%d auth=%d source=%d headers=%v body=%s",
			response.Code, authorizer.calls, source.calls, response.Header(), response.Body.String(),
		)
	}
	var delivered identity.Envelope
	if err := json.Unmarshal(response.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	deliveredDigest, err := delivered.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	expectedDigest, err := envelope.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if deliveredDigest != expectedDigest ||
		len(response.Body.Bytes()) >= len(mustMarshalJSON(t, receipt)) {
		t.Fatal("receipt delivery exposed the wrong document or journal metadata")
	}
}

func TestReceiptDeliveryContainsSourcePanics(t *testing.T) {
	now, descriptor, catalog, scope, receipt, _ := receiptDeliveryFixture(t)
	authorizer := &testReceiptAuthorizer{scope: scope}
	source := &testReceiptSource{receipt: receipt, panic: true}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			ReceiptAuthorizer: authorizer, ReceiptSource: source,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/tos/v1/receipts/"+receipt.ReceiptID, nil,
	))
	if response.Code != http.StatusServiceUnavailable ||
		strings.Contains(response.Body.String(), "private") {
		t.Fatalf("source panic escaped: %d %s", response.Code, response.Body.String())
	}
}

func TestReceiptDeliveryHidesAuthorizationAndLookupFailures(t *testing.T) {
	now, descriptor, catalog, scope, receipt, _ := receiptDeliveryFixture(t)
	wrongService := scope
	wrongService.ServiceID = "other.example.ai"
	for name, authorizer := range map[string]*testReceiptAuthorizer{
		"denied":        {scope: scope, err: errors.New("private denial")},
		"panicked":      {scope: scope, panic: true},
		"wrong-service": {scope: wrongService},
	} {
		t.Run(name, func(t *testing.T) {
			source := &testReceiptSource{receipt: receipt}
			server, err := NewServerWithDependencies(
				descriptor, catalog, now, ServerDependencies{
					ReceiptAuthorizer: authorizer, ReceiptSource: source,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Routes().ServeHTTP(response, httptest.NewRequest(
				http.MethodGet, "/tos/v1/receipts/"+receipt.ReceiptID, nil,
			))
			if response.Code != http.StatusNotFound || source.calls != 0 ||
				strings.Contains(response.Body.String(), "private") {
				t.Fatalf("authorization failure leaked: %d %s", response.Code, response.Body.String())
			}
		})
	}

	authorizer := &testReceiptAuthorizer{scope: scope}
	source := &testReceiptSource{err: journal.ErrNotFound}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			ReceiptAuthorizer: authorizer, ReceiptSource: source,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/tos/v1/receipts/"+receipt.ReceiptID, nil,
	))
	if response.Code != http.StatusNotFound ||
		strings.Contains(response.Body.String(), "journal") {
		t.Fatalf("lookup failure leaked: %d %s", response.Code, response.Body.String())
	}
}

func TestReceiptDeliveryRejectsMalformedIDBeforeAuthorization(t *testing.T) {
	now, descriptor, catalog, scope, receipt, _ := receiptDeliveryFixture(t)
	authorizer := &testReceiptAuthorizer{scope: scope}
	source := &testReceiptSource{receipt: receipt}
	server, err := NewServerWithDependencies(
		descriptor, catalog, now, ServerDependencies{
			ReceiptAuthorizer: authorizer, ReceiptSource: source,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.Routes().ServeHTTP(response, httptest.NewRequest(
		http.MethodGet, "/tos/v1/receipts/short", nil,
	))
	if response.Code != http.StatusNotFound || authorizer.calls != 0 || source.calls != 0 {
		t.Fatalf("malformed receipt ID reached dependencies: %#v", response)
	}
}

func TestReceiptDeliveryFailsClosedOnSourceBindingMismatch(t *testing.T) {
	for name, mutate := range map[string]func(*journal.ReceiptRecord){
		"scope": func(receipt *journal.ReceiptRecord) {
			receipt.Scope.RequestID = "request-other"
		},
		"receipt-id": func(receipt *journal.ReceiptRecord) {
			receipt.ReceiptID = "receipt-other"
		},
		"envelope-digest": func(receipt *journal.ReceiptRecord) {
			receipt.ReceiptEnvelopeDigest = "sha256:" + strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			now, descriptor, catalog, scope, receipt, _ := receiptDeliveryFixture(t)
			requestedReceiptID := receipt.ReceiptID
			mutate(&receipt)
			authorizer := &testReceiptAuthorizer{scope: scope}
			source := &testReceiptSource{receipt: receipt}
			server, err := NewServerWithDependencies(
				descriptor, catalog, now, ServerDependencies{
					ReceiptAuthorizer: authorizer, ReceiptSource: source,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			server.Routes().ServeHTTP(response, httptest.NewRequest(
				http.MethodGet, "/tos/v1/receipts/"+requestedReceiptID, nil,
			))
			if response.Code != http.StatusServiceUnavailable ||
				strings.Contains(response.Body.String(), scope.RequestID) {
				t.Fatalf(
					"source binding mismatch failed open: %d %s",
					response.Code, response.Body.String(),
				)
			}
		})
	}
}

func receiptDeliveryFixture(t *testing.T) (
	time.Time,
	protocol.ServiceDescriptor,
	ard.Catalog,
	journal.Scope,
	journal.ReceiptRecord,
	identity.Envelope,
) {
	t.Helper()
	now := time.Unix(1_800_000_000, 0).UTC()
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
	catalog := ard.Catalog{SpecVersion: ard.SpecVersion}
	scope := journal.Scope{
		Network: "testnet", Authority: "runtime-key-1",
		ServiceID: descriptor.ServiceID, SessionID: "session-0001",
		Operation: "generate", RequestID: "request-0001",
	}
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := identity.Sign(
		privateKey, protocol.ReceiptDomain, "receipt-key-1", []byte{0xa0},
		now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := envelope.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	receipt := journal.ReceiptRecord{
		Scope: scope, ReceiptID: "receipt-0001", Envelope: envelope,
		ReceiptEnvelopeDigest: digest,
	}
	return now, descriptor, catalog, scope, receipt, envelope
}

func mustMarshalJSON(t *testing.T, value any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
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

func TestReadinessGateContainsCheckerPanic(t *testing.T) {
	gate := newReadinessGate(panickingReadinessChecker{})
	now := time.Now().UTC()
	if err := gate.check(context.Background(), now); err == nil {
		t.Fatal("readiness checker panic escaped")
	}
	if err := gate.check(context.Background(), now); err == nil ||
		errors.Is(err, errReadinessProbeBusy) {
		t.Fatalf("readiness gate remained busy after panic: %v", err)
	}
}
