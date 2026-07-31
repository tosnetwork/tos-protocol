package conformance_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestAllBaseSchemasCompile(t *testing.T) {
	base := baseSpecDirectory(t)
	files, err := filepath.Glob(filepath.Join(base, "*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 12 {
		t.Fatalf("found only %d base schemas", len(files))
	}
	for _, file := range files {
		file := file
		t.Run(filepath.Base(file), func(t *testing.T) {
			compiler := jsonschema.NewCompiler()
			compiler.AssertFormat()
			if _, err := compiler.Compile(fileURL(file)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGoValuesConformToPublishedSchemas(t *testing.T) {
	now := time.Date(2027, 1, 15, 12, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	profile := protocol.ProfileReference{
		ID: "tos.ai.inference", Version: "0.1.0",
		MediaType: "application/vnd.tos.ai-inference+json",
		URL:       "https://edge.example/.well-known/inference.json", Digest: digest,
	}
	quote := protocol.Quote{
		Version: protocol.BaseEnvelopeVersion, QuoteID: "quote-0001", RequestID: "request-0001",
		SessionID: "session-0001",
		ServiceID: "edge.example.ai", ProfileID: profile.ID, Operation: "INVOKE",
		IntentDigest:    digest,
		ServiceRevision: "service-1", ResourceRevision: "model-1", PriceNanoTOS: 100,
		Network: "testnet", Payee: "payee-key-1", Settlement: "service-actor-request-1",
		MaxInputBytes: 1024, MaxOutputBytes: 2048, IssuedAt: now, Deadline: now.Add(time.Minute),
		ExpiresAt: now.Add(30 * time.Second),
		ResourceLimits: []protocol.ResourceLimit{{
			ID: "memory.ram", Unit: protocol.ResourceUnitBytes, Quantity: 4 << 30,
		}},
	}
	authorization := protocol.PaymentAuthorization{
		Version: protocol.BaseEnvelopeVersion, AuthorizationID: "authorization-0001",
		QuoteID: quote.QuoteID, RequestID: quote.RequestID, Network: "testnet",
		Payer: "payer-key-1", Payee: "payee-key-1", MaxNanoTOS: 100,
		Reference: quote.Settlement, ExpiresAt: now.Add(25 * time.Second),
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := identity.Sign(
		privateKey, "tos.quote.v1", "runtime-key-1", []byte{0xa0},
		now, now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	claimEvidence := protocol.ClaimEvidence{
		Level: protocol.EvidenceObserved, Issuer: "runtime-key-1",
		CollectedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	cases := map[string]interface{}{
		"signed-envelope.schema.json": envelope,
		"service-descriptor.schema.json": protocol.ServiceDescriptor{
			ProtocolVersion: protocol.DescriptorVersion, ServiceID: quote.ServiceID,
			DisplayName: "Example edge", Controller: "tos:test:controller",
			Network: "testnet", Revision: "descriptor-1", ExpiresAt: now.Add(time.Hour),
			Profiles: []protocol.ProfileReference{profile},
		},
		"profile-reference.schema.json": profile,
		"resource-limit.schema.json":    quote.ResourceLimits[0],
		"terminal-manifest.schema.json": protocol.TerminalManifest{
			Version: protocol.TerminalManifestVersion, TerminalID: "terminal-0001",
			ServiceID: quote.ServiceID, Network: "testnet", Revision: "terminal-1",
			PolicyRevision: "owner-policy-1", CollectedAt: now,
			ExpiresAt: now.Add(time.Minute),
			Readiness: []protocol.ReadinessComponent{{
				ID: "runtime.ollama", Status: protocol.ReadinessReady,
				Revision: "0.11.0", Evidence: claimEvidence,
			}},
			Resources: []protocol.ResourceClaim{{
				ID: "memory.host", Class: protocol.ResourceMemory,
				Unit: protocol.ResourceUnitBytes, Total: 64 << 30,
				OwnerReserved: 16 << 30, AvailableExternal: 32 << 30,
				Revision: "probe-v1", Evidence: claimEvidence,
				Attributes: map[string]string{"architecture.name": "amd64"},
			}},
		},
		"capability.schema.json": protocol.CapabilityClaim{
			ID: "tos.ai.generate", Revision: "model-1",
			Evidence: protocol.EvidenceBenchmarked, Attributes: map[string]string{"runtime": "stub"},
		},
		"service-manifest.schema.json": protocol.ServiceManifest{
			Version: protocol.ManifestVersion, ManifestID: "manifest-0001",
			ServiceID: quote.ServiceID, Controller: "tos:test:controller",
			Network: "testnet", Revision: "manifest-1", IssuedAt: now,
			ExpiresAt: now.Add(time.Hour),
			RuntimeKeys: []protocol.RuntimeKey{{
				KeyID: "runtime-key-1", Algorithm: "Ed25519",
				PublicKey: strings.Repeat("A", 43), Roles: []string{"authenticate", "quote"},
				NotBefore: now, NotAfter: now.Add(time.Hour),
			}},
			Endpoints: []protocol.ServiceEndpoint{{
				Transport: "https", Audience: "authenticated", URL: "https://edge.example/v1",
			}},
			Profiles: []protocol.ProfileReference{profile},
		},
		"quote.schema.json":                 quote,
		"payment-authorization.schema.json": authorization,
		"receipt.schema.json": protocol.Receipt{
			Version: protocol.BaseEnvelopeVersion, ReceiptID: "receipt-0001",
			RequestID: quote.RequestID, QuoteID: quote.QuoteID,
			AuthorizationID: authorization.AuthorizationID, ServiceID: quote.ServiceID,
			Status: "succeeded", Usage: []protocol.UsageItem{{Unit: "tokens", Quantity: 10}},
			ChargedNanoTOS: 100, ResultDigest: digest, ServiceRevision: quote.ServiceRevision,
			ResourceRevision: quote.ResourceRevision, CompletedAt: now.Add(50 * time.Second),
		},
		"evidence.schema.json": protocol.EvidenceBundle{
			Version: protocol.BaseEnvelopeVersion, BundleID: "evidence-0001",
			RequestID: quote.RequestID, Claims: []protocol.EvidenceClaim{{
				Type: "tos.ai.model", Level: protocol.EvidenceAttested,
				Subject: "model:qwen", Issuer: "attestor-key-1", CollectedAt: now,
				ExpiresAt: now.Add(time.Hour), Digest: digest,
			}},
		},
		"error.schema.json": protocol.ProtocolError{
			Code: protocol.ErrorResourceExhausted, Message: "capacity unavailable",
			Retry: protocol.RetryAfterDelay, RetryAfterMillis: 1000,
		},
		"session.schema.json": protocol.SessionGrant{
			Version: protocol.BaseEnvelopeVersion, SessionID: "session-0001",
			ServiceID: quote.ServiceID, ProfileID: profile.ID, Client: "client-key-1",
			RuntimeKeyID: "runtime-key-1", ManifestRevision: "manifest-1",
			Operations: []string{"INVOKE", "CANCEL"}, MaxRequests: 10,
			MaxNanoTOS: 1000, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
		},
		"delegation.schema.json": protocol.Delegation{
			Version: protocol.BaseEnvelopeVersion, DelegationID: "delegation-0001",
			Issuer: "owner-key-1", Subject: "controller-key-1", Audience: quote.ServiceID,
			Scopes: []string{"tos.ai.invoke"}, MaxNanoTOS: 1000, MaxActions: 10,
			NotBefore: now, ExpiresAt: now.Add(time.Hour),
		},
		"profile-negotiation.schema.json": protocol.ProfileRequest{
			ID: profile.ID, SupportedVersions: []string{"0.1.0"},
			SupportedExtensions: []string{"urn:tos:extension:receipts"},
		},
	}
	base := baseSpecDirectory(t)
	for filename, value := range cases {
		t.Run(filename, func(t *testing.T) {
			schema := compileSchema(t, filepath.Join(base, filename))
			document := jsonValue(t, value)
			if err := schema.Validate(document); err != nil {
				t.Fatalf("Go value does not conform: %v\n%#v", err, document)
			}
		})
	}
}

func TestSchemasRejectUnknownFields(t *testing.T) {
	schema := compileSchema(t, filepath.Join(baseSpecDirectory(t), "quote.schema.json"))
	value := jsonValue(t, map[string]interface{}{
		"version": "0.1", "quoteId": "quote-0001", "requestId": "request-0001",
		"sessionId": "session-0001",
		"serviceId": "edge.example.ai", "profileId": "tos.ai.inference",
		"operation": "INVOKE", "intentDigest": "sha256:" + strings.Repeat("a", 64),
		"serviceRevision": "service-1", "resourceRevision": "model-1",
		"network": "testnet", "payee": "payee-key-1", "settlement": "settlement-1",
		"priceNanoTos":  0,
		"maxInputBytes": 1, "maxOutputBytes": 1,
		"issuedAt": "2027-01-15T12:00:00Z",
		"deadline": "2027-01-15T12:01:00Z", "expiresAt": "2027-01-15T12:00:30Z",
		"unexpected": true,
	})
	if err := schema.Validate(value); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func compileSchema(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	schema, err := compiler.Compile(fileURL(path))
	if err != nil {
		t.Fatal(err)
	}
	return schema
}

func jsonValue(t *testing.T, value interface{}) interface{} {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var output interface{}
	if err := json.Unmarshal(data, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

func baseSpecDirectory(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate conformance test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", "..", "spec", "base"))
}

func fileURL(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		panic(err)
	}
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute)}).String()
}
