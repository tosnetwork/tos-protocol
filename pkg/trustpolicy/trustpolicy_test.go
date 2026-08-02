package trustpolicy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestWorkloadVerifierExactSPIFFEIdentity(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	root, leaf := issueWorkloadCertificate(t, now, "spiffe://operator.example/workload/worker-1")
	pool := x509.NewCertPool()
	pool.AddCert(root)
	verifier, err := NewWorkloadVerifier("operator.example", pool)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := verifier.Verify([]*x509.Certificate{leaf}, "spiffe://operator.example/workload/worker-1", now)
	if err != nil || principal.SPIFFEID != "spiffe://operator.example/workload/worker-1" {
		t.Fatalf("unexpected verification result: %#v, %v", principal, err)
	}
	for name, chain := range map[string][]*x509.Certificate{
		"nil leaf": {nil},
		"too long": append([]*x509.Certificate{leaf}, make([]*x509.Certificate, MaxCertificateChain)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(chain, principal.SPIFFEID, now); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	if _, err := verifier.Verify([]*x509.Certificate{leaf}, "spiffe://operator.example/workload/worker-2", now); err == nil {
		t.Fatal("accepted a different workload identity")
	}
	if _, err := verifier.Verify([]*x509.Certificate{leaf}, principal.SPIFFEID, leaf.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("accepted an expired certificate")
	}
}

func TestProvenanceVerifierAndArtifactBounds(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("immutable artifact")
	digest := digestOf(artifact)
	statement := ProvenanceStatement{
		Version: ArtifactProvenanceVersion, ArtifactDigest: digest, Subject: "worker-linux-amd64",
		BuilderID: "builder://release", SourceDigest: digestOf([]byte("source")), Materials: []string{digestOf([]byte("toolchain"))},
	}
	envelope, err := identity.SignCanonical(privateKey, ArtifactProvenanceDomain, "release-key", statement, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewProvenanceVerifier(map[string]ProvenanceTrust{
		"release-key": {PublicKey: publicKey, BuilderID: "builder://release", AllowedSubjects: []string{"worker-linux-amd64"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyEnvelope(envelope, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyEnvelope(envelope, digestOf([]byte("other")), now); err == nil {
		t.Fatal("accepted a provenance statement for another artifact")
	}
	if err := VerifyArtifact(bytes.NewReader(artifact), int64(len(artifact)), digest); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(bytes.NewReader(append(artifact, '!')), int64(len(artifact)), digest); err == nil {
		t.Fatal("accepted an artifact over the configured bound")
	}
}

func TestEvidenceVerifierTrustAndRequirements(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := protocol.EvidenceBundle{Version: protocol.BaseEnvelopeVersion, BundleID: "bundle-0001", Claims: []protocol.EvidenceClaim{{
		Type: "gpu.benchmark", Level: protocol.EvidenceBenchmarked, Subject: "device-pool-a", Issuer: "lab.example",
		CollectedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour), Digest: digestOf([]byte("benchmark")),
	}}}
	envelope, err := identity.SignCanonical(privateKey, EvidenceEnvelopeDomain, "lab-key", bundle, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewEvidenceVerifier(map[string]EvidenceIssuer{"lab-key": {
		PublicKey: publicKey, Issuer: "lab.example", AllowedTypes: []string{"gpu.benchmark"}, MaximumLevel: protocol.EvidenceBenchmarked,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(envelope, []EvidenceRequirement{{Type: "gpu.benchmark", Subject: "device-pool-a", MinimumLevel: protocol.EvidenceObserved}}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(envelope, []EvidenceRequirement{{Type: "gpu.benchmark", Subject: "device-pool-a", MinimumLevel: protocol.EvidenceAudited}}, now); err == nil {
		t.Fatal("accepted evidence below the required level")
	}
	overclaimed := bundle
	overclaimed.Claims = append([]protocol.EvidenceClaim(nil), bundle.Claims...)
	overclaimed.Claims[0].Level = protocol.EvidenceAudited
	overclaimedEnvelope, err := identity.SignCanonical(privateKey, EvidenceEnvelopeDomain, "lab-key", overclaimed, now.Add(-time.Minute), now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(overclaimedEnvelope, nil, now); err == nil {
		t.Fatal("accepted a level the issuer is not trusted to assert")
	}
}

func TestOPAClientAndStaticEvaluator(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	input := DecisionInput{WorkloadID: "spiffe://operator.example/worker/1", ServiceID: "ai.inference", Operation: "invoke"}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer secret-token" || request.Header.Get("Content-Type") != "application/json" {
			t.Error("missing authenticated JSON request")
		}
		var received struct {
			Input DecisionInput `json:"input"`
		}
		decoder := json.NewDecoder(request.Body)
		if err := decoder.Decode(&received); err != nil || received.Input.WorkloadID != input.WorkloadID {
			t.Errorf("unexpected request: %#v, %v", received, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]Decision{"result": {Allow: true, Revision: "policy-7", ExpiresAt: now.Add(time.Hour)}})
	}))
	defer server.Close()
	client, err := NewOPAClient(server.URL, "secret-token", server.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := client.Evaluate(context.Background(), input, now)
	if err != nil || !decision.Allow || decision.Revision != "policy-7" {
		t.Fatalf("unexpected policy decision: %#v, %v", decision, err)
	}

	static, err := NewStaticEvaluator([]StaticRule{{Input: input, Allow: true}}, "offline-1", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	decision, err = static.Evaluate(context.Background(), input, now)
	if err != nil || !decision.Allow {
		t.Fatalf("unexpected static decision: %#v, %v", decision, err)
	}
	input.Operation = "admin"
	decision, err = static.Evaluate(context.Background(), input, now)
	if err != nil || decision.Allow {
		t.Fatalf("unknown tuple did not fail closed: %#v, %v", decision, err)
	}
	if _, err := NewStaticEvaluator([]StaticRule{{Input: input}, {Input: input}}, "duplicate", time.Hour); err == nil {
		t.Fatal("accepted duplicate static rules")
	}
}

func TestOPAClientCapacityFailsClosed(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"result":{"allow":true,"revision":"r1","expiresAt":"2026-08-02T13:00:00Z"}}`))
	}))
	defer server.Close()
	client, err := NewOPAClient(server.URL, "token", server.Client(), 1)
	if err != nil {
		t.Fatal(err)
	}
	input := DecisionInput{WorkloadID: "worker", ServiceID: "service", Operation: "invoke"}
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	done := make(chan error, 1)
	go func() { _, err := client.Evaluate(context.Background(), input, now); done <- err }()
	<-entered
	if _, err := client.Evaluate(context.Background(), input, now); err == nil {
		t.Fatal("accepted a request after policy capacity was exhausted")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func issueWorkloadCertificate(t *testing.T, now time.Time, identityURI string) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, BasicConstraintsValid: true}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	parsedURI, err := url.Parse(identityURI)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "workload"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{parsedURI},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf
}

func digestOf(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func TestOPAClientConcurrentConstruction(t *testing.T) {
	// The transport is cloned by NewOPAClient; callers may safely reuse their
	// source client while policy calls are in flight.
	source := &http.Client{}
	var wait sync.WaitGroup
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if _, err := NewOPAClient("http://127.0.0.1/policy", "token", source, 1); err != nil {
				t.Error(err)
			}
		}()
	}
	wait.Wait()
}
