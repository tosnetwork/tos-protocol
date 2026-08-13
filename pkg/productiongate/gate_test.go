package productiongate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGatePassesCompleteLocalProductionShapeAndFailsClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	const deploymentID, network, gatewayDomain = "atos-production-a", "tos-test", "atos.im"
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			_, _ = w.Write([]byte("atos_reconciler_healthy 1\natos_protocol_quorum_healthy 1\natos_proof_reconciliation_lag_seconds 0\natos_verified_unresolved_operations 0\natos_settlement_failures 0\n"))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/key/") {
			purpose := strings.TrimPrefix(r.URL.Path, "/key/")
			_, _ = fmt.Fprintf(w, `{"version":"tos_phase4d_custody_health_v1","purpose":%q,"backend":"hsm","key_id":%q,"healthy":true}`, purpose, "key-"+purpose)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	dir := t.TempDir()
	evidence := func(name, subject, result string) Evidence {
		path := filepath.Join(dir, name)
		completed := now.Add(-time.Hour).Unix()
		content, err := json.Marshal(evidenceDocument{Version: EvidenceVersion, Subject: subject, DeploymentID: deploymentID, Network: network, GatewayDomain: gatewayDomain, CompletedUnix: completed, Result: result})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o400); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		entry := Evidence{Subject: subject, Path: path, SHA256: "sha256:" + hex.EncodeToString(sum[:]), CompletedUnix: completed, MaximumAgeSeconds: 86400, SignerID: "phase4d-auditor", PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey)}
		message := fmt.Sprintf("TOS-PHASE4D-EVIDENCE-V1\x00%s\x00%s\x00%s\x00%s\x00%s\x00%d\x00%d\x00%s", deploymentID, network, gatewayDomain, entry.Subject, entry.SHA256, entry.CompletedUnix, entry.MaximumAgeSeconds, entry.SignerID)
		entry.SignatureBase64 = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(message)))
		return entry
	}
	proofPath := filepath.Join(dir, "proof.cbor")
	if err := os.WriteFile(proofPath, []byte("portable-proof"), 0o400); err != nil {
		t.Fatal(err)
	}
	proofSum := sha256.Sum256([]byte("portable-proof"))
	readySum := sha256.Sum256([]byte("ok"))
	readyDigest := "sha256:" + hex.EncodeToString(readySum[:])
	m := Manifest{Version: Version, DeploymentID: deploymentID, Network: network, GatewayDomain: gatewayDomain, ProtocolObserverURL: server.URL,
		ATOSReplicas:     []Endpoint{{"atos-1", "ops-a", server.URL + "/a1", readyDigest}, {"atos-2", "ops-b", server.URL + "/a2", readyDigest}},
		ProtocolReplicas: []Endpoint{{"proto-1", "ops-a", server.URL + "/p1", readyDigest}, {"proto-2", "ops-b", server.URL + "/p2", readyDigest}},
		ChainEndpoints:   []Endpoint{{"chain-1", "validator-a", server.URL + "/c1", readyDigest}, {"chain-2", "validator-b", server.URL + "/c2", readyDigest}, {"chain-3", "validator-c", server.URL + "/c3", readyDigest}}, ChainQuorum: 2,
		AgentCodeHashes: []string{"tvm-cell-sha256:" + strings.Repeat("1", 64)}, EscrowCodeHashes: []string{"tvm-cell-sha256:" + strings.Repeat("2", 64)},
		Monitoring: Monitoring{URL: server.URL + "/metrics", RequiredMetrics: []MetricRequirement{
			{Name: "atos_reconciler_healthy", Minimum: float64Pointer(1), Maximum: float64Pointer(1)},
			{Name: "atos_protocol_quorum_healthy", Minimum: float64Pointer(1), Maximum: float64Pointer(1)},
			{Name: "atos_proof_reconciliation_lag_seconds", Maximum: float64Pointer(30)},
			{Name: "atos_verified_unresolved_operations", Maximum: float64Pointer(0)},
			{Name: "atos_settlement_failures", Maximum: float64Pointer(0)},
		}},
		Reconciliation: evidence("reconciliation.json", "reconciliation", "passed"), Backup: evidence("backup.json", "backup", "passed"), RestoreDrill: evidence("restore.json", "restore-drill", "passed"), IncidentDrill: evidence("incident.json", "incident-drill", "passed"),
		Proof: Proof{Path: proofPath, SHA256: "sha256:" + hex.EncodeToString(proofSum[:])}}
	for _, purpose := range []string{"quote", "receipt", "task-escrow", "chain-action"} {
		subject := "custody:" + purpose + ":hsm:key-" + purpose
		m.Custody = append(m.Custody, Custody{Purpose: purpose, Backend: "hsm", KeyID: "key-" + purpose, HealthURL: server.URL + "/key/" + purpose, Evidence: evidence("key-"+purpose+".json", subject, "passed")})
	}
	auditor := Auditor{HTTPClient: server.Client(), Now: func() time.Time { return now }, AllowLoopback: true, VerifyProof: func(_ context.Context, got []byte, manifest Manifest) error {
		if string(got) != "portable-proof" {
			t.Fatal("wrong proof")
		}
		return nil
	}}
	if report := auditor.Audit(context.Background(), m); !report.Passed {
		t.Fatalf("report=%+v", report)
	}

	bad := cloneManifest(t, m)
	bad.ChainEndpoints[2].Operator = bad.ChainEndpoints[0].Operator
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("non-diverse chain quorum passed")
	}
	bad = cloneManifest(t, m)
	bad.Backup.CompletedUnix = now.Add(-48 * time.Hour).Unix()
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("stale backup evidence passed")
	}
	bad = cloneManifest(t, m)
	bad.Custody[0].Backend = "file"
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("file key custody passed production gate")
	}
	bad = cloneManifest(t, m)
	bad.Backup.SignatureBase64 = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("forged evidence signature passed")
	}
	bad = cloneManifest(t, m)
	bad.Backup = bad.Reconciliation
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("cross-purpose evidence replay passed")
	}
	bad = cloneManifest(t, m)
	bad.DeploymentID = "atos-production-b"
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("cross-deployment evidence replay passed")
	}
	bad = cloneManifest(t, m)
	bad.Reconciliation.MaximumAgeSeconds = maxReconciliationAge + 1
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("over-broad reconciliation freshness passed")
	}
	bad = cloneManifest(t, m)
	bad.Monitoring.RequiredMetrics[0].Minimum = float64Pointer(0)
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("weakened required monitoring threshold passed")
	}
	bad = cloneManifest(t, m)
	bad.Backup = evidence("failed-backup.json", "backup", "failed")
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("signed failed backup report passed")
	}
	bad = cloneManifest(t, m)
	bad.ATOSReplicas[0].ResponseSHA256 = "sha256:" + strings.Repeat("0", 64)
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("unexpected readiness body passed")
	}
	bad = cloneManifest(t, m)
	bad.ProtocolObserverURL = "https://remote.example.com"
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("local relaxation with remote boundary passed")
	}
	bad = cloneManifest(t, m)
	bad.Network = "tos-test\x00atos.im"
	if report := auditor.Audit(context.Background(), bad); report.Passed {
		t.Fatal("signature delimiter injection passed")
	}
	invalidProofAuditor := auditor
	invalidProofAuditor.VerifyProof = func(context.Context, []byte, Manifest) error { return errors.New("invalid proof") }
	if report := invalidProofAuditor.Audit(context.Background(), m); report.Passed {
		t.Fatal("invalid independent proof passed")
	}
}

func cloneManifest(t *testing.T, source Manifest) Manifest {
	t.Helper()
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var clone Manifest
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func float64Pointer(value float64) *float64 { return &value }

func TestGateRejectsInsecureURLsAndTamperedEvidence(t *testing.T) {
	if err := secureURL("http://example.com/health", false); err == nil {
		t.Fatal("plaintext remote URL accepted")
	}
	if err := secureURL("http://127.0.0.1/health", true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "evidence")
	if err := os.WriteFile(path, []byte("actual"), 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := readDigestFile(path, "sha256:"+strings.Repeat("0", 64)); err == nil {
		t.Fatal("tampered evidence accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("actual"))
	if _, err := readDigestFile(path, "sha256:"+hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("writable evidence accepted")
	}
}

func TestProductionTopologyRequiresDistinctOrigins(t *testing.T) {
	endpoints := []Endpoint{
		{ID: "one", Operator: "operator-one", URL: "https://shared.example.com/one/readyz", ResponseSHA256: "sha256:" + strings.Repeat("1", 64)},
		{ID: "two", Operator: "operator-two", URL: "https://shared.example.com/two/readyz", ResponseSHA256: "sha256:" + strings.Repeat("1", 64)},
	}
	if err := uniqueEndpoints("protocol", endpoints, false, false); err == nil {
		t.Fatal("same-origin replicas passed production topology")
	}
	endpoints[1].URL = "https://independent.example.com/readyz"
	if err := uniqueEndpoints("protocol", endpoints, false, false); err != nil {
		t.Fatal(err)
	}
	endpoints[0].URL = "https://shared.example.com/readyz"
	endpoints[1].URL = "https://SHARED.EXAMPLE.COM.:443/other"
	if err := uniqueEndpoints("protocol", endpoints, false, false); err == nil {
		t.Fatal("equivalent default-port origin passed as distinct")
	}
}

func TestLoadRejectsUnknownAndTrailingManifestData(t *testing.T) {
	for name, body := range map[string]string{
		"unknown":   `{"version":"tos_phase4d_production_gate_v1","unknown":true}`,
		"duplicate": `{"version":"tos_phase4d_production_gate_v1","version":"attacker"}`,
		"trailing":  `{}` + "\n{}",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(path, []byte(body), 0o400); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("unsafe manifest passed")
			}
		})
	}
}

func TestLocalManifestTrustRelaxationIsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, []byte("{}"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := ValidateManifestTrust(path, true); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if err := ValidateManifestTrust(path, false); err == nil {
			t.Fatal("user-owned manifest passed production trust-root check")
		}
	}
}

func TestMonitoringRequiresExactMetricNamesAndRejectsRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("# atos_ready is only a comment\nother_atos_ready 1\n"))
	}))
	defer target.Close()
	if err := probe(context.Background(), target.Client(), target.URL, []MetricRequirement{{Name: "atos_ready", Minimum: float64Pointer(1)}}); err == nil {
		t.Fatal("metric substring passed")
	}
	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("atos_ready 0\n")) }))
	defer unhealthy.Close()
	if err := probe(context.Background(), unhealthy.Client(), unhealthy.URL, []MetricRequirement{{Name: "atos_ready", Minimum: float64Pointer(1)}}); err == nil {
		t.Fatal("unhealthy metric value passed")
	}
	redirect := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redirect.Close()
	if err := probe(context.Background(), redirect.Client(), redirect.URL, nil); err == nil {
		t.Fatal("redirected probe passed")
	}
}
