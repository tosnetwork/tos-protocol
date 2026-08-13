// Package productiongate implements the fail-closed Phase 4D deployment gate.
// It validates deployment diversity and immutable operator evidence, probes
// every required live boundary, and delegates portable-proof validation to an
// independent verifier. It performs no economic mutation.
package productiongate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	Version        = "tos_phase4d_production_gate_v1"
	maxBodyBytes   = 1 << 20
	maxConfigBytes = 1 << 20
	maxEvidenceAge = int64((10 * 365 * 24 * time.Hour) / time.Second)
)

type Endpoint struct {
	ID       string `json:"id"`
	Operator string `json:"operator"`
	URL      string `json:"url"`
}

type Custody struct {
	Purpose   string   `json:"purpose"`
	Backend   string   `json:"backend"`
	KeyID     string   `json:"key_id"`
	HealthURL string   `json:"health_url"`
	Evidence  Evidence `json:"evidence"`
}

type Evidence struct {
	Subject           string `json:"subject"`
	Path              string `json:"path"`
	SHA256            string `json:"sha256"`
	CompletedUnix     int64  `json:"completed_unix"`
	MaximumAgeSeconds int64  `json:"maximum_age_seconds"`
	SignerID          string `json:"signer_id"`
	PublicKeyBase64   string `json:"public_key_base64"`
	SignatureBase64   string `json:"signature_base64"`
}

type Monitoring struct {
	URL             string              `json:"url"`
	RequiredMetrics []MetricRequirement `json:"required_metrics"`
}

type MetricRequirement struct {
	Name    string   `json:"name"`
	Minimum *float64 `json:"minimum,omitempty"`
	Maximum *float64 `json:"maximum,omitempty"`
}

type Proof struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Version             string     `json:"version"`
	Network             string     `json:"network"`
	GatewayDomain       string     `json:"gateway_domain"`
	ProtocolObserverURL string     `json:"protocol_observer_url"`
	ATOSReplicas        []Endpoint `json:"atos_replicas"`
	ProtocolReplicas    []Endpoint `json:"protocol_replicas"`
	ChainEndpoints      []Endpoint `json:"chain_endpoints"`
	ChainQuorum         int        `json:"chain_quorum"`
	AgentCodeHashes     []string   `json:"agent_code_hashes"`
	EscrowCodeHashes    []string   `json:"escrow_code_hashes"`
	Custody             []Custody  `json:"custody"`
	Monitoring          Monitoring `json:"monitoring"`
	Reconciliation      Evidence   `json:"reconciliation"`
	Backup              Evidence   `json:"backup"`
	RestoreDrill        Evidence   `json:"restore_drill"`
	IncidentDrill       Evidence   `json:"incident_drill"`
	Proof               Proof      `json:"proof"`
}

type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
}

type Report struct {
	Version     string    `json:"version"`
	Network     string    `json:"network"`
	GeneratedAt time.Time `json:"generated_at"`
	Passed      bool      `json:"passed"`
	Checks      []Check   `json:"checks"`
}

type ProofVerifier func(context.Context, []byte, Manifest) error

type Auditor struct {
	HTTPClient    *http.Client
	Now           func() time.Time
	AllowLoopback bool
	VerifyProof   ProofVerifier
}

func Load(path string) (Manifest, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Manifest{}, errors.New("production gate manifest path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
		return Manifest{}, errors.New("production gate manifest must be a non-group/world-writable regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o022 != 0 {
		return Manifest{}, errors.New("production gate manifest changed while opening")
	}
	limited := io.LimitReader(file, maxConfigBytes+1)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("production gate manifest contains trailing data")
	}
	return manifest, nil
}

func (a Auditor) Audit(ctx context.Context, manifest Manifest) Report {
	now := time.Now().UTC()
	if a.Now != nil {
		now = a.Now().UTC()
	}
	report := Report{Version: Version, Network: manifest.Network, GeneratedAt: now, Passed: true}
	add := func(name string, err error) {
		check := Check{Name: name, Passed: err == nil}
		if err != nil {
			check.Detail = err.Error()
			report.Passed = false
		}
		report.Checks = append(report.Checks, check)
	}
	add("manifest", validateManifest(manifest, a.AllowLoopback))
	if !report.Passed {
		return report
	}
	client := a.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	for _, group := range [][]Endpoint{manifest.ATOSReplicas, manifest.ProtocolReplicas, manifest.ChainEndpoints} {
		for _, endpoint := range group {
			add("endpoint:"+endpoint.ID, probe(ctx, client, endpoint.URL, nil))
		}
	}
	for _, custody := range manifest.Custody {
		add("custody-health:"+custody.Purpose, probeCustody(ctx, client, custody))
		subject := fmt.Sprintf("custody:%s:%s:%s", custody.Purpose, custody.Backend, custody.KeyID)
		add("custody-evidence:"+custody.Purpose, verifyEvidence(custody.Evidence, now, subject))
	}
	add("monitoring", probe(ctx, client, manifest.Monitoring.URL, manifest.Monitoring.RequiredMetrics))
	add("reconciliation", verifyEvidence(manifest.Reconciliation, now, "reconciliation"))
	add("backup", verifyEvidence(manifest.Backup, now, "backup"))
	add("restore-drill", verifyEvidence(manifest.RestoreDrill, now, "restore-drill"))
	add("incident-drill", verifyEvidence(manifest.IncidentDrill, now, "incident-drill"))
	proof, err := readDigestFile(manifest.Proof.Path, manifest.Proof.SHA256)
	add("proof-package-digest", err)
	if err == nil {
		if a.VerifyProof == nil {
			err = errors.New("independent proof verifier is required")
		} else {
			err = a.VerifyProof(ctx, proof, manifest)
		}
		add("independent-proof", err)
	}
	return report
}

func validateManifest(m Manifest, allowLoopback bool) error {
	if m.Version != Version || strings.TrimSpace(m.Network) == "" || strings.TrimSpace(m.GatewayDomain) == "" {
		return errors.New("version, network and gateway_domain are required")
	}
	if len(m.ATOSReplicas) < 2 || len(m.ProtocolReplicas) < 2 || len(m.ChainEndpoints) < 3 || m.ChainQuorum <= len(m.ChainEndpoints)/2 || m.ChainQuorum > len(m.ChainEndpoints) {
		return errors.New("two ATOS/protocol replicas and strict-majority three-endpoint chain quorum are required")
	}
	if err := uniqueEndpoints("ATOS", m.ATOSReplicas, allowLoopback, false); err != nil {
		return err
	}
	if err := uniqueEndpoints("protocol", m.ProtocolReplicas, allowLoopback, false); err != nil {
		return err
	}
	if err := uniqueEndpoints("chain", m.ChainEndpoints, allowLoopback, true); err != nil {
		return err
	}
	if err := secureURL(m.ProtocolObserverURL, allowLoopback); err != nil {
		return fmt.Errorf("protocol observer URL: %w", err)
	}
	if len(m.AgentCodeHashes) == 0 || len(m.EscrowCodeHashes) == 0 {
		return errors.New("reviewed Agent and TaskEscrow code-hash allowlists are required")
	}
	for _, hashes := range [][]string{m.AgentCodeHashes, m.EscrowCodeHashes} {
		seenHashes := make(map[string]struct{}, len(hashes))
		for _, hash := range hashes {
			if !validCodeHash(hash) {
				return errors.New("invalid reviewed code hash")
			}
			if _, duplicate := seenHashes[hash]; duplicate {
				return errors.New("duplicate reviewed code hash")
			}
			seenHashes[hash] = struct{}{}
		}
	}
	requiredPurposes := []string{"quote", "receipt", "task-escrow", "chain-action"}
	seen := map[string]bool{}
	for _, custody := range m.Custody {
		if seen[custody.Purpose] || !slices.Contains(requiredPurposes, custody.Purpose) {
			return errors.New("duplicate or unsupported custody purpose")
		}
		seen[custody.Purpose] = true
		if !slices.Contains([]string{"hsm", "kms", "vault"}, custody.Backend) || strings.TrimSpace(custody.KeyID) == "" {
			return errors.New("production custody must identify an hsm, kms or vault key")
		}
		if err := secureURL(custody.HealthURL, allowLoopback); err != nil {
			return err
		}
	}
	for _, purpose := range requiredPurposes {
		if !seen[purpose] {
			return fmt.Errorf("missing %s custody", purpose)
		}
	}
	if len(m.Monitoring.RequiredMetrics) == 0 {
		return errors.New("monitoring metrics are required")
	}
	metricNames := make(map[string]struct{}, len(m.Monitoring.RequiredMetrics))
	for _, requirement := range m.Monitoring.RequiredMetrics {
		if !validMetricName(requirement.Name) || (requirement.Minimum == nil && requirement.Maximum == nil) {
			return errors.New("monitoring metric name and threshold are required")
		}
		if _, duplicate := metricNames[requirement.Name]; duplicate {
			return errors.New("duplicate monitoring metric requirement")
		}
		metricNames[requirement.Name] = struct{}{}
		if requirement.Minimum != nil && (math.IsNaN(*requirement.Minimum) || math.IsInf(*requirement.Minimum, 0)) {
			return errors.New("invalid monitoring minimum")
		}
		if requirement.Maximum != nil && (math.IsNaN(*requirement.Maximum) || math.IsInf(*requirement.Maximum, 0)) {
			return errors.New("invalid monitoring maximum")
		}
		if requirement.Minimum != nil && requirement.Maximum != nil && *requirement.Minimum > *requirement.Maximum {
			return errors.New("monitoring metric threshold is inverted")
		}
	}
	if err := secureURL(m.Monitoring.URL, allowLoopback); err != nil {
		return err
	}
	return nil
}

func uniqueEndpoints(kind string, endpoints []Endpoint, allowLoopback, distinctOperators bool) error {
	ids, urls, operators := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, endpoint := range endpoints {
		if endpoint.ID == "" || endpoint.Operator == "" || ids[endpoint.ID] || urls[endpoint.URL] {
			return fmt.Errorf("%s endpoints require unique ID, URL and operator", kind)
		}
		if distinctOperators && operators[endpoint.Operator] {
			return fmt.Errorf("%s endpoints require operator diversity", kind)
		}
		if err := secureURL(endpoint.URL, allowLoopback); err != nil {
			return fmt.Errorf("%s endpoint %s: %w", kind, endpoint.ID, err)
		}
		ids[endpoint.ID], urls[endpoint.URL], operators[endpoint.Operator] = true, true, true
	}
	return nil
}

func secureURL(raw string, allowLoopback bool) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Host == "" {
		return errors.New("invalid probe URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !allowLoopback {
		return errors.New("probe URL must use HTTPS")
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.IsLoopback() {
		return errors.New("plaintext probes are limited to explicit local acceptance")
	}
	return nil
}

func validCodeHash(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil && value == strings.ToLower(value)
}

func probe(ctx context.Context, client *http.Client, rawURL string, required []MetricRequirement) error {
	body, err := readProbe(ctx, client, rawURL)
	if err != nil {
		return err
	}
	for _, requirement := range required {
		value, err := metricValue(body, requirement.Name)
		if err != nil {
			return err
		}
		if requirement.Minimum != nil && value < *requirement.Minimum {
			return fmt.Errorf("monitoring signal %q is below minimum", requirement.Name)
		}
		if requirement.Maximum != nil && value > *requirement.Maximum {
			return fmt.Errorf("monitoring signal %q is above maximum", requirement.Name)
		}
	}
	return nil
}

func readProbe(ctx context.Context, client *http.Client, rawURL string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.Request == nil || response.Request.URL.String() != rawURL {
		return nil, errors.New("probe redirects are not allowed")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes+1))
	if err != nil || len(body) > maxBodyBytes {
		return nil, errors.New("probe response unavailable or oversized")
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("probe returned HTTP %d", response.StatusCode)
	}
	return body, nil
}

type custodyHealth struct {
	Version string `json:"version"`
	Purpose string `json:"purpose"`
	Backend string `json:"backend"`
	KeyID   string `json:"key_id"`
	Healthy bool   `json:"healthy"`
}

func probeCustody(ctx context.Context, client *http.Client, expected Custody) error {
	body, err := readProbe(ctx, client, expected.HealthURL)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var health custodyHealth
	if err := decoder.Decode(&health); err != nil {
		return errors.New("invalid custody health response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("custody health response contains trailing data")
	}
	if health.Version != "tos_phase4d_custody_health_v1" || !health.Healthy || health.Purpose != expected.Purpose || health.Backend != expected.Backend || health.KeyID != expected.KeyID {
		return errors.New("custody health identity mismatch")
	}
	return nil
}

func validMetricName(value string) bool {
	if value == "" {
		return false
	}
	for i, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' || c == ':' || (i > 0 && c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func metricValue(body []byte, required string) (float64, error) {
	found := false
	var result float64
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || strings.Contains(fields[0], "{") || fields[0] != required {
			continue
		}
		if found {
			return 0, fmt.Errorf("monitoring signal %q has duplicate samples", required)
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return 0, fmt.Errorf("monitoring signal %q has invalid value", required)
		}
		found, result = true, value
	}
	if !found {
		return 0, fmt.Errorf("required monitoring signal %q missing", required)
	}
	return result, nil
}

func verifyEvidence(e Evidence, now time.Time, expectedSubject string) error {
	if e.Subject != expectedSubject || strings.TrimSpace(expectedSubject) == "" {
		return errors.New("operator evidence subject mismatch")
	}
	if e.CompletedUnix <= 0 || e.MaximumAgeSeconds <= 0 || e.MaximumAgeSeconds > maxEvidenceAge {
		return errors.New("evidence time and bounded maximum age are required")
	}
	completed := time.Unix(e.CompletedUnix, 0).UTC()
	if completed.After(now.Add(time.Minute)) || now.Sub(completed) > time.Duration(e.MaximumAgeSeconds)*time.Second {
		return errors.New("operator evidence is stale or from the future")
	}
	if _, err := readDigestFile(e.Path, e.SHA256); err != nil {
		return err
	}
	publicKey, err := base64.StdEncoding.Strict().DecodeString(e.PublicKeyBase64)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || strings.TrimSpace(e.SignerID) == "" {
		return errors.New("evidence signer identity is invalid")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(e.SignatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("evidence signature is invalid")
	}
	message := fmt.Sprintf("TOS-PHASE4D-EVIDENCE-V1\x00%s\x00%s\x00%d\x00%d\x00%s", e.Subject, e.SHA256, e.CompletedUnix, e.MaximumAgeSeconds, e.SignerID)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature) {
		return errors.New("evidence signature verification failed")
	}
	return nil
}

func readDigestFile(path, expected string) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.HasPrefix(expected, "sha256:") || len(expected) != 71 {
		return nil, errors.New("absolute evidence path and SHA-256 are required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o222 != 0 {
		return nil, errors.New("evidence must be a read-only regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("evidence is unavailable")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, openedInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm()&0o222 != 0 {
		return nil, errors.New("evidence changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBodyBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxBodyBytes {
		return nil, errors.New("evidence is unavailable, empty or oversized")
	}
	digest := sha256.Sum256(data)
	if "sha256:"+hex.EncodeToString(digest[:]) != expected {
		return nil, errors.New("evidence digest mismatch")
	}
	return data, nil
}
