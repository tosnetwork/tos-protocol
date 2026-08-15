package nativecore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func testSoftwareWorkManifest() SoftwareWorkManifestV1 {
	return SoftwareWorkManifestV1{
		Protocol: SoftwareWorkManifestProtocolV1, Version: "1.0.0", Name: "Deterministic Go test",
		Description: "Run the committed Go test suite without network access.", Operation: "test",
		AcceptedSourceKinds: []string{"content-addressed-archive", "immutable-repository-commit"},
		InputSchemaDigest:   "sha256:" + strings.Repeat("11", 32), OutputSchemaDigest: "sha256:" + strings.Repeat("22", 32),
		ToolchainDigest: "sha256:" + strings.Repeat("33", 32),
		Invocation:      SoftwareWorkInvocationV1{Executable: "/usr/local/bin/go", Arguments: []string{"test", "./...", "-count=1"}, WorkingDirectory: "/workspace/source"},
		NetworkPolicy:   "none", Limits: SoftwareWorkLimitsV1{CPUMillis: 120000, MemoryBytes: 1073741824, ScratchBytes: 2147483648, OutputBytes: 16777216, WallClockMillis: 180000},
		ArtifactMediaTypes: []string{"application/vnd.atos.software-artifact.v1+tar"}, ReportMediaTypes: []string{"application/vnd.atos.test-report.v1+json"},
		SuccessCondition: "exit-code-zero-and-valid-reports", RefundConditions: []string{"not-started-before-deadline"},
		EndpointCommitment: "sha256:dca9babcd44775f2c19ef571964c01e2e75b15254d0d16f2349c8d446f76c44c", ExecutionSignerAuthorization: "sha256:" + strings.Repeat("55", 32), RetentionSeconds: 86400,
		SupportedAssets: []SoftwareWorkAssetIdentityV1{{Workchain: 0, MasterAccount: "ca11200a7d4a3c6822af077f035131868584f40f48fb1b7b7b1889ae51f9926a",
			MasterCodeHash: "tvm-cell-sha256:18d5b6e780ff0bb451254c2c760d09d6e485638cd1407abb97078752c3c1c9ee",
			WalletCodeHash: "tvm-cell-sha256:8f452d7a4dfd74066b682365177259ed05734435be76b5fd4bd5d8af2b7c3d68", Decimals: 6}},
	}
}

func TestSoftwareWorkManifestCanonicalEncoding(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	first, firstDigest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("software-work manifest encoding is not deterministic")
	}
	jsonBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeSoftwareWorkManifestJSON(jsonBytes)
	if err != nil {
		t.Fatal(err)
	}
	third, thirdDigest, err := CanonicalSoftwareWorkManifest(decoded)
	if err != nil || !bytes.Equal(first, third) || firstDigest != thirdDigest {
		t.Fatal("JSON projection changed canonical manifest")
	}
}

func TestSoftwareWorkManifestCanonicalCBORDecoder(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	encoded, _, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCanonicalSoftwareWorkManifestCBOR(encoded)
	if err != nil || decoded.Version != manifest.Version {
		t.Fatalf("canonical CBOR decode failed: %v", err)
	}
	// Replace the canonical definite-length map header with an indefinite map
	// and break. It has identical semantics but a forbidden alternate encoding.
	if encoded[0] != 0xb4 {
		t.Fatalf("unexpected manifest map header: %x", encoded[0])
	}
	nonCanonical := append([]byte{0xbf}, encoded[1:]...)
	nonCanonical = append(nonCanonical, 0xff)
	if _, err := DecodeCanonicalSoftwareWorkManifestCBOR(nonCanonical); err == nil {
		t.Fatal("non-canonical manifest CBOR accepted")
	}
}

func TestSoftwareWorkManifestRejectsCircularCapabilityID(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded[:len(encoded)-1], []byte(`,"capability_id":"cap_`+strings.Repeat("aa", 32)+`"}`)...)
	if _, err := DecodeSoftwareWorkManifestJSON(encoded); err == nil {
		t.Fatal("manifest accepted circular capability_id field")
	}
}

func TestSoftwareWorkManifestRejectsShellAndNonObjectiveRefunds(t *testing.T) {
	manifest := testSoftwareWorkManifest()
	manifest.Invocation.Executable = "/bin/sh"
	if err := ValidateSoftwareWorkManifest(manifest); err == nil {
		t.Fatal("manifest accepted a general-purpose shell")
	}
	manifest = testSoftwareWorkManifest()
	manifest.RefundConditions = []string{"executor-infrastructure-failure"}
	if err := ValidateSoftwareWorkManifest(manifest); err == nil {
		t.Fatal("manifest accepted a subjective refund condition")
	}
}

func TestFrozenSoftwareWorkManifestVector(t *testing.T) {
	type expected struct {
		Digest              string `json:"digest"`
		CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
	}
	type vector struct {
		Schema            string          `json:"schema"`
		Manifest          json.RawMessage `json:"manifest"`
		Expected          expected        `json:"expected"`
		NegativeMutations []string        `json:"negative_mutations"`
	}
	data, err := os.ReadFile("testdata/software_work_manifest_v1_vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var frozen vector
	if err := json.Unmarshal(data, &frozen); err != nil || frozen.Schema != "atos.software-work-manifest.v1.vector" {
		t.Fatalf("invalid frozen vector: %v", err)
	}
	manifest, err := DecodeSoftwareWorkManifestJSON(frozen.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	encoded, digest, err := CanonicalSoftwareWorkManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	expectedBytes, err := base64.StdEncoding.DecodeString(frozen.Expected.CanonicalCBORBase64)
	if err != nil {
		t.Fatal(err)
	}
	if digest != frozen.Expected.Digest || !bytes.Equal(encoded, expectedBytes) {
		t.Fatalf("frozen software-work vector mismatch: got digest=%s cbor=%s", digest, base64.StdEncoding.EncodeToString(encoded))
	}
	for _, mutation := range frozen.NegativeMutations {
		candidate := manifest
		switch mutation {
		case "add_capability_id":
			value := append(append([]byte(nil), frozen.Manifest[:len(frozen.Manifest)-1]...), []byte(`,"capability_id":"cap_`+strings.Repeat("aa", 32)+`"}`)...)
			if _, err := DecodeSoftwareWorkManifestJSON(value); err == nil {
				t.Fatalf("negative mutation %s was accepted", mutation)
			}
			continue
		case "wrong_protocol":
			candidate.Protocol = "atos.software-work-manifest.v0"
		case "shell_executable":
			candidate.Invocation.Executable = "/bin/sh"
		case "network_enabled":
			candidate.NetworkPolicy = "full"
		case "zero_cpu_limit":
			candidate.Limits.CPUMillis = 0
		case "subjective_refund_condition":
			candidate.RefundConditions = []string{"executor-infrastructure-failure"}
		case "ticker_only_asset":
			candidate.SupportedAssets = []SoftwareWorkAssetIdentityV1{{MasterAccount: "USDT", Decimals: 6}}
		case "zero_asset_decimals":
			candidate.SupportedAssets = append([]SoftwareWorkAssetIdentityV1(nil), candidate.SupportedAssets...)
			candidate.SupportedAssets[0].Decimals = 0
		default:
			t.Fatalf("unknown negative mutation %q", mutation)
		}
		if err := ValidateSoftwareWorkManifest(candidate); err == nil {
			t.Fatalf("negative mutation %s was accepted", mutation)
		}
	}
}
