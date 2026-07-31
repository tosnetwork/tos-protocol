package protocol

import (
	"strings"
	"testing"
	"time"
)

func validClaimEvidence(now time.Time) ClaimEvidence {
	return ClaimEvidence{
		Level: EvidenceObserved, Issuer: "runtime-key-1",
		CollectedAt: now, ExpiresAt: now.Add(time.Hour),
	}
}

func validTerminalManifest(now time.Time) TerminalManifest {
	return TerminalManifest{
		Version: TerminalManifestVersion, TerminalID: "terminal-0001",
		ServiceID: "edge.example.ai", Network: "testnet", Revision: "terminal-1",
		PolicyRevision: "owner-policy-1", CollectedAt: now,
		ExpiresAt: now.Add(time.Minute),
		Readiness: []ReadinessComponent{{
			ID: "runtime.ollama", Status: ReadinessReady, Revision: "0.11.0",
			Evidence: validClaimEvidence(now),
		}},
		Resources: []ResourceClaim{{
			ID: "memory.host", Class: ResourceMemory, Unit: ResourceUnitBytes,
			Total: 64 << 30, OwnerReserved: 16 << 30, AvailableExternal: 32 << 30,
			Revision: "probe-v1", Evidence: validClaimEvidence(now),
			Attributes: map[string]string{"architecture.name": "amd64"},
		}},
	}
}

func TestTerminalManifestValidate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	if err := validTerminalManifest(now).Validate(now); err != nil {
		t.Fatal(err)
	}
	duplicate := validTerminalManifest(now)
	duplicate.Resources = append(duplicate.Resources, duplicate.Resources[0])
	if err := duplicate.Validate(now); err == nil {
		t.Fatal("duplicate resource accepted")
	}
}

func TestTerminalManifestRejectsCapacityUnderflowAndFingerprint(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	invalidCapacity := validTerminalManifest(now)
	invalidCapacity.Resources[0].OwnerReserved = invalidCapacity.Resources[0].Total
	invalidCapacity.Resources[0].AvailableExternal = 1
	if err := invalidCapacity.Validate(now); err == nil {
		t.Fatal("resource capacity underflow accepted")
	}
	fingerprint := validTerminalManifest(now)
	fingerprint.Resources[0].Attributes["hardware.uuid"] = "secret"
	if err := fingerprint.Validate(now); err == nil {
		t.Fatal("stable hardware fingerprint accepted")
	}
}

func TestStrongClaimEvidenceRequiresDigest(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	manifest := validTerminalManifest(now)
	manifest.Resources[0].Evidence.Level = EvidenceAttested
	if err := manifest.Validate(now); err == nil {
		t.Fatal("attested claim without evidence digest accepted")
	}
	manifest.Resources[0].Evidence.Digest = "sha256:" + strings.Repeat("a", 64)
	if err := manifest.Validate(now); err != nil {
		t.Fatal(err)
	}
}

func TestResourceLimitsRejectDuplicates(t *testing.T) {
	limits := []ResourceLimit{
		{ID: "memory.ram", Unit: ResourceUnitBytes, Quantity: 1024},
		{ID: "memory.ram", Unit: ResourceUnitCount, Quantity: 2},
	}
	if err := validateResourceLimits(limits); err == nil {
		t.Fatal("duplicate resource limit accepted")
	}
}
