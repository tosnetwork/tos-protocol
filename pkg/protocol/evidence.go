package protocol

import (
	"errors"
	"fmt"
	"time"
)

type EvidenceLevel string

const (
	EvidenceDeclared    EvidenceLevel = "declared"
	EvidenceObserved    EvidenceLevel = "observed"
	EvidenceBenchmarked EvidenceLevel = "benchmarked"
	EvidenceAudited     EvidenceLevel = "audited"
	EvidenceAttested    EvidenceLevel = "attested"
	EvidenceReplicated  EvidenceLevel = "replicated"
	EvidenceProven      EvidenceLevel = "cryptographically-proven"
	MaxEvidenceClaims                 = 32
	MaxEvidenceLifetime               = 30 * 24 * time.Hour
)

func (l EvidenceLevel) Valid() bool {
	switch l {
	case EvidenceDeclared, EvidenceObserved, EvidenceBenchmarked,
		EvidenceAudited, EvidenceAttested, EvidenceReplicated, EvidenceProven:
		return true
	default:
		return false
	}
}

type EvidenceBundle struct {
	Version   string          `json:"version"`
	BundleID  string          `json:"bundleId"`
	RequestID string          `json:"requestId,omitempty"`
	Claims    []EvidenceClaim `json:"claims"`
}

type EvidenceClaim struct {
	Type        string        `json:"type"`
	Level       EvidenceLevel `json:"level"`
	Subject     string        `json:"subject"`
	Issuer      string        `json:"issuer"`
	CollectedAt time.Time     `json:"collectedAt"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	Digest      string        `json:"digest"`
	Reference   string        `json:"reference,omitempty"`
}

// IsValidEvidenceType reports whether value is a canonical protocol evidence
// type. Trust-policy configuration and claims intentionally share this exact
// grammar so a policy cannot silently authorize an unrepresentable type.
func IsValidEvidenceType(value string) bool {
	return serviceIDPattern.MatchString(value)
}

func (b EvidenceBundle) Validate(now time.Time) error {
	if b.Version != BaseEnvelopeVersion {
		return errors.New("unsupported evidence bundle version")
	}
	if err := validateCorrelationIDs(b.BundleID); err != nil {
		return err
	}
	if b.RequestID != "" {
		if err := validateCorrelationIDs(b.RequestID); err != nil {
			return err
		}
	}
	if len(b.Claims) == 0 || len(b.Claims) > MaxEvidenceClaims {
		return fmt.Errorf("evidence bundle must contain 1..%d claims", MaxEvidenceClaims)
	}
	seen := make(map[string]struct{}, len(b.Claims))
	for index, claim := range b.Claims {
		if err := claim.Validate(now); err != nil {
			return fmt.Errorf("claims[%d]: %w", index, err)
		}
		key := claim.Type + "\x00" + claim.Subject + "\x00" + claim.Digest
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("claims[%d]: duplicate claim", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func (c EvidenceClaim) Validate(now time.Time) error {
	if !IsValidEvidenceType(c.Type) {
		return errors.New("invalid evidence claim type")
	}
	if !c.Level.Valid() {
		return errors.New("invalid evidence level")
	}
	for name, value := range map[string]string{"subject": c.Subject, "issuer": c.Issuer} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if c.CollectedAt.IsZero() || c.ExpiresAt.IsZero() ||
		c.CollectedAt.After(now.Add(MaxClockSkewForReceipts)) ||
		!c.ExpiresAt.After(now) || !c.ExpiresAt.After(c.CollectedAt) ||
		c.ExpiresAt.Sub(c.CollectedAt) > MaxEvidenceLifetime {
		return errors.New("invalid evidence validity window")
	}
	if !digestPattern.MatchString(c.Digest) {
		return errors.New("evidence digest must be sha256:<lowercase hex>")
	}
	if err := boundedString("evidence reference", c.Reference, 0, 2048); err != nil {
		return err
	}
	return nil
}
