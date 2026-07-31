package protocol

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	TerminalManifestVersion     = "0.1"
	MaxTerminalManifestLifetime = 10 * time.Minute
	MaxReadinessComponents      = 64
	MaxResourceClaims           = 128
	MaxResourceLimits           = 64
	MaxResourceAttributes       = 32
)

type ResourceClass string

const (
	ResourceCompute     ResourceClass = "compute"
	ResourceAccelerator ResourceClass = "accelerator"
	ResourceMemory      ResourceClass = "memory"
	ResourceStorage     ResourceClass = "storage"
	ResourceNetwork     ResourceClass = "network"
	ResourceRuntime     ResourceClass = "runtime"
	ResourceDevice      ResourceClass = "device"
	ResourceOther       ResourceClass = "other"
)

func (c ResourceClass) Valid() bool {
	switch c {
	case ResourceCompute, ResourceAccelerator, ResourceMemory, ResourceStorage,
		ResourceNetwork, ResourceRuntime, ResourceDevice, ResourceOther:
		return true
	default:
		return false
	}
}

type ResourceUnit string

const (
	ResourceUnitCount         ResourceUnit = "count"
	ResourceUnitBytes         ResourceUnit = "bytes"
	ResourceUnitMilliseconds  ResourceUnit = "milliseconds"
	ResourceUnitMilliwatts    ResourceUnit = "milliwatts"
	ResourceUnitBitsPerSecond ResourceUnit = "bits-per-second"
)

func (u ResourceUnit) Valid() bool {
	switch u {
	case ResourceUnitCount, ResourceUnitBytes, ResourceUnitMilliseconds,
		ResourceUnitMilliwatts, ResourceUnitBitsPerSecond:
		return true
	default:
		return false
	}
}

type ReadinessStatus string

const (
	ReadinessReady       ReadinessStatus = "ready"
	ReadinessDegraded    ReadinessStatus = "degraded"
	ReadinessUnavailable ReadinessStatus = "unavailable"
	ReadinessUnknown     ReadinessStatus = "unknown"
	ReadinessDraining    ReadinessStatus = "draining"
)

func (s ReadinessStatus) Valid() bool {
	switch s {
	case ReadinessReady, ReadinessDegraded, ReadinessUnavailable,
		ReadinessUnknown, ReadinessDraining:
		return true
	default:
		return false
	}
}

// TerminalManifest is a short-lived, service-scoped view of an edge
// terminal. TerminalID must be a rotating or service-specific pseudonym, not a
// hardware fingerprint.
type TerminalManifest struct {
	Version        string               `json:"version"`
	TerminalID     string               `json:"terminalId"`
	ServiceID      string               `json:"serviceId"`
	Network        string               `json:"network"`
	Revision       string               `json:"revision"`
	PolicyRevision string               `json:"policyRevision"`
	CollectedAt    time.Time            `json:"collectedAt"`
	ExpiresAt      time.Time            `json:"expiresAt"`
	Readiness      []ReadinessComponent `json:"readiness"`
	Resources      []ResourceClaim      `json:"resources"`
	Extensions     []Extension          `json:"extensions,omitempty"`
}

type ReadinessComponent struct {
	ID         string          `json:"id"`
	Status     ReadinessStatus `json:"status"`
	Revision   string          `json:"revision"`
	ReasonCode string          `json:"reasonCode,omitempty"`
	Evidence   ClaimEvidence   `json:"evidence"`
}

// ResourceClaim publishes coarse resource capacity. AvailableExternal must
// already exclude OwnerReserved and any currently committed capacity.
type ResourceClaim struct {
	ID                string            `json:"id"`
	Class             ResourceClass     `json:"class"`
	Unit              ResourceUnit      `json:"unit"`
	Total             uint64            `json:"total"`
	OwnerReserved     uint64            `json:"ownerReserved"`
	AvailableExternal uint64            `json:"availableExternal"`
	Revision          string            `json:"revision"`
	Evidence          ClaimEvidence     `json:"evidence"`
	Attributes        map[string]string `json:"attributes,omitempty"`
}

// ResourceLimit binds one admission dimension to a quote or profile action.
// It is a protocol limit, not an instruction to allocate the quantity.
type ResourceLimit struct {
	ID       string       `json:"id"`
	Unit     ResourceUnit `json:"unit"`
	Quantity uint64       `json:"quantity"`
}

// ClaimEvidence describes freshness and provenance for one field group. A
// digest commits to the profile-defined evidence artifact, not to its truth.
type ClaimEvidence struct {
	Level       EvidenceLevel `json:"level"`
	Issuer      string        `json:"issuer"`
	CollectedAt time.Time     `json:"collectedAt"`
	ExpiresAt   time.Time     `json:"expiresAt"`
	Digest      string        `json:"digest,omitempty"`
	Reference   string        `json:"reference,omitempty"`
}

func (m TerminalManifest) Validate(now time.Time) error {
	if m.Version != TerminalManifestVersion {
		return errors.New("unsupported terminal manifest version")
	}
	if err := validateCorrelationIDs(m.TerminalID); err != nil {
		return fmt.Errorf("invalid terminalId: %w", err)
	}
	if !serviceIDPattern.MatchString(m.ServiceID) {
		return errors.New("invalid terminal serviceId")
	}
	for name, value := range map[string]string{
		"network": m.Network, "revision": m.Revision, "policyRevision": m.PolicyRevision,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if m.CollectedAt.IsZero() || m.ExpiresAt.IsZero() ||
		m.CollectedAt.After(now.Add(MaxClockSkewForReceipts)) ||
		!m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.CollectedAt) ||
		m.ExpiresAt.Sub(m.CollectedAt) > MaxTerminalManifestLifetime {
		return errors.New("invalid terminal manifest validity window")
	}
	if len(m.Readiness) == 0 || len(m.Readiness) > MaxReadinessComponents ||
		len(m.Resources) == 0 || len(m.Resources) > MaxResourceClaims ||
		len(m.Extensions) > MaxExtensions {
		return errors.New("terminal manifest collection bounds are invalid")
	}
	readiness := make(map[string]struct{}, len(m.Readiness))
	for index, component := range m.Readiness {
		if err := component.Validate(now, m.CollectedAt, m.ExpiresAt); err != nil {
			return fmt.Errorf("readiness[%d]: %w", index, err)
		}
		if _, duplicate := readiness[component.ID]; duplicate {
			return fmt.Errorf("readiness[%d]: duplicate component", index)
		}
		readiness[component.ID] = struct{}{}
	}
	resources := make(map[string]struct{}, len(m.Resources))
	for index, resource := range m.Resources {
		if err := resource.Validate(now, m.CollectedAt, m.ExpiresAt); err != nil {
			return fmt.Errorf("resources[%d]: %w", index, err)
		}
		if _, duplicate := resources[resource.ID]; duplicate {
			return fmt.Errorf("resources[%d]: duplicate resource", index)
		}
		resources[resource.ID] = struct{}{}
	}
	extensions := make(map[string]struct{}, len(m.Extensions))
	for index, extension := range m.Extensions {
		if err := extension.Validate(); err != nil {
			return fmt.Errorf("extensions[%d]: %w", index, err)
		}
		if _, duplicate := extensions[extension.ID]; duplicate {
			return fmt.Errorf("extensions[%d]: duplicate extension", index)
		}
		extensions[extension.ID] = struct{}{}
	}
	return nil
}

func (r ReadinessComponent) Validate(now, manifestTime, manifestExpiry time.Time) error {
	if !serviceIDPattern.MatchString(r.ID) {
		return errors.New("invalid readiness component id")
	}
	if !r.Status.Valid() {
		return errors.New("invalid readiness status")
	}
	if err := boundedString("readiness revision", r.Revision, 1, 256); err != nil {
		return err
	}
	if r.ReasonCode != "" && !serviceIDPattern.MatchString(r.ReasonCode) {
		return errors.New("invalid readiness reasonCode")
	}
	return r.Evidence.Validate(now, manifestTime, manifestExpiry)
}

func (r ResourceClaim) Validate(now, manifestTime, manifestExpiry time.Time) error {
	if !serviceIDPattern.MatchString(r.ID) {
		return errors.New("invalid resource id")
	}
	if !r.Class.Valid() || !r.Unit.Valid() {
		return errors.New("invalid resource class or unit")
	}
	if r.Total == 0 || r.OwnerReserved > r.Total ||
		r.AvailableExternal > r.Total-r.OwnerReserved {
		return errors.New("invalid resource capacity accounting")
	}
	if err := boundedString("resource revision", r.Revision, 1, 256); err != nil {
		return err
	}
	if len(r.Attributes) > MaxResourceAttributes {
		return errors.New("too many resource attributes")
	}
	for key, value := range r.Attributes {
		if !serviceIDPattern.MatchString(key) || forbiddenResourceAttribute(key) {
			return fmt.Errorf("forbidden or invalid resource attribute %q", key)
		}
		if err := boundedString("resource attribute", value, 0, 256); err != nil {
			return err
		}
	}
	return r.Evidence.Validate(now, manifestTime, manifestExpiry)
}

func (l ResourceLimit) Validate() error {
	if !serviceIDPattern.MatchString(l.ID) {
		return errors.New("invalid resource limit id")
	}
	if !l.Unit.Valid() || l.Quantity == 0 {
		return errors.New("invalid resource limit unit or quantity")
	}
	return nil
}

func (e ClaimEvidence) Validate(now, manifestTime, manifestExpiry time.Time) error {
	if !e.Level.Valid() {
		return errors.New("invalid claim evidence level")
	}
	if err := boundedString("evidence issuer", e.Issuer, 1, 512); err != nil {
		return err
	}
	if e.CollectedAt.IsZero() || e.ExpiresAt.IsZero() ||
		e.CollectedAt.After(now.Add(MaxClockSkewForReceipts)) ||
		e.CollectedAt.After(manifestTime.Add(MaxClockSkewForReceipts)) ||
		e.ExpiresAt.Before(manifestExpiry) || !e.ExpiresAt.After(e.CollectedAt) ||
		e.ExpiresAt.Sub(e.CollectedAt) > MaxEvidenceLifetime {
		return errors.New("invalid claim evidence validity window")
	}
	if e.Digest != "" && !digestPattern.MatchString(e.Digest) {
		return errors.New("claim evidence digest must be sha256:<lowercase hex>")
	}
	switch e.Level {
	case EvidenceBenchmarked, EvidenceAudited, EvidenceAttested,
		EvidenceReplicated, EvidenceProven:
		if e.Digest == "" {
			return errors.New("strong evidence level requires an evidence digest")
		}
	}
	if err := boundedString("evidence reference", e.Reference, 0, 2048); err != nil {
		return err
	}
	return nil
}

func validateResourceLimits(limits []ResourceLimit) error {
	if len(limits) > MaxResourceLimits {
		return errors.New("too many resource limits")
	}
	seen := make(map[string]struct{}, len(limits))
	for index, limit := range limits {
		if err := limit.Validate(); err != nil {
			return fmt.Errorf("resourceLimits[%d]: %w", index, err)
		}
		key := limit.ID
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("resourceLimits[%d]: duplicate resource limit", index)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func forbiddenResourceAttribute(key string) bool {
	normalized := strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(key))
	switch normalized {
	case "serial", "serial-number", "uuid", "pci", "pci-address", "mac",
		"mac-address", "hostname", "host-name", "hardware-fingerprint",
		"ip", "ip-address", "precise-location":
		return true
	}
	for _, component := range strings.Split(normalized, "-") {
		switch component {
		case "serial", "uuid", "pci", "mac", "hostname", "fingerprint":
			return true
		}
	}
	return false
}
