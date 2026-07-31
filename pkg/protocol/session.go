package protocol

import (
	"errors"
	"fmt"
	"time"
)

const (
	MaxSessionLifetime   = 24 * time.Hour
	MaxSessionOperations = 32
	MaxDelegationScopes  = 32
	MaxDelegationDepth   = 4
)

// SessionGrant is a signed, bounded authorization to use one service profile.
// It is not a payment authorization and does not prove current capacity.
type SessionGrant struct {
	Version          string    `json:"version"`
	SessionID        string    `json:"sessionId"`
	ServiceID        string    `json:"serviceId"`
	ProfileID        string    `json:"profileId"`
	Client           string    `json:"client"`
	RuntimeKeyID     string    `json:"runtimeKeyId"`
	ManifestRevision string    `json:"manifestRevision"`
	Operations       []string  `json:"operations"`
	MaxRequests      uint64    `json:"maxRequests"`
	MaxNanoTOS       uint64    `json:"maxNanoTos"`
	IssuedAt         time.Time `json:"issuedAt"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

func (s SessionGrant) Validate(now time.Time) error {
	if s.Version != BaseEnvelopeVersion {
		return errors.New("unsupported session version")
	}
	if err := validateCorrelationIDs(s.SessionID); err != nil {
		return err
	}
	if !serviceIDPattern.MatchString(s.ServiceID) || !serviceIDPattern.MatchString(s.ProfileID) {
		return errors.New("invalid session service or profile")
	}
	for name, value := range map[string]string{
		"client": s.Client, "runtimeKeyId": s.RuntimeKeyID, "manifestRevision": s.ManifestRevision,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if s.MaxRequests == 0 {
		return errors.New("session maxRequests must be nonzero")
	}
	if len(s.Operations) == 0 || len(s.Operations) > MaxSessionOperations {
		return fmt.Errorf("session operations must contain 1..%d entries", MaxSessionOperations)
	}
	seen := make(map[string]struct{}, len(s.Operations))
	for _, operation := range s.Operations {
		if err := boundedString("session operation", operation, 1, 128); err != nil {
			return err
		}
		if _, duplicate := seen[operation]; duplicate {
			return errors.New("duplicate session operation")
		}
		seen[operation] = struct{}{}
	}
	if s.IssuedAt.IsZero() || s.ExpiresAt.IsZero() || !s.ExpiresAt.After(s.IssuedAt) ||
		s.IssuedAt.After(now.Add(MaxClockSkewForReceipts)) || !s.ExpiresAt.After(now) ||
		s.ExpiresAt.Sub(s.IssuedAt) > MaxSessionLifetime {
		return errors.New("invalid session validity window")
	}
	return nil
}

// Delegation grants a subject a finite subset of an issuer's authority.
// Consumers must additionally verify the signature, issuer authority,
// revocation status, and every parent in the chain.
type Delegation struct {
	Version      string    `json:"version"`
	DelegationID string    `json:"delegationId"`
	Issuer       string    `json:"issuer"`
	Subject      string    `json:"subject"`
	Audience     string    `json:"audience"`
	Scopes       []string  `json:"scopes"`
	ParentID     string    `json:"parentId,omitempty"`
	Depth        uint8     `json:"depth"`
	MaxNanoTOS   uint64    `json:"maxNanoTos"`
	MaxActions   uint64    `json:"maxActions"`
	NotBefore    time.Time `json:"notBefore"`
	ExpiresAt    time.Time `json:"expiresAt"`
}

func (d Delegation) Validate(now time.Time) error {
	if d.Version != BaseEnvelopeVersion {
		return errors.New("unsupported delegation version")
	}
	if err := validateCorrelationIDs(d.DelegationID); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"issuer": d.Issuer, "subject": d.Subject, "audience": d.Audience,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if d.Depth > MaxDelegationDepth {
		return errors.New("delegation depth exceeds protocol maximum")
	}
	if d.Depth == 0 && d.ParentID != "" {
		return errors.New("root delegation must not have a parent")
	}
	if d.Depth > 0 {
		if err := validateCorrelationIDs(d.ParentID); err != nil {
			return errors.New("child delegation requires a valid parentId")
		}
	}
	if d.MaxActions == 0 {
		return errors.New("delegation maxActions must be nonzero")
	}
	if len(d.Scopes) == 0 || len(d.Scopes) > MaxDelegationScopes {
		return fmt.Errorf("delegation scopes must contain 1..%d entries", MaxDelegationScopes)
	}
	seen := make(map[string]struct{}, len(d.Scopes))
	for _, scope := range d.Scopes {
		if !serviceIDPattern.MatchString(scope) {
			return errors.New("invalid delegation scope")
		}
		if _, duplicate := seen[scope]; duplicate {
			return errors.New("duplicate delegation scope")
		}
		seen[scope] = struct{}{}
	}
	if d.NotBefore.IsZero() || d.ExpiresAt.IsZero() || !d.ExpiresAt.After(d.NotBefore) ||
		d.NotBefore.After(now.Add(MaxClockSkewForReceipts)) || !d.ExpiresAt.After(now) ||
		d.ExpiresAt.Sub(d.NotBefore) > MaxSessionLifetime {
		return errors.New("invalid delegation validity window")
	}
	return nil
}

// ValidateChildOf verifies monotonic attenuation. It intentionally does not
// verify signatures or revocation; those depend on the caller's trust store.
func (d Delegation) ValidateChildOf(parent Delegation, now time.Time) error {
	if err := parent.Validate(now); err != nil {
		return fmt.Errorf("invalid parent delegation: %w", err)
	}
	if err := d.Validate(now); err != nil {
		return err
	}
	if parent.Depth >= MaxDelegationDepth {
		return errors.New("parent delegation cannot have another child")
	}
	if d.ParentID != parent.DelegationID || d.Issuer != parent.Subject ||
		d.Audience != parent.Audience || d.Depth != parent.Depth+1 {
		return errors.New("delegation parent binding mismatch")
	}
	if d.NotBefore.Before(parent.NotBefore) || d.ExpiresAt.After(parent.ExpiresAt) ||
		d.MaxActions > parent.MaxActions || d.MaxNanoTOS > parent.MaxNanoTOS {
		return errors.New("child delegation expands parent limits")
	}
	parentScopes := make(map[string]struct{}, len(parent.Scopes))
	for _, scope := range parent.Scopes {
		parentScopes[scope] = struct{}{}
	}
	for _, scope := range d.Scopes {
		if _, allowed := parentScopes[scope]; !allowed {
			return errors.New("child delegation expands parent scopes")
		}
	}
	return nil
}
