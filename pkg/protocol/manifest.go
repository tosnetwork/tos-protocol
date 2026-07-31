package protocol

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	ManifestVersion     = "0.1"
	MaxManifestLifetime = 24 * time.Hour
	MaxRuntimeKeys      = 16
	MaxEndpoints        = 16
	MaxCapabilities     = 128
	MaxExtensions       = 32
	MaxClaimAttributes  = 64
)

// ServiceManifest is the signed, operational description referenced by a
// ServiceDescriptor. Rapid capacity and price changes belong in live quote
// responses rather than this document.
type ServiceManifest struct {
	Version      string             `json:"version"`
	ManifestID   string             `json:"manifestId"`
	ServiceID    string             `json:"serviceId"`
	Controller   string             `json:"controller"`
	Network      string             `json:"network"`
	Revision     string             `json:"revision"`
	IssuedAt     time.Time          `json:"issuedAt"`
	ExpiresAt    time.Time          `json:"expiresAt"`
	RuntimeKeys  []RuntimeKey       `json:"runtimeKeys"`
	Endpoints    []ServiceEndpoint  `json:"endpoints"`
	Profiles     []ProfileReference `json:"profiles"`
	Capabilities []CapabilityClaim  `json:"capabilities,omitempty"`
	Extensions   []Extension        `json:"extensions,omitempty"`
}

type RuntimeKey struct {
	KeyID     string    `json:"keyId"`
	Algorithm string    `json:"algorithm"`
	PublicKey string    `json:"publicKey"`
	Roles     []string  `json:"roles"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
}

type ServiceEndpoint struct {
	Transport   string `json:"transport"`
	Audience    string `json:"audience"`
	URL         string `json:"url,omitempty"`
	ADNLAddress string `json:"adnlAddress,omitempty"`
}

type CapabilityClaim struct {
	ID         string            `json:"id"`
	Revision   string            `json:"revision"`
	Evidence   EvidenceLevel     `json:"evidence"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type Extension struct {
	ID       string `json:"id"`
	Critical bool   `json:"critical"`
	Digest   string `json:"digest"`
	URL      string `json:"url,omitempty"`
}

func (m ServiceManifest) Validate(now time.Time) error {
	if m.Version != ManifestVersion {
		return errors.New("unsupported manifest version")
	}
	if err := validateCorrelationIDs(m.ManifestID); err != nil {
		return err
	}
	if !serviceIDPattern.MatchString(m.ServiceID) {
		return errors.New("invalid manifest serviceId")
	}
	for name, value := range map[string]string{
		"controller": m.Controller,
		"network":    m.Network,
		"revision":   m.Revision,
	} {
		if err := boundedString(name, value, 1, 512); err != nil {
			return err
		}
	}
	if m.IssuedAt.IsZero() || m.ExpiresAt.IsZero() ||
		m.IssuedAt.After(now.Add(MaxClockSkewForReceipts)) ||
		!m.ExpiresAt.After(now) || !m.ExpiresAt.After(m.IssuedAt) ||
		m.ExpiresAt.Sub(m.IssuedAt) > MaxManifestLifetime {
		return errors.New("invalid manifest validity window")
	}
	if len(m.RuntimeKeys) == 0 || len(m.RuntimeKeys) > MaxRuntimeKeys ||
		len(m.Endpoints) == 0 || len(m.Endpoints) > MaxEndpoints ||
		len(m.Profiles) == 0 || len(m.Profiles) > MaxProfiles ||
		len(m.Capabilities) > MaxCapabilities || len(m.Extensions) > MaxExtensions {
		return errors.New("manifest collection bounds are invalid")
	}
	if err := validateRuntimeKeys(m.RuntimeKeys, m.IssuedAt, m.ExpiresAt); err != nil {
		return err
	}
	endpoints := make(map[string]struct{}, len(m.Endpoints))
	for index, endpoint := range m.Endpoints {
		if err := endpoint.Validate(); err != nil {
			return fmt.Errorf("endpoints[%d]: %w", index, err)
		}
		key := endpoint.Transport + "\x00" + endpoint.Audience + "\x00" + endpoint.URL + "\x00" + endpoint.ADNLAddress
		if _, duplicate := endpoints[key]; duplicate {
			return fmt.Errorf("endpoints[%d]: duplicate endpoint", index)
		}
		endpoints[key] = struct{}{}
	}
	profiles := make(map[string]struct{}, len(m.Profiles))
	for index, profile := range m.Profiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("profiles[%d]: %w", index, err)
		}
		key := profile.ID + "\x00" + profile.Version
		if _, duplicate := profiles[key]; duplicate {
			return fmt.Errorf("profiles[%d]: duplicate profile", index)
		}
		profiles[key] = struct{}{}
	}
	claims := make(map[string]struct{}, len(m.Capabilities))
	for index, claim := range m.Capabilities {
		if err := claim.Validate(); err != nil {
			return fmt.Errorf("capabilities[%d]: %w", index, err)
		}
		if _, duplicate := claims[claim.ID]; duplicate {
			return fmt.Errorf("capabilities[%d]: duplicate capability", index)
		}
		claims[claim.ID] = struct{}{}
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

func validateRuntimeKeys(keys []RuntimeKey, manifestStart, manifestEnd time.Time) error {
	seen := make(map[string]struct{}, len(keys))
	for index, key := range keys {
		if err := key.Validate(manifestStart, manifestEnd); err != nil {
			return fmt.Errorf("runtimeKeys[%d]: %w", index, err)
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return fmt.Errorf("runtimeKeys[%d]: duplicate keyId", index)
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

func (k RuntimeKey) Validate(manifestStart, manifestEnd time.Time) error {
	if err := boundedString("keyId", k.KeyID, 1, 512); err != nil {
		return err
	}
	if k.Algorithm != "Ed25519" {
		return errors.New("runtime key algorithm must be Ed25519")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(k.PublicKey)
	if err != nil || len(publicKey) != 32 {
		return errors.New("runtime public key must be 32-byte base64url Ed25519")
	}
	if len(k.Roles) == 0 || len(k.Roles) > 8 {
		return errors.New("runtime key roles must contain 1..8 entries")
	}
	roles := make(map[string]struct{}, len(k.Roles))
	for _, role := range k.Roles {
		switch role {
		case "authenticate", "quote", "receipt", "evidence":
		default:
			return fmt.Errorf("unsupported runtime key role %q", role)
		}
		if _, duplicate := roles[role]; duplicate {
			return errors.New("duplicate runtime key role")
		}
		roles[role] = struct{}{}
	}
	if k.NotBefore.IsZero() || k.NotAfter.IsZero() || !k.NotAfter.After(k.NotBefore) ||
		k.NotBefore.Before(manifestStart) || k.NotAfter.After(manifestEnd) {
		return errors.New("runtime key validity must be inside manifest validity")
	}
	return nil
}

func (e ServiceEndpoint) Validate() error {
	switch e.Audience {
	case "public", "authenticated", "private":
	default:
		return errors.New("invalid endpoint audience")
	}
	switch e.Transport {
	case "https":
		if e.ADNLAddress != "" {
			return errors.New("HTTPS endpoint must not contain ADNL address")
		}
		parsed, err := url.ParseRequestURI(e.URL)
		if err != nil || len(e.URL) > MaxStringBytes || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("HTTPS endpoint requires an absolute https URL")
		}
	case "rldp":
		if e.URL != "" || len(e.ADNLAddress) < 16 || len(e.ADNLAddress) > 256 {
			return errors.New("RLDP endpoint requires only a bounded ADNL address")
		}
	case "relay":
		if e.ADNLAddress != "" {
			return errors.New("relay endpoint must not contain ADNL address")
		}
		parsed, err := url.ParseRequestURI(e.URL)
		if err != nil || len(e.URL) > MaxStringBytes || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("relay endpoint requires an absolute https URL")
		}
	default:
		return errors.New("unsupported endpoint transport")
	}
	return nil
}

func (c CapabilityClaim) Validate() error {
	if !serviceIDPattern.MatchString(c.ID) {
		return errors.New("invalid capability id")
	}
	if err := boundedString("capability revision", c.Revision, 1, 128); err != nil {
		return err
	}
	if !c.Evidence.Valid() {
		return errors.New("invalid capability evidence level")
	}
	if len(c.Attributes) > MaxClaimAttributes {
		return errors.New("too many capability attributes")
	}
	for key, value := range c.Attributes {
		if !serviceIDPattern.MatchString(key) {
			return errors.New("invalid capability attribute key")
		}
		if err := boundedString("capability attribute", value, 0, 1024); err != nil {
			return err
		}
	}
	return nil
}

func (e Extension) Validate() error {
	if err := boundedString("extension id", e.ID, 3, 256); err != nil {
		return err
	}
	if strings.ContainsAny(e.ID, " \t\r\n") {
		return errors.New("extension id must not contain whitespace")
	}
	if !digestPattern.MatchString(e.Digest) {
		return errors.New("extension digest must be sha256:<lowercase hex>")
	}
	if e.URL != "" {
		parsed, err := url.ParseRequestURI(e.URL)
		if err != nil || len(e.URL) > MaxStringBytes || parsed.Scheme != "https" || parsed.Host == "" {
			return errors.New("extension URL must be absolute HTTPS")
		}
	}
	return nil
}
