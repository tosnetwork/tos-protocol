// Package ard implements the pinned ARD v0.9 discovery data model. It enforces
// bounded structural validation but does not replace upstream conformance
// testing against the authoritative schemas.
package ard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

const (
	SpecVersion = "1.0"
)

var identifierPattern = regexp.MustCompile(`^urn:air:([a-zA-Z0-9.-]+)(?::[a-zA-Z0-9._-]+)+$`)

type Limits struct {
	MaxCatalogBytes          int64
	MaxEntries               int
	MaxDataBytes             int
	MaxMetadataEntries       int
	MaxExtensions            int
	MaxExtensionBytes        int
	MaxTextBytes             int
	MaxTags                  int
	MaxCapabilities          int
	MaxRepresentativeQueries int
}

func DefaultLimits() Limits {
	return Limits{
		MaxCatalogBytes:          2 << 20,
		MaxEntries:               1024,
		MaxDataBytes:             256 << 10,
		MaxMetadataEntries:       64,
		MaxExtensions:            32,
		MaxExtensionBytes:        64 << 10,
		MaxTextBytes:             4096,
		MaxTags:                  64,
		MaxCapabilities:          128,
		MaxRepresentativeQueries: 5,
	}
}

type Catalog struct {
	SpecVersion string  `json:"specVersion"`
	Host        *Host   `json:"host,omitempty"`
	Entries     []Entry `json:"entries"`
}

type Host struct {
	DisplayName      string         `json:"displayName"`
	Identifier       string         `json:"identifier,omitempty"`
	DocumentationURL string         `json:"documentationUrl,omitempty"`
	LogoURL          string         `json:"logoUrl,omitempty"`
	TrustManifest    *TrustManifest `json:"trustManifest,omitempty"`
}

type Entry struct {
	Identifier            string                     `json:"identifier"`
	DisplayName           string                     `json:"displayName"`
	Type                  string                     `json:"type"`
	URL                   string                     `json:"url,omitempty"`
	Data                  json.RawMessage            `json:"data,omitempty"`
	Description           string                     `json:"description,omitempty"`
	Tags                  []string                   `json:"tags,omitempty"`
	Capabilities          []string                   `json:"capabilities,omitempty"`
	RepresentativeQueries []string                   `json:"representativeQueries,omitempty"`
	Version               string                     `json:"version,omitempty"`
	UpdatedAt             string                     `json:"updatedAt,omitempty"`
	Metadata              map[string]interface{}     `json:"metadata,omitempty"`
	TrustManifest         *TrustManifest             `json:"trustManifest,omitempty"`
	Extensions            map[string]json.RawMessage `json:"-"`
}

type TrustManifest struct {
	Identity     string           `json:"identity"`
	IdentityType string           `json:"identityType,omitempty"`
	TrustSchema  *TrustSchema     `json:"trustSchema,omitempty"`
	Attestations []Attestation    `json:"attestations,omitempty"`
	Provenance   []ProvenanceItem `json:"provenance,omitempty"`
	Signature    string           `json:"signature,omitempty"`
}

type TrustSchema struct {
	Identifier          string   `json:"identifier"`
	Version             string   `json:"version"`
	GovernanceURI       string   `json:"governanceUri,omitempty"`
	VerificationMethods []string `json:"verificationMethods,omitempty"`
}

type Attestation struct {
	Type      string `json:"type"`
	URI       string `json:"uri"`
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest,omitempty"`
}

type ProvenanceItem struct {
	Relation     string `json:"relation"`
	SourceID     string `json:"sourceId"`
	SourceDigest string `json:"sourceDigest,omitempty"`
}

func (e *Entry) UnmarshalJSON(data []byte) error {
	var fields map[string]json.RawMessage
	// Entry is also a public json.Unmarshaler, so enforce the same ambiguity
	// checks even when a caller decodes one entry outside DecodeCatalog.
	if err := jsonstrict.Decode(data, &fields); err != nil {
		return err
	}
	type entryAlias Entry
	var decoded entryAlias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	for _, known := range []string{
		"identifier", "displayName", "type", "url", "data", "description",
		"tags", "capabilities", "representativeQueries", "version", "updatedAt",
		"metadata", "trustManifest",
	} {
		delete(fields, known)
	}
	*e = Entry(decoded)
	if len(fields) != 0 {
		e.Extensions = fields
	}
	return nil
}

func (e Entry) MarshalJSON() ([]byte, error) {
	type entryAlias Entry
	encoded, err := json.Marshal(entryAlias(e))
	if err != nil {
		return nil, err
	}
	if len(e.Extensions) == 0 {
		return encoded, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		return nil, err
	}
	for key, value := range e.Extensions {
		if _, collision := fields[key]; collision {
			return nil, fmt.Errorf("extension %q collides with a standard field", key)
		}
		fields[key] = value
	}
	return json.Marshal(fields)
}

func DecodeCatalog(reader io.Reader, limits Limits) (Catalog, error) {
	if err := limits.validate(); err != nil {
		return Catalog{}, err
	}
	limited := io.LimitReader(reader, limits.MaxCatalogBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return Catalog{}, fmt.Errorf("read catalog: %w", err)
	}
	if int64(len(data)) > limits.MaxCatalogBytes {
		return Catalog{}, errors.New("catalog exceeds byte limit")
	}
	var catalog Catalog
	if err := jsonstrict.Decode(data, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	if err := catalog.Validate(limits); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

func (c Catalog) Validate(limits Limits) error {
	if err := limits.validate(); err != nil {
		return err
	}
	if c.SpecVersion != SpecVersion {
		return fmt.Errorf("unsupported ARD catalog specVersion %q", c.SpecVersion)
	}
	if len(c.Entries) > limits.MaxEntries {
		return errors.New("catalog has too many entries")
	}
	if c.Host != nil {
		if err := validateText("host.displayName", c.Host.DisplayName, 1, limits.MaxTextBytes); err != nil {
			return err
		}
		if c.Host.TrustManifest != nil {
			if err := c.Host.TrustManifest.validate(limits); err != nil {
				return fmt.Errorf("host.trustManifest: %w", err)
			}
		}
	}
	seen := make(map[string]struct{}, len(c.Entries))
	for i := range c.Entries {
		if err := c.Entries[i].Validate(limits); err != nil {
			return fmt.Errorf("entries[%d]: %w", i, err)
		}
		if _, exists := seen[c.Entries[i].Identifier]; exists {
			return fmt.Errorf("entries[%d]: duplicate identifier", i)
		}
		seen[c.Entries[i].Identifier] = struct{}{}
	}
	return nil
}

func (e Entry) Validate(limits Limits) error {
	if _, err := Publisher(e.Identifier); err != nil {
		return err
	}
	if err := validateText("displayName", e.DisplayName, 1, 512); err != nil {
		return err
	}
	if err := validateText("type", e.Type, 1, 256); err != nil {
		return err
	}
	hasURL := e.URL != ""
	hasData := len(e.Data) != 0
	if hasURL == hasData {
		return errors.New("exactly one of url or data is required")
	}
	if hasURL {
		parsed, err := url.ParseRequestURI(e.URL)
		if err != nil || parsed.Scheme == "" {
			return errors.New("url must be an absolute URI")
		}
	}
	if hasData {
		if len(e.Data) > limits.MaxDataBytes {
			return errors.New("embedded data exceeds byte limit")
		}
		var object map[string]interface{}
		if err := jsonstrict.Decode(e.Data, &object); err != nil || object == nil {
			return errors.New("data must be a JSON object")
		}
	}
	if err := validateText("description", e.Description, 0, limits.MaxTextBytes); err != nil {
		return err
	}
	if len(e.Tags) > limits.MaxTags || len(e.Capabilities) > limits.MaxCapabilities {
		return errors.New("tags or capabilities exceed limit")
	}
	if n := len(e.RepresentativeQueries); n != 0 && (n < 2 || n > limits.MaxRepresentativeQueries) {
		return errors.New("representativeQueries must contain 2..5 items when present")
	}
	if len(e.Metadata) > limits.MaxMetadataEntries {
		return errors.New("metadata exceeds entry limit")
	}
	for key, value := range e.Metadata {
		if err := validateText("metadata key", key, 1, 128); err != nil {
			return err
		}
		switch value.(type) {
		case nil, string, float64, bool:
		default:
			return errors.New("metadata values must be scalar")
		}
	}
	if len(e.Extensions) > limits.MaxExtensions {
		return errors.New("entry has too many extension fields")
	}
	extensionBytes := 0
	for key, value := range e.Extensions {
		if err := validateText("extension key", key, 1, 128); err != nil {
			return err
		}
		if !json.Valid(value) {
			return errors.New("entry extension is not valid JSON")
		}
		extensionBytes += len(key) + len(value)
	}
	if extensionBytes > limits.MaxExtensionBytes {
		return errors.New("entry extensions exceed byte limit")
	}
	if _, present, err := DecodeWorkerCatalogExtension(e); present && err != nil {
		return err
	}
	if e.TrustManifest != nil {
		if err := e.TrustManifest.validate(limits); err != nil {
			return fmt.Errorf("trustManifest: %w", err)
		}
	}
	for _, group := range [][]string{e.Tags, e.Capabilities, e.RepresentativeQueries} {
		for _, value := range group {
			if err := validateText("entry list value", value, 1, limits.MaxTextBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func (t TrustManifest) validate(limits Limits) error {
	if err := validateText("identity", t.Identity, 1, limits.MaxTextBytes); err != nil {
		return err
	}
	switch t.IdentityType {
	case "", "spiffe", "did", "https", "other":
	default:
		return errors.New("unsupported identityType")
	}
	if len(t.Attestations) > 32 || len(t.Provenance) > 64 {
		return errors.New("trust manifest lists exceed bounds")
	}
	if t.TrustSchema != nil {
		if err := validateText("trustSchema.identifier", t.TrustSchema.Identifier, 1, 512); err != nil {
			return err
		}
		if err := validateText("trustSchema.version", t.TrustSchema.Version, 1, 128); err != nil {
			return err
		}
		if len(t.TrustSchema.VerificationMethods) > 32 {
			return errors.New("too many trust verification methods")
		}
	}
	for _, attestation := range t.Attestations {
		if err := validateText("attestation.type", attestation.Type, 1, 256); err != nil {
			return err
		}
		if err := validateText("attestation.uri", attestation.URI, 1, limits.MaxTextBytes); err != nil {
			return err
		}
		if err := validateText("attestation.mediaType", attestation.MediaType, 1, 256); err != nil {
			return err
		}
	}
	for _, provenance := range t.Provenance {
		switch provenance.Relation {
		case "derivedFrom", "publishedFrom", "copiedFrom":
		default:
			return errors.New("invalid provenance relation")
		}
		if err := validateText("provenance.sourceId", provenance.SourceID, 1, limits.MaxTextBytes); err != nil {
			return err
		}
	}
	return nil
}

func Publisher(identifier string) (string, error) {
	match := identifierPattern.FindStringSubmatch(identifier)
	if match == nil {
		return "", errors.New("identifier must be a domain-anchored urn:air value")
	}
	publisher := strings.ToLower(match[1])
	if strings.Contains(publisher, "..") || net.ParseIP(publisher) != nil || !strings.Contains(publisher, ".") {
		return "", errors.New("identifier publisher must be an FQDN")
	}
	return publisher, nil
}

func (l Limits) validate() error {
	if l.MaxCatalogBytes <= 0 || l.MaxEntries <= 0 || l.MaxDataBytes <= 0 ||
		l.MaxMetadataEntries <= 0 || l.MaxExtensions <= 0 || l.MaxExtensionBytes <= 0 ||
		l.MaxTextBytes <= 0 || l.MaxTags <= 0 ||
		l.MaxCapabilities <= 0 || l.MaxRepresentativeQueries < 2 {
		return errors.New("invalid ARD limits")
	}
	return nil
}

func validateText(name, value string, minBytes, maxBytes int) error {
	if len(value) < minBytes || len(value) > maxBytes || strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s has invalid length or content", name)
	}
	return nil
}
