// Package protocol defines the generic TOS service descriptor and common
// validation primitives. Profile-specific fields belong in vertical modules.
package protocol

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	DescriptorVersion = "0.1"
	MaxProfiles       = 32
	MaxStringBytes    = 4096
)

var (
	serviceIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{2,127}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// ServiceDescriptor is served at /.well-known/tos-service.json. Discovery
// data is not authorization, availability, price, or a payment destination.
type ServiceDescriptor struct {
	ProtocolVersion string             `json:"protocolVersion"`
	ServiceID       string             `json:"serviceId"`
	DisplayName     string             `json:"displayName"`
	Controller      string             `json:"controller"`
	Network         string             `json:"network"`
	Revision        string             `json:"revision"`
	ExpiresAt       time.Time          `json:"expiresAt"`
	Profiles        []ProfileReference `json:"profiles"`
	ARDIdentifier   string             `json:"ardIdentifier,omitempty"`
	TOSName         string             `json:"tosName,omitempty"`
	ADNLAddress     string             `json:"adnlAddress,omitempty"`
}

type ProfileReference struct {
	ID        string `json:"id"`
	Version   string `json:"version"`
	MediaType string `json:"mediaType"`
	URL       string `json:"url"`
	Digest    string `json:"digest"`
}

func (d ServiceDescriptor) Validate(now time.Time) error {
	if d.ProtocolVersion != DescriptorVersion {
		return fmt.Errorf("unsupported protocol version %q", d.ProtocolVersion)
	}
	if !serviceIDPattern.MatchString(d.ServiceID) {
		return errors.New("invalid serviceId")
	}
	if err := boundedString("displayName", d.DisplayName, 1, 256); err != nil {
		return err
	}
	if err := boundedString("controller", d.Controller, 1, 512); err != nil {
		return err
	}
	if err := boundedString("network", d.Network, 1, 64); err != nil {
		return err
	}
	if err := boundedString("revision", d.Revision, 1, 128); err != nil {
		return err
	}
	if d.ExpiresAt.IsZero() || !d.ExpiresAt.After(now) {
		return errors.New("descriptor is expired")
	}
	if len(d.Profiles) == 0 || len(d.Profiles) > MaxProfiles {
		return fmt.Errorf("profiles must contain 1..%d entries", MaxProfiles)
	}
	seen := make(map[string]struct{}, len(d.Profiles))
	for i, profile := range d.Profiles {
		if err := profile.Validate(); err != nil {
			return fmt.Errorf("profiles[%d]: %w", i, err)
		}
		key := profile.ID + "\x00" + profile.Version
		if _, ok := seen[key]; ok {
			return fmt.Errorf("profiles[%d]: duplicate profile", i)
		}
		seen[key] = struct{}{}
	}
	if d.TOSName != "" && !strings.HasSuffix(strings.ToLower(d.TOSName), ".tos") {
		return errors.New("tosName must end in .tos")
	}
	return nil
}

func (p ProfileReference) Validate() error {
	if !serviceIDPattern.MatchString(p.ID) {
		return errors.New("invalid profile id")
	}
	if err := boundedString("version", p.Version, 1, 64); err != nil {
		return err
	}
	if err := boundedString("mediaType", p.MediaType, 1, 256); err != nil {
		return err
	}
	parsed, err := url.ParseRequestURI(p.URL)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return errors.New("profile URL must be an absolute HTTP(S) URL")
	}
	if !digestPattern.MatchString(p.Digest) {
		return errors.New("profile digest must be sha256:<lowercase hex>")
	}
	return nil
}

func boundedString(name, value string, minBytes, maxBytes int) error {
	n := len(value)
	if n < minBytes || n > maxBytes || n > MaxStringBytes {
		return fmt.Errorf("%s length is outside %d..%d bytes", name, minBytes, maxBytes)
	}
	if strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("%s contains NUL", name)
	}
	return nil
}
