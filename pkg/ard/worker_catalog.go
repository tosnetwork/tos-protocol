package ard

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

const (
	workerCatalogEntryType        = "application/vnd.tos.service+json"
	WorkerCatalogExtensionName    = "x-tos-worker-capabilities"
	WorkerCatalogExtensionVersion = "0.1"
)

// WorkerCatalogConfig contains only operator-approved public discovery data.
// Dynamic capacity, local paths, endpoints, and hardware identifiers are never
// copied from the private Worker snapshot.
type WorkerCatalogConfig struct {
	ServiceIdentifier  string
	ServiceDisplayName string
	HostDisplayName    string
	HostIdentifier     string
	ServiceURL         string
	EntryVersion       string
}

// WorkerCatalogCapability is the public, capacity-independent subset of one
// externally callable private Worker capability.
type WorkerCatalogCapability struct {
	ServiceID       string `json:"serviceId"`
	Operation       string `json:"operation"`
	Model           string `json:"model"`
	ModelDigest     string `json:"modelDigest"`
	Runtime         string `json:"runtime"`
	RuntimeRevision string `json:"runtimeRevision"`
	MaxInputBytes   string `json:"maxInputBytes"`
	MaxOutputBytes  string `json:"maxOutputBytes"`
}

// WorkerCatalogExtension is embedded in one ARD service entry. One entry maps
// to one TOS service descriptor and therefore to exactly one ARD identifier.
type WorkerCatalogExtension struct {
	Version          string                    `json:"version"`
	TerminalRevision string                    `json:"terminalRevision"`
	Capabilities     []WorkerCatalogCapability `json:"capabilities"`
}

// BuildWorkerCatalog maps a fresh, fully validated private Worker capability
// snapshot into one deterministic ARD service entry. Only capabilities that
// accept external-service work are included.
func BuildWorkerCatalog(
	config WorkerCatalogConfig,
	response *edgev1.GetCapabilitiesResponse,
	now time.Time,
) (Catalog, error) {
	config, err := validateWorkerCatalogConfig(config)
	if err != nil {
		return Catalog{}, err
	}
	if err := localrpc.ValidateWorkerCapabilitiesResponse(response, now); err != nil {
		return Catalog{}, fmt.Errorf("validate Worker capability snapshot: %w", err)
	}
	capabilities := make([]*edgev1.Capability, 0, len(response.Capabilities))
	for _, capability := range response.Capabilities {
		if acceptsExternalService(capability.AcceptedPriorities) {
			if !canonicalSHA256Digest(capability.ModelDigest) {
				return Catalog{}, errors.New(
					"externally callable Worker capability has invalid model digest",
				)
			}
			capabilities = append(capabilities, capability)
		}
	}
	if len(capabilities) == 0 {
		return Catalog{}, errors.New("Worker has no externally callable capabilities")
	}
	sort.Slice(capabilities, func(left, right int) bool {
		return workerCapabilitySortKey(capabilities[left]) <
			workerCapabilitySortKey(capabilities[right])
	})
	extension := WorkerCatalogExtension{
		Version:          WorkerCatalogExtensionVersion,
		TerminalRevision: response.TerminalRevision,
		Capabilities:     make([]WorkerCatalogCapability, 0, len(capabilities)),
	}
	for _, capability := range capabilities {
		extension.Capabilities = append(
			extension.Capabilities,
			WorkerCatalogCapability{
				ServiceID: capability.ServiceId, Operation: capability.Operation,
				Model: capability.Model, ModelDigest: capability.ModelDigest,
				Runtime: capability.Runtime, RuntimeRevision: capability.RuntimeRevision,
				MaxInputBytes:  strconv.FormatUint(capability.MaxInputBytes, 10),
				MaxOutputBytes: strconv.FormatUint(capability.MaxOutputBytes, 10),
			},
		)
	}
	extensionJSON, err := json.Marshal(extension)
	if err != nil {
		return Catalog{}, fmt.Errorf("encode Worker ARD extension: %w", err)
	}
	catalog := Catalog{
		SpecVersion: SpecVersion,
		Host: &Host{
			DisplayName: config.HostDisplayName,
			Identifier:  config.HostIdentifier,
		},
		Entries: []Entry{{
			Identifier:   config.ServiceIdentifier,
			DisplayName:  config.ServiceDisplayName,
			Type:         workerCatalogEntryType,
			URL:          config.ServiceURL,
			Description:  "TOS AI edge inference service.",
			Tags:         []string{"tos", "edge-ai", "local-first"},
			Capabilities: []string{"inference"},
			Version:      config.EntryVersion,
			UpdatedAt: time.UnixMilli(response.CollectedUnixMillis).
				UTC().Format(time.RFC3339Nano),
			Metadata: map[string]interface{}{
				"capabilityCount":  strconv.Itoa(len(capabilities)),
				"terminalRevision": response.TerminalRevision,
			},
			Extensions: map[string]json.RawMessage{
				WorkerCatalogExtensionName: extensionJSON,
			},
		}},
	}
	if err := catalog.Validate(DefaultLimits()); err != nil {
		return Catalog{}, fmt.Errorf("validate generated ARD catalog: %w", err)
	}
	return catalog, nil
}

func validateWorkerCatalogConfig(
	config WorkerCatalogConfig,
) (WorkerCatalogConfig, error) {
	publisher, err := Publisher(config.ServiceIdentifier)
	if err != nil || !canonicalPublisherDomain(publisher) ||
		!strings.HasPrefix(config.ServiceIdentifier, "urn:air:"+publisher+":") {
		return WorkerCatalogConfig{}, errors.New("invalid ARD service identifier")
	}
	if err := validateText(
		"service display name", config.ServiceDisplayName, 1, 512,
	); err != nil {
		return WorkerCatalogConfig{}, err
	}
	if err := validateText(
		"host display name", config.HostDisplayName, 1, 512,
	); err != nil {
		return WorkerCatalogConfig{}, err
	}
	if err := validateText(
		"host identifier", config.HostIdentifier, 0, 4096,
	); err != nil {
		return WorkerCatalogConfig{}, err
	}
	if err := validateText("entry version", config.EntryVersion, 1, 128); err != nil {
		return WorkerCatalogConfig{}, err
	}
	parsed, err := url.ParseRequestURI(config.ServiceURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.Fragment != "" {
		return WorkerCatalogConfig{}, errors.New(
			"ARD service URL must be an absolute HTTPS URL without userinfo or fragment",
		)
	}
	return config, nil
}

func canonicalPublisherDomain(value string) bool {
	if len(value) > 253 || strings.HasPrefix(value, ".") ||
		strings.HasSuffix(value, ".") {
		return false
	}
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' ||
			label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func canonicalSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(value, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(value, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}

func acceptsExternalService(priorities []edgev1.Priority) bool {
	for _, priority := range priorities {
		if priority == edgev1.Priority_PRIORITY_EXTERNAL_SERVICE {
			return true
		}
	}
	return false
}

func workerCapabilitySortKey(capability *edgev1.Capability) string {
	return capability.ServiceId + "\x00" + capability.Operation + "\x00" +
		capability.Model
}
