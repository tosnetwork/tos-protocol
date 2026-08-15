// Package capabilitycatalog maintains a derived, incomplete discovery set of
// Capability IDs and immutable software-work manifests. Every returned state
// is freshly resolved from finalized TOS state; the catalog is never authority.
package capabilitycatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

type NativeResolver interface {
	ResolveNativeState(context.Context, *nativev1.ResolveNativeStateRequest) (*nativev1.ResolveNativeStateResponse, error)
}

type Config struct {
	Directory        string
	Resolver         NativeResolver
	Network          *nativev1.NetworkDomain
	RegistryCodeHash string
	CallerID         string
	ResolveTimeout   time.Duration
	MaxEntries       uint32
	Now              func() time.Time
}

type Catalog struct {
	store            *fileStore
	resolver         NativeResolver
	network          *nativev1.NetworkDomain
	registryCodeHash string
	callerID         string
	resolveTimeout   time.Duration
	now              func() time.Time
}

type Page struct {
	Capabilities []*nativev1.NativeStateV1
	NextToken    string
}

type SearchPage struct {
	Results   []*nativev1.CapabilitySearchResultV1
	NextToken string
}

func New(config Config) (*Catalog, error) {
	if config.Resolver == nil || config.Network == nil || config.Network.NetworkId == "" ||
		config.RegistryCodeHash == "" || config.CallerID == "" {
		return nil, errors.New("invalid Capability catalog configuration")
	}
	if config.ResolveTimeout == 0 {
		config.ResolveTimeout = 30 * time.Second
	}
	if config.ResolveTimeout < time.Second || config.ResolveTimeout > 5*time.Minute {
		return nil, errors.New("invalid Capability catalog resolution timeout")
	}
	if config.MaxEntries == 0 {
		config.MaxEntries = 10_000
	}
	if config.MaxEntries > 1_000_000 {
		return nil, errors.New("Capability catalog entry bound is too large")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	store, err := newFileStore(config.Directory, config.MaxEntries)
	if err != nil {
		return nil, err
	}
	return &Catalog{store: store, resolver: config.Resolver,
		network: proto.Clone(config.Network).(*nativev1.NetworkDomain), registryCodeHash: config.RegistryCodeHash,
		callerID: config.CallerID, resolveTimeout: config.ResolveTimeout, now: config.Now}, nil
}

// PublishManifest admits bytes only after a fresh finalized Capability read
// proves that its exact version currently commits to their digest.
func (c *Catalog) PublishManifest(ctx context.Context, capabilityID string, canonicalCBOR []byte) (*nativev1.NativeStateV1, string, error) {
	if c == nil || ctx == nil || !capabilityIDValid(capabilityID) {
		return nil, "", errors.New("invalid Capability manifest publication")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(canonicalCBOR)
	if err != nil {
		return nil, "", fmt.Errorf("decode canonical Capability manifest: %w", err)
	}
	digestBytes := sha256.Sum256(canonicalCBOR)
	digest := "sha256:" + hex.EncodeToString(digestBytes[:])
	state, err := c.resolve(ctx, capabilityID)
	if err != nil {
		return nil, "", err
	}
	capability := state.GetCapability()
	linked := false
	for _, version := range capability.Versions {
		if version != nil && version.Version == manifest.Version && version.ManifestDigest == digest && !version.Revoked {
			linked = true
			break
		}
	}
	if !linked || capability.Tombstoned {
		return nil, "", errors.New("manifest is not committed by an active finalized Capability version")
	}
	if err := c.store.publish(state, digest, canonicalCBOR); err != nil {
		return nil, "", err
	}
	return proto.Clone(state).(*nativev1.NativeStateV1), digest, nil
}

// Manifest returns immutable canonical bytes by digest. The caller must still
// compare that digest with the freshly resolved Capability or Accepted Quote.
func (c *Catalog) Manifest(digest string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("Capability catalog is unavailable")
	}
	return c.store.manifest(digest)
}

// List returns a page from the gateway's incomplete discovery set, but every
// included state is re-resolved and validated at finalized TOS state. The page
// token is the last scanned Capability ID, not a completeness claim.
func (c *Catalog) List(ctx context.Context, pageSize uint32, after string) (*Page, error) {
	if c == nil || ctx == nil || (after != "" && !capabilityIDValid(after)) {
		return nil, errors.New("invalid Capability catalog request")
	}
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		return nil, errors.New("Capability catalog page is too large")
	}
	entries, err := c.store.entries()
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CapabilityID < entries[j].CapabilityID })
	start := sort.Search(len(entries), func(i int) bool { return entries[i].CapabilityID > after })
	page := &Page{}
	end := start + int(pageSize)
	if end > len(entries) {
		end = len(entries)
	}
	for index := start; index < end; index++ {
		entry := entries[index]
		state, err := c.resolve(ctx, entry.CapabilityID)
		if err != nil {
			return nil, err
		}
		if state.Reference.FinalizedCheckpoint < entry.FinalizedCheckpoint {
			return nil, errors.New("finalized Capability observation rolled back behind catalog fence")
		}
		if err := c.store.observe(state); err != nil {
			return nil, err
		}
		if !state.GetCapability().Tombstoned {
			page.Capabilities = append(page.Capabilities, state)
		}
	}
	if end < len(entries) {
		page.NextToken = entries[end-1].CapabilityID
	}
	return page, nil
}

// Search scans the gateway-local discovery set in Capability-ID order. Chain
// state, selected version, and digest remain separate from the explicitly
// local manifest projection and score.
func (c *Catalog) Search(ctx context.Context, query string, pageSize uint32, after string) (*SearchPage, error) {
	query = strings.TrimSpace(query)
	if c == nil || ctx == nil || query == "" || len(query) > 128 ||
		(after != "" && !capabilityIDValid(after)) {
		return nil, errors.New("invalid Capability search request")
	}
	if pageSize == 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		return nil, errors.New("Capability search page is too large")
	}
	tokens := strings.Fields(strings.ToLower(query))
	if len(tokens) == 0 || len(tokens) > 16 {
		return nil, errors.New("invalid Capability search query")
	}
	entries, err := c.store.entries()
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].CapabilityID < entries[j].CapabilityID })
	start := sort.Search(len(entries), func(i int) bool { return entries[i].CapabilityID > after })
	page := &SearchPage{}
	lastScanned := start - 1
	for index := start; index < len(entries) && uint32(len(page.Results)) < pageSize; index++ {
		lastScanned = index
		entry := entries[index]
		state, err := c.resolve(ctx, entry.CapabilityID)
		if err != nil {
			return nil, err
		}
		if state.Reference.FinalizedCheckpoint < entry.FinalizedCheckpoint {
			return nil, errors.New("finalized Capability observation rolled back behind catalog fence")
		}
		if err := c.store.observe(state); err != nil {
			return nil, err
		}
		capability := state.GetCapability()
		if capability.Tombstoned {
			continue
		}
		result, err := c.searchResult(state, tokens)
		if err != nil {
			return nil, err
		}
		if result != nil {
			page.Results = append(page.Results, result)
		}
	}
	if lastScanned >= start && lastScanned+1 < len(entries) {
		page.NextToken = entries[lastScanned].CapabilityID
	}
	return page, nil
}

func (c *Catalog) searchResult(state *nativev1.NativeStateV1, tokens []string) (*nativev1.CapabilitySearchResultV1, error) {
	capability := state.GetCapability()
	var best *nativev1.CapabilitySearchResultV1
	for _, version := range capability.Versions {
		if version == nil || version.Revoked {
			continue
		}
		raw, err := c.store.manifest(version.ManifestDigest)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(raw)
		if err != nil || manifest.Version != version.Version {
			return nil, errors.New("stored manifest conflicts with finalized Capability version")
		}
		score := searchScore(tokens, capability.CapabilityId, capability.OwnerAgentId,
			version.Version, version.ManifestDigest, manifest.Name, manifest.Description, manifest.Operation)
		if score == 0 {
			continue
		}
		candidate := &nativev1.CapabilitySearchResultV1{Capability: proto.Clone(state).(*nativev1.NativeStateV1),
			CapabilityVersion: version.Version, ManifestDigest: version.ManifestDigest,
			GatewayLocal: &nativev1.GatewayLocalCapabilityMetadataV1{Name: manifest.Name,
				Description: manifest.Description, Operation: manifest.Operation, MatchScore: score}}
		if best == nil || score > best.GatewayLocal.MatchScore ||
			score == best.GatewayLocal.MatchScore && version.Version < best.CapabilityVersion {
			best = candidate
		}
	}
	return best, nil
}

func searchScore(tokens []string, fields ...string) uint32 {
	values := make([]string, len(fields))
	for index, field := range fields {
		values[index] = strings.ToLower(field)
	}
	var score uint32
	for _, token := range tokens {
		matched := false
		for index, value := range values {
			if strings.Contains(value, token) {
				matched = true
				weight := uint32(2)
				if index < 4 {
					weight = 12
				} else if index == 4 || index == 6 {
					weight = 8
				}
				score += weight
				break
			}
		}
		if !matched {
			return 0
		}
	}
	return score
}

func (c *Catalog) resolve(ctx context.Context, capabilityID string) (*nativev1.NativeStateV1, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, c.resolveTimeout)
	defer cancel()
	requestID := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%d", c.callerID, capabilityID, c.now().UnixNano())))
	response, err := c.resolver.ResolveNativeState(resolveCtx, &nativev1.ResolveNativeStateRequest{
		Context: &nativev1.RequestContext{RequestId: hex.EncodeToString(requestID[:]), CallerId: c.callerID,
			DeadlineUnixMillis: c.now().Add(c.resolveTimeout).UnixMilli()}, ObjectId: capabilityID,
	})
	if err != nil {
		return nil, err
	}
	if response == nil || !response.Found || response.State == nil || response.State.GetCapability() == nil ||
		!proto.Equal(response.State.Network, c.network) || response.State.TvmStateHash == "" ||
		response.State.Reference == nil || response.State.Reference.FinalizedCheckpoint == 0 ||
		response.State.Reference.ContractCodeHash != c.registryCodeHash {
		return nil, errors.New("Capability is absent or not valid finalized typed state")
	}
	capability := response.State.GetCapability()
	if capability.CapabilityId != capabilityID || capability.OwnerAgentId == "" ||
		capability.Generation == 0 || capability.Sequence == 0 || capability.LastActionHash == "" {
		return nil, errors.New("finalized Capability state is structurally invalid")
	}
	seenVersions := make(map[string]struct{}, len(capability.Versions))
	for _, version := range capability.Versions {
		if version == nil || version.Version == "" || !digestValid(version.ManifestDigest) {
			return nil, errors.New("finalized Capability version is structurally invalid")
		}
		if _, duplicate := seenVersions[version.Version]; duplicate {
			return nil, errors.New("finalized Capability contains duplicate versions")
		}
		seenVersions[version.Version] = struct{}{}
	}
	if len(seenVersions) == 0 {
		return nil, errors.New("finalized Capability contains no versions")
	}
	return proto.Clone(response.State).(*nativev1.NativeStateV1), nil
}

func capabilityIDValid(value string) bool {
	if len(value) != 68 || !strings.HasPrefix(value, "cap_") {
		return false
	}
	raw, err := hex.DecodeString(value[4:])
	return err == nil && !bytes.Equal(raw, make([]byte, 32)) && value == strings.ToLower(value)
}

func digestValid(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[7:])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}
