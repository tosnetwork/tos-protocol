// Package dnsalias verifies the narrow .tos -> Native object alias boundary.
// DNS discovery never replaces finalized Native identity or authorization.
package dnsalias

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"google.golang.org/protobuf/proto"
)

const (
	MaxNameBytes    = 126
	MaxResolverHops = 8
	LeaseSeconds    = uint64(31_622_400)
)

var categoryNames = map[nativev1.DNSAliasKindV1]string{
	nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT:      "agent",
	nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY: "capability",
	nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER:  "messenger",
}

// ChainResult is produced by a quorum-backed resolver after verifying every
// DNS hop, the canonical Domain Item, its collection and its lifecycle at one
// immutable checkpoint. ResolverPath is ordered Root -> Collection -> Item ->
// optional delegates and contains canonical raw addresses.
type ChainResult struct {
	CanonicalName string
	CategoryHash  string
	Resolved      string
	Checkpoint    *nativev1.DNSCheckpointV1
	Lifecycle     *nativev1.DNSLifecycleV1
	ResolverPath  []string
}

type ChainResolver interface {
	ResolveDNSAtFinalizedCheckpoint(context.Context, string, string) (*ChainResult, error)
}

// NativeResolver must read and decode the deterministic Registry account at
// exactly checkpoint. An implementation that performs a fresh independent
// latest-state read does not satisfy this interface.
type NativeResolver interface {
	ResolveNativeAtCheckpoint(context.Context, string, *nativev1.DNSCheckpointV1) (*nativev1.NativeStateV1, bool, error)
}

type Resolver struct {
	chain   ChainResolver
	native  NativeResolver
	locator *nativecore.Locator
	now     func() time.Time
}

func NewResolver(chain ChainResolver, native NativeResolver, locator *nativecore.Locator) (*Resolver, error) {
	if chain == nil || native == nil || locator == nil {
		return nil, errors.New("DNS alias resolver requires chain, Native resolver, and locator")
	}
	return &Resolver{chain: chain, native: native, locator: locator, now: time.Now}, nil
}

func Category(kind nativev1.DNSAliasKindV1) (string, string, error) {
	name, ok := categoryNames[kind]
	if !ok {
		return "", "", errors.New("unsupported DNS alias kind")
	}
	digest := sha256.Sum256([]byte(name))
	return name, hex.EncodeToString(digest[:]), nil
}

func CanonicalName(name string) (string, error) {
	if len(name) == 0 || len(name) > MaxNameBytes || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return "", errors.New("invalid .tos name length or boundary")
	}
	parts := strings.Split(name, ".")
	if len(parts) < 2 || parts[len(parts)-1] != "tos" {
		return "", errors.New("name is not canonical .tos")
	}
	for _, part := range parts {
		if part == "" {
			return "", errors.New(".tos name contains an empty component")
		}
		for i := 0; i < len(part); i++ {
			b := part[i]
			if b < 0x21 || b > 0x7e || b >= 'A' && b <= 'Z' || b == '/' || b == ':' {
				return "", errors.New(".tos name contains a non-canonical byte")
			}
		}
	}
	return name, nil
}

func EncodeName(name string) ([]byte, error) {
	canonical, err := CanonicalName(name)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(canonical, ".")
	encoded := make([]byte, 0, len(canonical)+1)
	for i := len(parts) - 1; i >= 0; i-- {
		encoded = append(encoded, parts[i]...)
		encoded = append(encoded, 0)
	}
	if len(encoded) > 127 {
		return nil, errors.New("encoded .tos name exceeds 127 bytes")
	}
	return encoded, nil
}

func (r *Resolver) ResolveDNSAlias(ctx context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
	if r == nil || request == nil || request.Context == nil || request.Context.RequestId == "" || request.Context.CallerId == "" {
		return nil, errors.New("complete DNS alias request context is required")
	}
	if request.Context.DeadlineUnixMillis <= 0 || !r.now().Before(time.UnixMilli(request.Context.DeadlineUnixMillis)) {
		return nil, errors.New("DNS alias request deadline expired")
	}
	name, err := CanonicalName(request.Name)
	if err != nil {
		return nil, err
	}
	_, categoryHash, err := Category(request.Kind)
	if err != nil {
		return nil, err
	}
	chain, err := r.chain.ResolveDNSAtFinalizedCheckpoint(ctx, name, categoryHash)
	if err != nil {
		return nil, fmt.Errorf("resolve finalized .tos alias: %w", err)
	}
	evaluationTime := uint64(r.now().Unix())
	if chain != nil && chain.Checkpoint != nil && chain.Checkpoint.GenerationUnixSeconds > evaluationTime {
		evaluationTime = chain.Checkpoint.GenerationUnixSeconds
	}
	if err := validateChainResult(chain, name, categoryHash, evaluationTime); err != nil {
		return nil, err
	}

	// The chain resolver supplies the account address but not the Native object
	// ID. A Registry-aware implementation obtains the ID while decoding typed
	// state at this same checkpoint.
	state, found, err := r.native.ResolveNativeAtCheckpoint(ctx, chain.Resolved, chain.Checkpoint)
	if err != nil {
		return nil, fmt.Errorf("resolve Native alias target: %w", err)
	}
	if !found || state == nil {
		return nil, errors.New("DNS alias target is not a finalized Native object")
	}
	objectID, err := validateNativeTarget(request.Kind, state)
	if err != nil {
		return nil, err
	}
	identity, err := r.locator.Locate(objectID)
	if err != nil || identity.Address != chain.Resolved {
		return nil, errors.New("DNS alias target fails deterministic Native address derivation")
	}
	if state.Reference == nil || state.Reference.Account != chain.Resolved ||
		state.Reference.FinalizedCheckpoint != chain.Checkpoint.Sequence ||
		state.Reference.ContractCodeHash != identity.CodeHash || !proto.Equal(state.Network, r.locator.Network) {
		return nil, errors.New("DNS alias Native state provenance does not match its checkpoint or account")
	}
	if capability := state.GetCapability(); capability != nil {
		ownerIdentity, locateErr := r.locator.Locate(capability.OwnerAgentId)
		if locateErr != nil {
			return nil, errors.New("DNS Capability owner identity is invalid")
		}
		owner, ownerFound, resolveErr := r.native.ResolveNativeAtCheckpoint(ctx, ownerIdentity.Address, chain.Checkpoint)
		if resolveErr != nil || !ownerFound || owner == nil {
			return nil, errors.New("DNS Capability owner is not available at the alias checkpoint")
		}
		ownerID, ownerErr := validateNativeTarget(nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, owner)
		if ownerErr != nil || ownerID != capability.OwnerAgentId || owner.Reference == nil ||
			owner.Reference.Account != ownerIdentity.Address || owner.Reference.FinalizedCheckpoint != chain.Checkpoint.Sequence ||
			owner.Reference.ContractCodeHash != ownerIdentity.CodeHash || !proto.Equal(owner.Network, r.locator.Network) {
			return nil, errors.New("DNS Capability owner fails finalized Native verification")
		}
	}

	parsed, _ := address.ParseRawAddr(chain.Resolved)
	path := make([]*nativev1.TOSAccountAddressV1, 0, len(chain.ResolverPath))
	for _, value := range chain.ResolverPath {
		item, _ := address.ParseRawAddr(value)
		path = append(path, &nativev1.TOSAccountAddressV1{Workchain: item.Workchain(), AccountId: append([]byte(nil), item.Data()...)})
	}
	return &nativev1.ResolveDNSAliasResponse{
		CanonicalName: name, Kind: request.Kind, CategoryHash: categoryHash,
		ResolvedAccount: &nativev1.TOSAccountAddressV1{Workchain: parsed.Workchain(), AccountId: append([]byte(nil), parsed.Data()...)},
		NativeObjectId:  objectID, NativeState: proto.Clone(state).(*nativev1.NativeStateV1),
		Checkpoint:   proto.Clone(chain.Checkpoint).(*nativev1.DNSCheckpointV1),
		Lifecycle:    proto.Clone(chain.Lifecycle).(*nativev1.DNSLifecycleV1),
		Provenance:   nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED,
		ResolverPath: path,
	}, nil
}

func validateChainResult(result *ChainResult, name, categoryHash string, now uint64) error {
	if result == nil || result.CanonicalName != name || result.CategoryHash != categoryHash {
		return errors.New("DNS result does not match the requested name and category")
	}
	if err := validateCheckpoint(result.Checkpoint); err != nil {
		return err
	}
	if len(result.ResolverPath) < 3 || len(result.ResolverPath) > MaxResolverHops {
		return errors.New("DNS resolver path is outside 3..8 hops")
	}
	seen := make(map[string]struct{}, len(result.ResolverPath))
	for _, value := range result.ResolverPath {
		canonical, err := canonicalRawAddress(value)
		if err != nil || canonical != value {
			return errors.New("DNS resolver path contains a non-canonical address")
		}
		if _, duplicate := seen[value]; duplicate {
			return errors.New("DNS resolver path contains a cycle")
		}
		seen[value] = struct{}{}
	}
	if canonical, err := canonicalRawAddress(result.Resolved); err != nil || canonical != result.Resolved {
		return errors.New("DNS target is not a canonical raw address")
	}
	return validateLifecycle(result.Lifecycle, now)
}

func validateCheckpoint(value *nativev1.DNSCheckpointV1) error {
	if value == nil || value.Workchain != -1 || value.Sequence == 0 || value.GenerationUnixSeconds == 0 ||
		len(value.RootHash) != 32 || len(value.FileHash) != 32 {
		return errors.New("invalid DNS finalized checkpoint")
	}
	return nil
}

func validateLifecycle(value *nativev1.DNSLifecycleV1, now uint64) error {
	if value == nil || value.AuctionEndUnixSeconds != 0 || value.LastFillUpUnixSeconds == 0 {
		return errors.New("DNS Domain Item is auctioning, unfinalized, or lacks a renewal clock")
	}
	if value.LastFillUpUnixSeconds > math.MaxUint64-LeaseSeconds {
		return errors.New("DNS renewal deadline overflows")
	}
	deadline := value.LastFillUpUnixSeconds + LeaseSeconds
	if value.RenewalDeadlineUnixSeconds != deadline || now > deadline {
		return errors.New("DNS Domain Item is overdue or has an invalid renewal deadline")
	}
	return nil
}

func validateNativeTarget(kind nativev1.DNSAliasKindV1, state *nativev1.NativeStateV1) (string, error) {
	switch kind {
	case nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER:
		agent := state.GetAgent()
		if agent == nil || agent.Tombstoned || !strings.HasPrefix(agent.AgentId, "agent_") {
			return "", errors.New("DNS alias does not resolve to a live Agent")
		}
		return agent.AgentId, nil
	case nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY:
		capability := state.GetCapability()
		if capability == nil || capability.Tombstoned || !strings.HasPrefix(capability.CapabilityId, "cap_") {
			return "", errors.New("DNS alias does not resolve to a live Capability")
		}
		return capability.CapabilityId, nil
	default:
		return "", errors.New("unsupported DNS alias kind")
	}
}

func canonicalRawAddress(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return "", errors.New("invalid TOS address")
	}
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 {
		return "", errors.New("invalid standard TOS address")
	}
	return parsed.StringRaw(), nil
}
