package toschain

import (
	"context"
	"errors"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tosutils-go/address"
)

// AgentAccountAgentBinding is owner-pinned local policy. The chain proves the
// Agent Account and its owner; this binding says which Agent principal the
// owner permits a relay Provider to associate with that exact account. It is
// deliberately not learned from an Intent, relay request, or Provider quote.
type AgentAccountAgentBinding struct {
	SourceAccount     string
	OwnerAddress      string
	AuthorizedAgentID string
}

// finalizedAgentAccountReader is the narrow read-side seam implemented by
// AgentGiftReader. Keeping it private lets tests exercise policy failures
// without weakening the production constructor below.
type finalizedAgentAccountReader interface {
	FinalizedAgentAccount(context.Context, string) (agentgift.FinalizedAgentAccount, uint32, error)
}

// AgentGiftFinalizedAgentAccountResolver adapts the existing checkpoint-pinned
// AgentGiftReader to the relay transaction inspector. The mutable account state
// always comes from a fresh finalized quorum read. Only the account-to-Agent
// association comes from immutable owner configuration.
type AgentGiftFinalizedAgentAccountResolver struct {
	reader   finalizedAgentAccountReader
	network  agentrelay.NetworkDomain
	bindings map[string]AgentAccountAgentBinding
}

// NewAgentGiftFinalizedAgentAccountResolver constructs the production
// resolver. AgentGiftReader already performs strict endpoint-quorum reads at a
// consensus checkpoint and validates the Agent Account code/state layout.
func NewAgentGiftFinalizedAgentAccountResolver(reader *AgentGiftReader, network agentrelay.NetworkDomain,
	bindings []AgentAccountAgentBinding) (*AgentGiftFinalizedAgentAccountResolver, error) {
	if reader == nil || reader.chain == nil || reader.network == nil || reader.chain.pinnedDomain == nil ||
		!samePinnedRelayNetwork(*reader.chain.pinnedDomain, network) || reader.network.NetworkId != network.NetworkID ||
		reader.network.GenesisRootHash != network.ZeroStateRootHash ||
		reader.network.GenesisFileHash != network.ZeroStateFileHash {
		return nil, errors.New("invalid Agent Account relay resolver configuration")
	}
	return newAgentGiftFinalizedAgentAccountResolver(reader, network, bindings)
}

func newAgentGiftFinalizedAgentAccountResolver(reader finalizedAgentAccountReader,
	network agentrelay.NetworkDomain, bindings []AgentAccountAgentBinding) (*AgentGiftFinalizedAgentAccountResolver, error) {
	if reader == nil || len(bindings) == 0 {
		return nil, errors.New("Agent Account relay resolver requires an account reader and owner bindings")
	}
	if _, err := agentrelay.NetworkDomainDigest(network); err != nil {
		return nil, errors.New("Agent Account relay resolver network is invalid")
	}
	resolved := &AgentGiftFinalizedAgentAccountResolver{reader: reader, network: network,
		bindings: make(map[string]AgentAccountAgentBinding, len(bindings))}
	for _, binding := range bindings {
		source, sourceErr := address.ParseRawAddr(binding.SourceAccount)
		owner, ownerErr := address.ParseRawAddr(binding.OwnerAddress)
		if sourceErr != nil || source == nil || source.StringRaw() != binding.SourceAccount ||
			source.Workchain() != network.WorkchainID || ownerErr != nil || owner == nil ||
			owner.StringRaw() != binding.OwnerAddress || !validRelayAgentIdentifier(binding.AuthorizedAgentID) {
			return nil, errors.New("invalid owner-pinned Agent Account binding")
		}
		if _, duplicate := resolved.bindings[binding.SourceAccount]; duplicate {
			return nil, errors.New("duplicate owner-pinned Agent Account binding")
		}
		resolved.bindings[binding.SourceAccount] = binding
	}
	return resolved, nil
}

func validRelayAgentIdentifier(value string) bool {
	return len(value) > 0 && len(value) <= 256 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\x00\r\n")
}

func (resolver *AgentGiftFinalizedAgentAccountResolver) ResolveFinalizedAgentAccount(ctx context.Context,
	network agentrelay.NetworkDomain, account string) (ResolvedRelayAgentAccount, error) {
	var zero ResolvedRelayAgentAccount
	if resolver == nil || resolver.reader == nil || ctx == nil || network != resolver.network {
		return zero, errors.New("invalid finalized Agent Account relay request")
	}
	binding, err := resolver.binding(account)
	if err != nil {
		return zero, err
	}
	finalized, chainTime, err := resolver.reader.FinalizedAgentAccount(ctx, account)
	if err != nil {
		return zero, err
	}
	if finalized.Address != binding.SourceAccount || finalized.OwnerAddress != binding.OwnerAddress {
		return zero, errors.New("finalized Agent Account conflicts with owner-pinned Agent authorization")
	}
	resolved := ResolvedRelayAgentAccount{Account: finalized, FinalizedTime: chainTime,
		AuthorizedAgentID: binding.AuthorizedAgentID}
	if chainTime == 0 {
		return zero, errors.New("finalized Agent Account chain time is missing")
	}
	if _, err := AgentAccountRelayAuthorityDigest(network, resolved); err != nil {
		return zero, errors.New("finalized Agent Account does not match the pinned relay network and authority")
	}
	return resolved, nil
}

func (resolver *AgentGiftFinalizedAgentAccountResolver) binding(account string) (AgentAccountAgentBinding, error) {
	if resolver == nil {
		return AgentAccountAgentBinding{}, errors.New("Agent Account relay resolver is unavailable")
	}
	canonical, err := CanonicalAddress(account)
	if err != nil {
		return AgentAccountAgentBinding{}, err
	}
	binding, found := resolver.bindings[canonical]
	if !found {
		return AgentAccountAgentBinding{}, errors.New("Agent Account has no owner-pinned Agent authorization")
	}
	return binding, nil
}

var _ FinalizedAgentAccountResolver = (*AgentGiftFinalizedAgentAccountResolver)(nil)
