package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentrelay"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ExactRelayResolutionSource performs the query-before-retry half of relay
// recovery. Implementations must resolve the exact journaled transaction at a
// checkpoint satisfying the selected finality profile; a moving latest-head
// lookup is not sufficient.
type ExactRelayResolutionSource interface {
	ResolveExactRelay(context.Context, agentrelay.Record) (agentrelay.ChainResolution, error)
}

// TOSExactRelayBroadcaster is the production write boundary for an exact TOS
// relay. Read-side resolution is deliberately injected separately so callers
// cannot mistake one RPC acknowledgement for independent chain finality.
//
// The adapter sends to the first configured endpoint exactly once. It never
// fails over a write: a transport error can occur after the node accepted the
// BOC and is therefore an ambiguous outcome that must enter Resolve.
type TOSExactRelayBroadcaster struct {
	chain      *Adapter
	network    agentrelay.NetworkDomain
	resolution ExactRelayResolutionSource
}

func NewTOSExactRelayBroadcaster(chain *Adapter, network agentrelay.NetworkDomain,
	resolution ExactRelayResolutionSource) (*TOSExactRelayBroadcaster, error) {
	if chain == nil || resolution == nil || chain.network != network.NetworkID || len(chain.nodes) < 3 ||
		chain.pinnedDomain == nil || !samePinnedRelayNetwork(*chain.pinnedDomain, network) {
		return nil, errors.New("invalid exact TOS relay broadcaster configuration")
	}
	if _, err := agentrelay.NetworkDomainDigest(network); err != nil {
		return nil, errors.New("invalid exact TOS relay network domain")
	}
	return &TOSExactRelayBroadcaster{chain: chain, network: network, resolution: resolution}, nil
}

func samePinnedRelayNetwork(pinned PinnedNetworkDomain, network agentrelay.NetworkDomain) bool {
	return pinned.NetworkID == network.NetworkID && pinned.GlobalID == network.GlobalID &&
		pinned.ZeroStateRootHash == network.ZeroStateRootHash && pinned.ZeroStateFileHash == network.ZeroStateFileHash &&
		pinned.WorkchainID == network.WorkchainID
}

func (broadcaster *TOSExactRelayBroadcaster) SubmitExact(ctx context.Context,
	request agentrelay.RelayExecutionRequest) (agentrelay.BroadcastResult, error) {
	var result agentrelay.BroadcastResult
	network, exactBOC := request.QuoteRequest.Body.Network, request.SignedTransactionBytes
	if broadcaster == nil || broadcaster.chain == nil || ctx == nil || network != broadcaster.network ||
		len(exactBOC) == 0 || len(exactBOC) > agentrelay.MaxSignedTransactionBytes {
		return result, errors.New("invalid exact TOS relay submission")
	}
	if request.QuoteRequest.Body.Mode == agentrelay.ModeSponsorOnly ||
		agentrelay.VerifyRelaySideEffectAdmissionReceiptIntegrity(request.AdmissionReceipt, request) != nil {
		return result, errors.New("exact TOS relay submission lacks its admitted broadcast receipt")
	}
	root, err := cell.FromBOC(exactBOC)
	if err != nil || !bytes.Equal(exactBOC, root.ToBOCWithFlags(false)) {
		return result, errors.New("exact TOS relay BOC is not canonical single-root bytes")
	}
	transactionReference := fmt.Sprintf("tvm-cell-sha256:%x", root.Hash())
	result.TransactionReference = transactionReference
	if err := broadcaster.chain.attestPinnedRelayGenesis(ctx, broadcaster.network); err != nil {
		result.Status = agentrelay.BroadcastUnknown
		return result, fmt.Errorf("exact TOS relay network preflight failed: %w", err)
	}
	var response struct {
		Status int32  `json:"status"`
		Hash   string `json:"hash"`
	}
	// Do not iterate over chain.nodes here. One write attempt is the security
	// boundary; endpoint failover is reserved for idempotent reads.
	err = broadcaster.chain.nodes[0].client.Call(ctx, "sendBocReturnHash", struct {
		BOC string `json:"boc"`
	}{BOC: base64.StdEncoding.EncodeToString(exactBOC)}, &response)
	if err != nil {
		result.Status = agentrelay.BroadcastUnknown
		return result, fmt.Errorf("exact TOS relay write outcome is ambiguous: %w", err)
	}
	nodeHash, err := base64.StdEncoding.DecodeString(response.Hash)
	if err != nil || !bytes.Equal(nodeHash, root.Hash()) {
		result.Status = agentrelay.BroadcastUnknown
		return result, errors.New("exact TOS relay endpoint returned an unrelated message hash")
	}
	switch response.Status {
	case 1:
		// Accepted means only that the selected endpoint returned the exact local
		// cell hash. The resolution source still has to prove execution/finality.
		result.Status = agentrelay.BroadcastAccepted
		return result, nil
	default:
		result.Status = agentrelay.BroadcastUnknown
		return result, errors.New("exact TOS relay endpoint did not return the documented acceptance status")
	}
}

func (broadcaster *TOSExactRelayBroadcaster) Resolve(ctx context.Context,
	record agentrelay.Record) (agentrelay.ChainResolution, error) {
	if broadcaster == nil || broadcaster.resolution == nil || ctx == nil {
		return agentrelay.ChainResolution{}, errors.New("exact TOS relay resolution is unavailable")
	}
	request := record.ExecutionRequest()
	if request.QuoteRequest.Body.Network != broadcaster.network {
		return agentrelay.ChainResolution{}, errors.New("relay journal record belongs to another TOS network")
	}
	return broadcaster.resolution.ResolveExactRelay(ctx, record)
}

var _ agentrelay.ExactTransactionBroadcaster = (*TOSExactRelayBroadcaster)(nil)

type relayGenesisVote struct {
	ZeroStateRootHash string `json:"zero_state_root_hash"`
	ZeroStateFileHash string `json:"zero_state_file_hash"`
}

// attestPinnedRelayGenesis corroborates immutable chain identity through a
// strict endpoint quorum immediately before the bearer write. Global ID and
// source workchain are independently bound by the mandatory transaction
// inspector because those values live in the signed Agent Account message.
func (adapter *Adapter) attestPinnedRelayGenesis(ctx context.Context, network agentrelay.NetworkDomain) error {
	if adapter == nil || adapter.pinnedDomain == nil || !samePinnedRelayNetwork(*adapter.pinnedDomain, network) {
		return errors.New("TOS relay adapter has no matching pinned network domain")
	}
	vote, supportingNodes, err := quorumRead(ctx, adapter.nodes, adapter.quorum, func(ctx context.Context,
		node *rpcNode) (relayGenesisVote, error) {
		var master struct {
			Type          string  `json:"@type"`
			Last          blockID `json:"last"`
			StateRootHash string  `json:"state_root_hash"`
			Init          blockID `json:"init"`
		}
		if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
			return relayGenesisVote{}, err
		}
		if master.Type != "blocks.masterchainInfo" || master.Init.Type != "tos.blockIdExt" ||
			master.Init.Workchain != -1 || master.Init.Shard != "-9223372036854775808" || master.Init.Seqno != 0 {
			return relayGenesisVote{}, errors.New("TOS endpoint returned an invalid genesis identity")
		}
		root, rootErr := decodeBase64Hash(master.Init.RootHash)
		file, fileErr := decodeBase64Hash(master.Init.FileHash)
		if rootErr != nil || fileErr != nil {
			return relayGenesisVote{}, errors.New("TOS endpoint returned malformed genesis hashes")
		}
		return relayGenesisVote{ZeroStateRootHash: "sha256:" + hex.EncodeToString(root),
			ZeroStateFileHash: "sha256:" + hex.EncodeToString(file)}, nil
	})
	if err != nil {
		return err
	}
	primaryAgreed := false
	for _, node := range supportingNodes {
		if node == adapter.nodes[0] {
			primaryAgreed = true
			break
		}
	}
	if !primaryAgreed {
		return errors.New("primary TOS relay endpoint did not join the pinned-genesis quorum")
	}
	if vote.ZeroStateRootHash != network.ZeroStateRootHash || vote.ZeroStateFileHash != network.ZeroStateFileHash {
		return errors.New("TOS endpoint quorum belongs to another zero state")
	}
	return nil
}

// VerifyPinnedRelayGenesis performs the read-only quorum preflight used by
// operators before enabling a relay client or provider. Bearer submission runs
// the same check again immediately before its one allowed network write.
func (adapter *Adapter) VerifyPinnedRelayGenesis(ctx context.Context,
	network agentrelay.NetworkDomain) error {
	if ctx == nil {
		return errors.New("TOS relay genesis verification requires a context")
	}
	return adapter.attestPinnedRelayGenesis(ctx, network)
}
