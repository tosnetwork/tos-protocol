package toschain

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
)

// SimplifiedNativeResolver reads the deterministic object account directly.
// It never consults Action Anchors, a gateway database, or portable state.
type SimplifiedNativeResolver struct {
	chain     *Adapter
	locator   *nativecore.Locator
	network   *nativev1.NetworkDomain
	mu        sync.Mutex
	highWater uint64
}

func NewSimplifiedNativeResolver(chain *Adapter, locator *nativecore.Locator) (*SimplifiedNativeResolver, error) {
	if chain == nil || locator == nil || locator.Network == nil || chain.network != locator.Network.NetworkId {
		return nil, errors.New("invalid simplified Native resolver configuration")
	}
	return &SimplifiedNativeResolver{chain: chain, locator: locator, network: locator.Network}, nil
}

func (r *SimplifiedNativeResolver) CheckReady(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("simplified Native resolver is not configured")
	}
	_, _, err := r.chain.consensus(ctx)
	return err
}

func (r *SimplifiedNativeResolver) ResolveState(ctx context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, error) {
	if r == nil || ctx == nil {
		return nil, false, errors.New("invalid simplified Native resolution request")
	}
	identity, err := r.locator.Locate(objectID)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadAction, "invalid Native object resolution target", err)
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		r.mu.Unlock()
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadSequence, "simplified Native finalized checkpoint regressed", nil)
	}
	r.highWater = observation.seqno
	r.mu.Unlock()
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, identity.Address, observation.seqno, r.network, r.locator.CodeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if !vote.Found {
		return nil, false, nil
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native account data BOC", err)
	}
	state, found, err := r.locator.DecodeData(data, objectID)
	if err != nil || !found {
		return state, found, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native typed state", err)
	}
	if expectedStateHash != "" && state.TvmStateHash != expectedStateHash {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadPredecessor, "simplified Native state hash mismatch", nil)
	}
	lt, txHash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	state.Reference = &nativev1.ChainReference{Workchain: r.locator.Workchain, Account: identity.Address,
		LogicalTime: lt, TransactionHash: "sha256:" + hex.EncodeToString(txHash), ContractCodeHash: identity.CodeHash,
		FinalizedCheckpoint: observation.seqno}
	return state, true, nil
}
