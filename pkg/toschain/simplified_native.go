package toschain

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
)

// SimplifiedNativeResolver reads the deterministic object account directly.
// It never consults Action Anchors, a gateway database, or portable state.
type SimplifiedNativeResolver struct {
	chain      *Adapter
	locator    *nativecore.Locator
	network    *nativev1.NetworkDomain
	mu         sync.Mutex
	highWater  uint64
	checkpoint *checkpointStore
}

func NewSimplifiedNativeResolver(chain *Adapter, locator *nativecore.Locator, checkpointPath string) (*SimplifiedNativeResolver, error) {
	if chain == nil || locator == nil || locator.Network == nil || chain.network != locator.Network.NetworkId {
		return nil, errors.New("invalid simplified Native resolver configuration")
	}
	result := &SimplifiedNativeResolver{chain: chain, locator: locator, network: locator.Network}
	store, err := newCheckpointStore(checkpointPath)
	if err != nil {
		return nil, err
	}
	result.checkpoint = store
	return result, nil
}

func (r *SimplifiedNativeResolver) CheckReady(ctx context.Context) error {
	if r == nil || ctx == nil {
		return errors.New("simplified Native resolver is not configured")
	}
	_, _, err := r.chain.consensus(ctx)
	return err
}

func (r *SimplifiedNativeResolver) ResolveState(ctx context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, error) {
	state, found, _, err := r.resolveFinalizedState(ctx, objectID, expectedStateHash)
	return state, found, err
}

// ResolveNativeAtCheckpoint resolves an address-selected Native object at the
// exact DNS checkpoint. It rejects both checkpoint substitution and an account
// whose embedded object ID does not reproduce the supplied address.
func (r *SimplifiedNativeResolver) ResolveNativeAtCheckpoint(ctx context.Context, account string, checkpoint *nativev1.DNSCheckpointV1) (*nativev1.NativeStateV1, bool, error) {
	if r == nil || ctx == nil || checkpoint == nil || checkpoint.Workchain != -1 || checkpoint.Sequence == 0 ||
		len(checkpoint.RootHash) != 32 || len(checkpoint.FileHash) != 32 {
		return nil, false, errors.New("invalid DNS Native checkpoint request")
	}
	canonical, err := CanonicalAddress(account)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadAction, "invalid DNS Native account", err)
	}
	r.mu.Lock()
	if checkpoint.Sequence < r.highWater {
		r.mu.Unlock()
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadSequence, "DNS Native checkpoint regressed", nil)
	}
	r.mu.Unlock()
	vote, _, err := quorumRead(ctx, r.chain.nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, canonical, checkpoint.Sequence, r.network, r.locator.CodeHash)
	})
	if err != nil {
		return nil, false, err
	}
	if vote.BlockRoot != "sha256:"+hex.EncodeToString(checkpoint.RootHash) ||
		vote.BlockFile != "sha256:"+hex.EncodeToString(checkpoint.FileHash) {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadSequence, "DNS and Native checkpoint hashes differ", nil)
	}
	if !vote.Found {
		if err := r.commitCheckpoint(checkpoint.Sequence); err != nil {
			return nil, false, err
		}
		return nil, false, nil
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid DNS Native account data BOC", err)
	}
	state, found, objectID, err := r.locator.DecodeDataAny(data)
	if err != nil || !found {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid DNS Native typed state", err)
	}
	identity, err := r.locator.Locate(objectID)
	if err != nil || identity.Address != canonical {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "DNS Native address derivation mismatch", err)
	}
	lt, txHash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, err
	}
	state.Reference = &nativev1.ChainReference{Workchain: r.locator.Workchain, Account: canonical,
		LogicalTime: lt, TransactionHash: "sha256:" + hex.EncodeToString(txHash), ContractCodeHash: identity.CodeHash,
		FinalizedCheckpoint: checkpoint.Sequence}
	if err := r.commitCheckpoint(checkpoint.Sequence); err != nil {
		return nil, false, err
	}
	return state, true, nil
}

// ResolveFinalizedState returns the chain-authored unix time from the same
// quorum-finalized masterchain observation used for the typed account read.
// Relayers use it for contract-time preflight and must not substitute host time.
func (r *SimplifiedNativeResolver) ResolveFinalizedState(ctx context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, time.Time, error) {
	return r.resolveFinalizedState(ctx, objectID, expectedStateHash)
}

func (r *SimplifiedNativeResolver) resolveFinalizedState(ctx context.Context, objectID, expectedStateHash string) (*nativev1.NativeStateV1, bool, time.Time, error) {
	if r == nil || ctx == nil {
		return nil, false, time.Time{}, errors.New("invalid simplified Native resolution request")
	}
	identity, err := r.locator.Locate(objectID)
	if err != nil {
		return nil, false, time.Time{}, nativecore.NewProtocolError(nativecore.ErrBadAction, "invalid Native object resolution target", err)
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, false, time.Time{}, err
	}
	if err := r.chain.validateObservationTime(observation, time.Now()); err != nil {
		return nil, false, time.Time{}, err
	}
	r.mu.Lock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		r.mu.Unlock()
		return nil, false, time.Time{}, nativecore.NewProtocolError(nativecore.ErrBadSequence, "simplified Native finalized checkpoint regressed", nil)
	}
	r.mu.Unlock()
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, identity.Address, observation.seqno, r.network, r.locator.CodeHash)
	})
	if err != nil {
		return nil, false, time.Time{}, err
	}
	if !vote.Found {
		if err := r.commitCheckpoint(observation.seqno); err != nil {
			return nil, false, time.Time{}, err
		}
		return nil, false, observation.observedAt, nil
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nil, false, time.Time{}, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native account data BOC", err)
	}
	state, found, err := r.locator.DecodeData(data, objectID)
	if err != nil || !found {
		return state, found, time.Time{}, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid Native typed state", err)
	}
	if expectedStateHash != "" && state.TvmStateHash != expectedStateHash {
		return nil, false, time.Time{}, nativecore.NewProtocolError(nativecore.ErrBadPredecessor, "simplified Native state hash mismatch", nil)
	}
	lt, txHash, err := transactionTuple(vote)
	if err != nil {
		return nil, false, time.Time{}, err
	}
	state.Reference = &nativev1.ChainReference{Workchain: r.locator.Workchain, Account: identity.Address,
		LogicalTime: lt, TransactionHash: "sha256:" + hex.EncodeToString(txHash), ContractCodeHash: identity.CodeHash,
		FinalizedCheckpoint: observation.seqno}
	if err := r.commitCheckpoint(observation.seqno); err != nil {
		return nil, false, time.Time{}, err
	}
	return state, true, observation.observedAt, nil
}

func (r *SimplifiedNativeResolver) commitCheckpoint(value uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value == 0 || value < r.highWater {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "simplified Native finalized checkpoint regressed", nil)
	}
	if r.checkpoint == nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "simplified Native durable checkpoint is unavailable", nil)
	}
	if err := r.checkpoint.checkAndAdvance(value); err != nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "simplified Native durable checkpoint rejected observation", err)
	}
	r.highWater = value
	return nil
}
