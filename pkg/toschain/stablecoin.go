package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// StablecoinAssetObservation binds a reviewed TOS stablecoin identity and the
// buyer's exact derived wallet balance to one quorum-finalized checkpoint.
type StablecoinAssetObservation struct {
	Asset               *nativev1.TOSAssetIdentityV1
	MasterAddress       string
	BuyerWalletAddress  string
	BuyerBalanceAtomic  string
	FinalizedCheckpoint uint64
}

// StablecoinResolver derives the buyer wallet from the wallet-code preimage
// stored by the authenticated master contract, then reads both accounts at the
// same finalized checkpoint. It never trusts a ticker, index, or gateway.
type StablecoinResolver struct {
	chain      *Adapter
	network    *nativev1.NetworkDomain
	mu         sync.Mutex
	highWater  uint64
	checkpoint *checkpointStore
}

func NewStablecoinResolver(chain *Adapter, network *nativev1.NetworkDomain, checkpointPath string) (*StablecoinResolver, error) {
	if chain == nil || network == nil || chain.network != network.NetworkId {
		return nil, errors.New("invalid stablecoin resolver configuration")
	}
	store, err := newCheckpointStore(checkpointPath)
	if err != nil {
		return nil, err
	}
	return &StablecoinResolver{chain: chain, network: proto.Clone(network).(*nativev1.NetworkDomain), checkpoint: store}, nil
}

func (r *StablecoinResolver) ResolveBuyerAsset(ctx context.Context, asset *nativev1.TOSAssetIdentityV1, buyerAddress string) (*StablecoinAssetObservation, error) {
	if r == nil || ctx == nil || !validStablecoinIdentity(asset) {
		return nil, errors.New("invalid stablecoin resolution request")
	}
	buyer, err := parseRawWC0(buyerAddress)
	if err != nil {
		return nil, err
	}
	masterAddress := fmt.Sprintf("0:%s", hex.EncodeToString(asset.Master.AccountId))
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, err
	}
	if err := r.chain.validateObservationTime(observation, time.Now()); err != nil {
		return nil, err
	}
	r.mu.Lock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		r.mu.Unlock()
		return nil, nativecore.NewProtocolError(nativecore.ErrBadSequence, "stablecoin finalized checkpoint regressed", nil)
	}
	r.mu.Unlock()
	masterVote, masterNodes, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, masterAddress, observation.seqno, r.network, asset.Master.CodeHash)
	})
	if err != nil || !masterVote.Found {
		return nil, nativecore.NewProtocolError(nativecore.ErrWrongContract, "stablecoin master is unavailable", err)
	}
	masterData, err := decodeCellBOC(masterVote.Data)
	if err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid stablecoin master data", err)
	}
	walletCode, err := decodeStablecoinMasterWalletCode(masterData, asset.WalletCodeHash)
	if err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrWrongContract, "stablecoin master wallet code is invalid", err)
	}
	walletAddress, err := deriveStablecoinWalletAddress(buyer, mustRawWC0(masterAddress), walletCode)
	if err != nil {
		return nil, err
	}
	walletVote, _, err := quorumRead(ctx, masterNodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, walletAddress, observation.seqno, r.network, asset.WalletCodeHash)
	})
	if err != nil || !walletVote.Found {
		return nil, nativecore.NewProtocolError(nativecore.ErrWrongContract, "buyer stablecoin wallet is unavailable", err)
	}
	walletData, err := decodeCellBOC(walletVote.Data)
	if err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid buyer stablecoin wallet data", err)
	}
	balance, err := decodeStablecoinWallet(walletData, buyerAddress, masterAddress)
	if err != nil {
		return nil, nativecore.NewProtocolError(nativecore.ErrWrongContract, "buyer stablecoin wallet identity is invalid", err)
	}
	if err := r.commitCheckpoint(observation.seqno); err != nil {
		return nil, err
	}
	return &StablecoinAssetObservation{Asset: proto.Clone(asset).(*nativev1.TOSAssetIdentityV1),
		MasterAddress: masterAddress, BuyerWalletAddress: walletAddress,
		BuyerBalanceAtomic: balance, FinalizedCheckpoint: observation.seqno}, nil
}

func validStablecoinIdentity(asset *nativev1.TOSAssetIdentityV1) bool {
	return asset != nil && asset.Master != nil && asset.Master.Workchain == 0 &&
		len(asset.Master.AccountId) == 32 && !bytes.Equal(asset.Master.AccountId, make([]byte, 32)) &&
		validTVMCellHash(asset.Master.CodeHash) && validTVMCellHash(asset.WalletCodeHash) &&
		asset.Decimals > 0 && asset.Decimals <= 18
}

func validTVMCellHash(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func decodeStablecoinMasterWalletCode(data *cell.Cell, expectedHash string) (*cell.Cell, error) {
	if data == nil {
		return nil, errors.New("missing stablecoin master data")
	}
	s := data.BeginParse()
	supply, err := s.LoadBigCoins()
	if err != nil || supply.Sign() < 0 {
		return nil, errors.New("invalid stablecoin total supply")
	}
	admin, err := s.LoadAddr()
	if err != nil || admin == nil {
		return nil, errors.New("invalid stablecoin admin")
	}
	if _, err := s.LoadAddr(); err != nil {
		return nil, errors.New("invalid stablecoin next admin")
	}
	walletCode, err := s.LoadRefCell()
	if err != nil || walletCode == nil || "tvm-cell-sha256:"+hex.EncodeToString(walletCode.Hash()) != expectedHash {
		return nil, errors.New("stablecoin wallet code hash mismatch")
	}
	metadata, err := s.LoadRefCell()
	if err != nil || metadata == nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid stablecoin master data suffix")
	}
	return walletCode, nil
}

func deriveStablecoinWalletAddress(owner, master *address.Address, walletCode *cell.Cell) (string, error) {
	if owner == nil || master == nil || walletCode == nil || owner.Workchain() != 0 || master.Workchain() != 0 {
		return "", errors.New("invalid stablecoin wallet derivation")
	}
	data := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(0).
		MustStoreAddr(owner).MustStoreAddr(master).EndCell()
	init := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(walletCode).
		MustStoreBoolBit(true).MustStoreRef(data).MustStoreBoolBit(false).EndCell()
	return address.NewAddress(0, 0, init.Hash()).StringRaw(), nil
}

func decodeStablecoinWallet(data *cell.Cell, ownerAddress, masterAddress string) (string, error) {
	if data == nil {
		return "", errors.New("missing stablecoin wallet data")
	}
	s := data.BeginParse()
	status, err := s.LoadUInt(4)
	if err != nil || status != 0 {
		return "", errors.New("buyer stablecoin wallet is frozen")
	}
	balance, err := s.LoadBigCoins()
	if err != nil || balance.Sign() < 0 {
		return "", errors.New("invalid stablecoin wallet balance")
	}
	owner, err := s.LoadAddr()
	if err != nil || owner == nil || owner.StringRaw() != ownerAddress {
		return "", errors.New("stablecoin wallet owner mismatch")
	}
	master, err := s.LoadAddr()
	if err != nil || master == nil || master.StringRaw() != masterAddress || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return "", errors.New("stablecoin wallet master mismatch")
	}
	return balance.String(), nil
}

func parseRawWC0(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil, errors.New("invalid raw workchain-zero address")
	}
	return parsed, nil
}

func mustRawWC0(value string) *address.Address {
	parsed, _ := parseRawWC0(value)
	return parsed
}

func (r *StablecoinResolver) commitCheckpoint(value uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if value == 0 || value < r.highWater || r.checkpoint == nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "stablecoin finalized checkpoint regressed", nil)
	}
	if err := r.checkpoint.checkAndAdvance(value); err != nil {
		return nativecore.NewProtocolError(nativecore.ErrBadSequence, "stablecoin durable checkpoint rejected observation", err)
	}
	r.highWater = value
	return nil
}
