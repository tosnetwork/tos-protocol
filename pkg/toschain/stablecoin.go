package toschain

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

// StablecoinAssetObservation binds a reviewed TOS stablecoin identity and the
// buyer's exact derived wallet balance to one quorum-finalized checkpoint.
type StablecoinAssetObservation struct {
	Asset                 *nativev1.TOSAssetIdentityV1
	MasterAddress         string
	BuyerWalletAddress    string
	BuyerBalanceAtomic    string
	FinalizedCheckpoint   uint64
	WalletTransactionHash string
	WalletTransactionTime uint64
}

// StablecoinCreditObservation proves one exact, successful wallet-level
// internal transfer. A balance or latest-transaction observation alone cannot
// identify which commercial obligation caused a credit.
type StablecoinCreditObservation struct {
	Asset                  *nativev1.TOSAssetIdentityV1
	SourceOwnerAddress     string
	SourceWalletAddress    string
	RecipientOwnerAddress  string
	RecipientWalletAddress string
	QueryID                uint64
	AmountAtomic           string
	TransactionHash        string
	TransactionTime        uint64
	FinalizedCheckpoint    uint64
	RecipientBalanceAtomic string
}

type stablecoinCreditVote struct {
	Credited        bool   `json:"credited"`
	AbsenceKnown    bool   `json:"absence_known"`
	TransactionHash string `json:"transaction_hash"`
	TransactionTime uint64 `json:"transaction_time"`
}

const maxStablecoinCreditHistoryTransactions = 256

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
		BuyerBalanceAtomic: balance, FinalizedCheckpoint: observation.seqno,
		WalletTransactionHash: walletVote.TransactionHash, WalletTransactionTime: walletVote.TransactionTime}, nil
}

// ResolveExactCredit verifies the recipient wallet transaction whose inbound
// internal-transfer body binds source owner, query ID, and atomic amount. The
// lookup is quorum-backed, checkpoint-pinned, bounded, and history-continuous.
func (r *StablecoinResolver) ResolveExactCredit(ctx context.Context, asset *nativev1.TOSAssetIdentityV1,
	sourceOwnerAddress, recipientOwnerAddress string, queryID uint64, amountAtomic string,
	notBeforeUnix uint64) (*StablecoinCreditObservation, bool, error) {
	if r == nil || ctx == nil || !validStablecoinIdentity(asset) || queryID == 0 || notBeforeUnix == 0 {
		return nil, false, errors.New("invalid stablecoin credit request")
	}
	sourceOwner, err := parseRawWC0(sourceOwnerAddress)
	if err != nil {
		return nil, false, err
	}
	recipientOwner, err := parseRawWC0(recipientOwnerAddress)
	if err != nil {
		return nil, false, err
	}
	amount, ok := new(big.Int).SetString(amountAtomic, 10)
	if !ok || amount.Sign() <= 0 || amount.String() != amountAtomic {
		return nil, false, errors.New("invalid stablecoin credit amount")
	}
	masterAddress := fmt.Sprintf("0:%s", hex.EncodeToString(asset.Master.AccountId))
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nil, false, err
	}
	if err := r.chain.validateObservationTime(observation, time.Now()); err != nil {
		return nil, false, err
	}
	r.mu.Lock()
	if observation.seqno == 0 || observation.seqno < r.highWater {
		r.mu.Unlock()
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadSequence, "stablecoin finalized checkpoint regressed", nil)
	}
	r.mu.Unlock()
	masterVote, masterNodes, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, masterAddress, observation.seqno, r.network, asset.Master.CodeHash)
	})
	if err != nil || !masterVote.Found {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "stablecoin master is unavailable", err)
	}
	masterData, err := decodeCellBOC(masterVote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid stablecoin master data", err)
	}
	walletCode, err := decodeStablecoinMasterWalletCode(masterData, asset.WalletCodeHash)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "stablecoin master wallet code is invalid", err)
	}
	sourceWallet, err := deriveStablecoinWalletAddress(sourceOwner, mustRawWC0(masterAddress), walletCode)
	if err != nil {
		return nil, false, err
	}
	recipientWallet, err := deriveStablecoinWalletAddress(recipientOwner, mustRawWC0(masterAddress), walletCode)
	if err != nil {
		return nil, false, err
	}
	recipientVote, recipientNodes, err := quorumRead(ctx, masterNodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, recipientWallet, observation.seqno, r.network, asset.WalletCodeHash)
	})
	if err != nil || !recipientVote.Found {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "recipient stablecoin wallet is unavailable", err)
	}
	recipientData, err := decodeCellBOC(recipientVote.Data)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrBadMessage, "invalid recipient stablecoin wallet data", err)
	}
	balance, err := decodeStablecoinWallet(recipientData, recipientOwnerAddress, masterAddress)
	if err != nil {
		return nil, false, nativecore.NewProtocolError(nativecore.ErrWrongContract, "recipient stablecoin wallet identity is invalid", err)
	}
	credit, _, err := quorumRead(ctx, recipientNodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (stablecoinCreditVote, error) {
		last, err := finalizedAccountLastTransaction(ctx, node, recipientWallet, observation.seqno)
		if err != nil {
			return stablecoinCreditVote{}, err
		}
		history, err := finalizedTransactionHistory(ctx, node, recipientWallet, last)
		if err != nil {
			return stablecoinCreditVote{}, err
		}
		return matchStablecoinCredit(history, sourceWallet, recipientWallet, sourceOwnerAddress,
			queryID, amount, notBeforeUnix)
	})
	if err != nil {
		return nil, false, err
	}
	if err := r.commitCheckpoint(observation.seqno); err != nil {
		return nil, false, err
	}
	if !credit.Credited {
		return nil, false, nil
	}
	return &StablecoinCreditObservation{Asset: proto.Clone(asset).(*nativev1.TOSAssetIdentityV1),
		SourceOwnerAddress: sourceOwnerAddress, SourceWalletAddress: sourceWallet,
		RecipientOwnerAddress: recipientOwnerAddress, RecipientWalletAddress: recipientWallet,
		QueryID: queryID, AmountAtomic: amountAtomic, TransactionHash: credit.TransactionHash,
		TransactionTime: credit.TransactionTime, FinalizedCheckpoint: observation.seqno,
		RecipientBalanceAtomic: balance}, true, nil
}

func matchStablecoinCredit(history []tlb.Transaction, sourceWallet, recipientWallet, sourceOwner string,
	queryID uint64, amount *big.Int, notBeforeUnix uint64) (stablecoinCreditVote, error) {
	if len(history) == 0 || amount == nil || amount.Sign() <= 0 {
		return stablecoinCreditVote{}, errors.New("empty or invalid stablecoin credit history")
	}
	for index := range history {
		transaction := &history[index]
		if transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal {
			continue
		}
		in := transaction.IO.In.AsInternal()
		if in.SrcAddr == nil || in.SrcAddr.StringRaw() != sourceWallet || in.DstAddr == nil ||
			in.DstAddr.StringRaw() != recipientWallet || in.Body == nil {
			continue
		}
		body, err := in.Body.BeginParse()
		if err != nil {
			continue
		}
		op, opErr := body.LoadUInt(32)
		query, queryErr := body.LoadUInt(64)
		value, valueErr := body.LoadBigCoins()
		from, fromErr := body.LoadAddr()
		response, responseErr := body.LoadAddr()
		forward, forwardErr := body.LoadBigCoins()
		either, eitherErr := body.LoadBoolBit()
		if opErr != nil || queryErr != nil || valueErr != nil || fromErr != nil || responseErr != nil ||
			forwardErr != nil || eitherErr != nil || op != 0x178d4519 || query != queryID ||
			value.Cmp(amount) != 0 || from == nil || from.StringRaw() != sourceOwner || response == nil ||
			response.StringRaw() != sourceOwner || forward.Sign() != 0 || either || body.BitsLeft() != 0 || body.RefsNum() != 0 {
			continue
		}
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		compute, vm := description.ComputePhase.Phase.(tlb.ComputePhaseVM)
		if !ordinary || !vm || !compute.Success || description.Aborted || transaction.Now == 0 ||
			uint64(transaction.Now) < notBeforeUnix || len(transaction.Hash) != 32 {
			return stablecoinCreditVote{}, errors.New("exact stablecoin credit transaction failed or violates its time bound")
		}
		return stablecoinCreditVote{Credited: true, AbsenceKnown: true,
			TransactionHash: "sha256:" + hex.EncodeToString(transaction.Hash),
			TransactionTime: uint64(transaction.Now)}, nil
	}
	oldest := history[len(history)-1]
	return stablecoinCreditVote{AbsenceKnown: len(history) < maxStablecoinCreditHistoryTransactions ||
		oldest.PrevTxLT == 0 || uint64(oldest.Now) < notBeforeUnix}, nil
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
	s, err := data.BeginParse()
	if err != nil {
		return nil, errors.New("invalid stablecoin master data")
	}
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
	s, err := data.BeginParse()
	if err != nil {
		return "", errors.New("invalid stablecoin wallet data")
	}
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
