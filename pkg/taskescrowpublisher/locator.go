package taskescrowpublisher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type transactionID struct {
	Type string `json:"@type"`
	LT   string `json:"lt"`
	Hash string `json:"hash"`
}

// accountInformation mirrors every field the TOS JSON-RPC getAddressInformation
// method returns. jsonstrict.Decode rejects unknown fields, so this must stay
// in sync with that response even though latest() only reads State and
// LastTransactionID.
type accountInformation struct {
	Type              string        `json:"@type"`
	Balance           any           `json:"balance"`
	Code              any           `json:"code"`
	Data              any           `json:"data"`
	LastTransactionID transactionID `json:"last_transaction_id"`
	BlockID           any           `json:"block_id"`
	SyncUtime         any           `json:"sync_utime"`
	ExtraCurrencies   any           `json:"extra_currencies"`
	State             string        `json:"state"`
	FrozenHash        any           `json:"frozen_hash"`
}

// blockID mirrors every field the TOS JSON-RPC daemon's format_block_id_json
// emits (validator-engine/json-rpc-server-shared.cpp). jsonstrict.Decode
// rejects unknown fields, so shard must stay declared even though nothing
// here reads it.
type blockID struct {
	Type      string `json:"@type"`
	Workchain int32  `json:"workchain"`
	Shard     string `json:"shard"`
	Seqno     uint64 `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

// masterchainInformation mirrors the complete getMasterchainInfo result.
// The JSON-RPC client rejects unknown result fields, so readiness must track
// the real daemon schema rather than decoding only init.{root,file}_hash.
type masterchainInformation struct {
	Type          string  `json:"@type"`
	Last          blockID `json:"last"`
	StateRootHash string  `json:"state_root_hash"`
	Init          blockID `json:"init"`
}

// rawTransaction mirrors every field the TOS JSON-RPC getTransactions method
// emits per transaction. jsonstrict.Decode rejects unknown fields, and fee/
// in_msg_hash are only present when the daemon can parse the fee or the
// transaction has an inbound message, so both must still be declared even
// though matchTaskEscrowTransaction doesn't read them.
type rawTransaction struct {
	Type          string        `json:"@type"`
	BlockID       blockID       `json:"block_id"`
	Data          string        `json:"data"`
	Utime         uint32        `json:"utime"`
	TransactionID transactionID `json:"transaction_id"`
	Fee           any           `json:"fee"`
	Account       string        `json:"account"`
	InMsgHash     any           `json:"in_msg_hash"`
}

type transactionCursor struct {
	LT   uint64
	Hash string
}

type transactionLocator struct {
	client       *chain.Client
	pollInterval time.Duration
	lookback     int
}

func newTransactionLocator(endpoint string, timeout, pollInterval time.Duration, lookback int) (*transactionLocator, error) {
	if pollInterval <= 0 || pollInterval > 5*time.Second || lookback <= 0 || lookback > 100 {
		return nil, errors.New("invalid transaction locator policy")
	}
	client, err := chain.NewClient(endpoint, timeout, 8<<20)
	if err != nil {
		return nil, err
	}
	return &transactionLocator{client: client, pollInterval: pollInterval, lookback: lookback}, nil
}

func (l *transactionLocator) latest(ctx context.Context, contractAddress string) (transactionCursor, error) {
	if l == nil || l.client == nil {
		return transactionCursor{}, errors.New("invalid transaction locator")
	}
	contractAddress, err := toschain.CanonicalAddress(contractAddress)
	if err != nil {
		return transactionCursor{}, err
	}
	var info accountInformation
	err = l.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
	}{Address: contractAddress}, &info)
	if err != nil {
		return transactionCursor{}, err
	}
	if info.LastTransactionID.LT == "" || info.LastTransactionID.LT == "0" {
		return transactionCursor{}, nil
	}
	lt, err := strconv.ParseUint(info.LastTransactionID.LT, 10, 64)
	if err != nil || lt == 0 {
		return transactionCursor{}, errors.New("invalid latest transaction logical time")
	}
	hash, err := base64.StdEncoding.DecodeString(info.LastTransactionID.Hash)
	if err != nil || len(hash) != 32 {
		return transactionCursor{}, errors.New("invalid latest transaction hash")
	}
	return transactionCursor{LT: lt, Hash: hex.EncodeToString(hash)}, nil
}

func (l *transactionLocator) waitFor(
	ctx context.Context,
	action chain.TaskEscrowAction,
	prepared PreparedAction,
	maxWait time.Duration,
) (string, bool, error) {
	deadline := time.Now().Add(maxWait)
	for {
		reference, found, err := l.find(ctx, action, prepared)
		if err == nil && found {
			return reference, true, nil
		}
		if err != nil && ctx.Err() == nil {
			// JSON-RPC may transiently expose a new account before its history can
			// be queried. Keep polling until the bounded deadline.
		}
		if ctx.Err() != nil {
			return "", false, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			return "", false, nil
		}
		timer := time.NewTimer(l.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", false, ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *transactionLocator) find(
	ctx context.Context,
	action chain.TaskEscrowAction,
	prepared PreparedAction,
) (string, bool, error) {
	latest, err := l.latest(ctx, prepared.ContractAddress)
	if err != nil {
		return "", false, err
	}
	if latest.LT == 0 || (latest.LT == prepared.BaselineLT && latest.Hash == prepared.BaselineHash) {
		return "", false, nil
	}
	hash, err := hex.DecodeString(latest.Hash)
	if err != nil || len(hash) != 32 {
		return "", false, errors.New("invalid latest transaction cursor")
	}
	params := struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{
		Address: prepared.ContractAddress, Limit: l.lookback,
		LT: strconv.FormatUint(latest.LT, 10), Hash: base64.StdEncoding.EncodeToString(hash),
	}
	var transactions []rawTransaction
	if err := l.client.Call(ctx, "getTransactions", params, &transactions); err != nil {
		return "", false, err
	}
	for _, raw := range transactions {
		matched, txLT, txHash, err := matchTaskEscrowTransaction(raw, action, prepared)
		if err != nil {
			continue
		}
		if matched {
			reference, err := toschain.FormatTransactionReference(prepared.ContractAddress, txLT, txHash)
			return reference, err == nil, err
		}
		if raw.TransactionID.LT == strconv.FormatUint(prepared.BaselineLT, 10) {
			break
		}
	}
	return "", false, nil
}

func matchTaskEscrowTransaction(
	raw rawTransaction,
	action chain.TaskEscrowAction,
	prepared PreparedAction,
) (matched bool, lt uint64, hash []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			matched, lt, hash, err = false, 0, nil, fmt.Errorf("invalid transaction BOC: %v", recovered)
		}
	}()
	if raw.Type != "raw.transaction" || raw.BlockID.Type != "tos.blockIdExt" ||
		raw.TransactionID.Type != "internal.transactionId" || raw.Data == "" {
		return false, 0, nil, errors.New("invalid raw transaction")
	}
	lt, err = strconv.ParseUint(raw.TransactionID.LT, 10, 64)
	if err != nil || lt == 0 || (prepared.BaselineLT != 0 && lt <= prepared.BaselineLT) {
		return false, 0, nil, errors.New("transaction is not after baseline")
	}
	responseHash, err := base64.StdEncoding.DecodeString(raw.TransactionID.Hash)
	if err != nil || len(responseHash) != 32 {
		return false, 0, nil, errors.New("invalid transaction hash")
	}
	boc, err := base64.StdEncoding.DecodeString(raw.Data)
	if err != nil {
		return false, 0, nil, err
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(root.Hash(), responseHash) {
		return false, 0, nil, errors.New("transaction BOC hash mismatch")
	}
	var transaction tlb.Transaction
	if err := tlb.LoadFromCell(&transaction, root.BeginParse()); err != nil {
		return false, 0, nil, err
	}
	addressParts := strings.Split(prepared.ContractAddress, ":")
	if len(addressParts) != 2 || !strings.EqualFold(raw.Account, addressParts[1]) ||
		transaction.LT != lt || !bytes.Equal(transaction.AccountAddr, mustDecodeHex(addressParts[1])) ||
		transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal ||
		verifySuccessfulTransaction(&transaction) != nil {
		return false, 0, nil, errors.New("transaction is not a successful escrow call")
	}
	message := transaction.IO.In.AsInternal()
	if message == nil || message.Bounced || message.SrcAddr == nil || message.DstAddr == nil ||
		message.SrcAddr.Type() != address.StdAddress || message.DstAddr.Type() != address.StdAddress ||
		message.DstAddr.StringRaw() != prepared.ContractAddress {
		return false, 0, nil, errors.New("invalid escrow inbound message")
	}
	expectedSender := expectedActionSender(action)
	if expectedSender != "" && message.SrcAddr.StringRaw() != expectedSender {
		return false, 0, nil, errors.New("escrow action sender mismatch")
	}
	amount := message.Amount.Nano()
	if !amount.IsUint64() {
		return false, 0, nil, errors.New("escrow action amount outside uint64")
	}
	if action.Kind == chain.TaskEscrowActionDeploy {
		if amount.Uint64() < action.FundingNanoTOS {
			return false, 0, nil, errors.New("escrow deployment underfunded")
		}
		return true, lt, responseHash, nil
	}
	if message.Body == nil {
		return false, 0, nil, errors.New("escrow action body missing")
	}
	bodyHash := "tvm-cell-sha256:" + hex.EncodeToString(message.Body.Hash())
	if bodyHash != action.ExpectedBodyHash {
		return false, 0, nil, errors.New("escrow action body hash mismatch")
	}
	body := message.Body.BeginParse()
	if body.BitsLeft() < 96 {
		return false, 0, nil, errors.New("escrow action body is truncated")
	}
	_, _ = body.LoadUInt(32)
	queryID, err := body.LoadUInt(64)
	if err != nil || queryID != action.QueryID {
		return false, 0, nil, errors.New("escrow action query ID mismatch")
	}
	return true, lt, responseHash, nil
}

func expectedActionSender(action chain.TaskEscrowAction) string {
	switch action.Kind {
	case chain.TaskEscrowActionDeploy, chain.TaskEscrowActionCancel, chain.TaskEscrowActionDispute:
		return action.Creator
	case chain.TaskEscrowActionAccept, chain.TaskEscrowActionResult, chain.TaskEscrowActionReject:
		return action.Agent
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		return action.Verifier
	default:
		return ""
	}
}

func verifySuccessfulTransaction(transaction *tlb.Transaction) error {
	if transaction == nil {
		return errors.New("transaction missing")
	}
	var ordinary tlb.TransactionDescriptionOrdinary
	switch value := transaction.Description.(type) {
	case tlb.TransactionDescriptionOrdinary:
		ordinary = value
	case *tlb.TransactionDescriptionOrdinary:
		if value == nil {
			return errors.New("transaction description missing")
		}
		ordinary = *value
	default:
		return errors.New("transaction is not ordinary")
	}
	if ordinary.Aborted || ordinary.Destroyed || ordinary.ActionPhase == nil ||
		!ordinary.ActionPhase.Success || !ordinary.ActionPhase.Valid || ordinary.ActionPhase.NoFunds ||
		ordinary.ActionPhase.ResultCode != 0 {
		return errors.New("transaction action phase failed")
	}
	switch phase := ordinary.ComputePhase.Phase.(type) {
	case tlb.ComputePhaseVM:
		if !phase.Success || phase.Details.ExitCode != 0 {
			return errors.New("transaction VM failed")
		}
	case *tlb.ComputePhaseVM:
		if phase == nil || !phase.Success || phase.Details.ExitCode != 0 {
			return errors.New("transaction VM failed")
		}
	default:
		return errors.New("transaction did not execute VM")
	}
	return nil
}

func mustDecodeHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}
