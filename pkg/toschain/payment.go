package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const transactionReferencePrefix = "tos:tx:v1:"

type transactionReference struct {
	payee     string
	workchain int32
	account   []byte
	lt        uint64
	hash      []byte
}

type rawTransaction struct {
	Type          string        `json:"@type"`
	BlockID       blockID       `json:"block_id"`
	Data          string        `json:"data"`
	Utime         uint32        `json:"utime"`
	TransactionID transactionID `json:"transaction_id"`
	Fee           string        `json:"fee"`
	Account       string        `json:"account"`
	InMsgHash     string        `json:"in_msg_hash"`
}

type paymentQuorumState struct {
	Found         bool   `json:"found"`
	Payer         string `json:"payer,omitempty"`
	Payee         string `json:"payee,omitempty"`
	AmountNanoTOS uint64 `json:"amount_nano_tos,omitempty"`
}

// FormatTransactionReference returns the canonical settlement identifier
// carried by payment authorizations and durable journals. It names one exact
// transaction in one exact payee account history.
func FormatTransactionReference(payee string, lt uint64, hash []byte) (string, error) {
	canonical, err := requireCanonicalAddress(payee)
	if err != nil {
		return "", err
	}
	if lt == 0 || len(hash) != 32 {
		return "", errors.New("invalid TOS payment transaction identity")
	}
	parts := strings.Split(canonical, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid canonical TOS payee")
	}
	return transactionReferencePrefix + parts[0] + ":" + parts[1] + ":" +
		strconv.FormatUint(lt, 10) + ":" + hex.EncodeToString(hash), nil
}

func parseTransactionReference(value string) (transactionReference, error) {
	if len(value) < len(transactionReferencePrefix)+1 || len(value) > 256 ||
		strings.TrimSpace(value) != value {
		return transactionReference{}, errors.New("invalid TOS payment reference")
	}
	parts := strings.Split(value, ":")
	if len(parts) != 7 || parts[0] != "tos" || parts[1] != "tx" || parts[2] != "v1" {
		return transactionReference{}, errors.New("unsupported TOS payment reference")
	}
	wc, err := strconv.ParseInt(parts[3], 10, 32)
	if err != nil {
		return transactionReference{}, errors.New("invalid payment workchain")
	}
	account, err := hex.DecodeString(parts[4])
	if err != nil || len(account) != 32 || parts[4] != strings.ToLower(parts[4]) {
		return transactionReference{}, errors.New("invalid payment account ID")
	}
	lt, err := strconv.ParseUint(parts[5], 10, 64)
	if err != nil || lt == 0 || parts[5] != strconv.FormatUint(lt, 10) {
		return transactionReference{}, errors.New("invalid payment logical time")
	}
	hash, err := hex.DecodeString(parts[6])
	if err != nil || len(hash) != 32 || parts[6] != strings.ToLower(parts[6]) {
		return transactionReference{}, errors.New("invalid payment transaction hash")
	}
	payee := fmt.Sprintf("%d:%s", wc, parts[4])
	if _, err := requireCanonicalAddress(payee); err != nil {
		return transactionReference{}, err
	}
	return transactionReference{
		payee: payee, workchain: int32(wc), account: account, lt: lt, hash: hash,
	}, nil
}

func (a *Adapter) ObservePayment(
	ctx context.Context,
	reference chain.PaymentReference,
) (chain.PaymentState, error) {
	if a == nil || ctx == nil {
		return chain.PaymentState{}, errors.New("invalid TOS payment observation request")
	}
	if reference.Network != a.network || !boundedReference(reference.AuthorizationID) ||
		!boundedReference(reference.QuoteID) || !boundedReference(reference.RequestID) ||
		reference.AmountNanoTOS == 0 {
		return chain.PaymentState{}, errors.New("invalid TOS payment observation reference")
	}
	payer, err := requireCanonicalAddress(reference.Payer)
	if err != nil {
		return chain.PaymentState{}, fmt.Errorf("invalid expected payer: %w", err)
	}
	payee, err := requireCanonicalAddress(reference.Payee)
	if err != nil {
		return chain.PaymentState{}, fmt.Errorf("invalid expected payee: %w", err)
	}
	target, err := parseTransactionReference(reference.Reference)
	if err != nil {
		return chain.PaymentState{}, err
	}
	if target.payee != payee {
		return chain.PaymentState{}, errors.New("payment reference does not name expected payee")
	}
	observation, nodes, err := a.consensus(ctx)
	if err != nil {
		return chain.PaymentState{}, err
	}
	if observation.seqno < reference.MinimumMasterSeqno {
		return chain.PaymentState{}, errors.New("TOS payment observation is below high-water mark")
	}
	state, _, err := quorumRead(ctx, nodes, a.quorum, func(
		ctx context.Context,
		node *rpcNode,
	) (paymentQuorumState, error) {
		return readPayment(ctx, node, target)
	})
	if err != nil {
		return chain.PaymentState{}, fmt.Errorf("resolve TOS payment quorum: %w", err)
	}
	// getTransactions has no historical masterchain-seqno parameter. Take a
	// second finalized quorum observation after the exact transaction read so
	// the returned high-water mark cannot predate a transaction that appeared
	// between the first consensus read and the account-history query.
	finalObservation, _, err := a.consensus(ctx)
	if err != nil {
		return chain.PaymentState{}, err
	}
	if finalObservation.seqno < observation.seqno ||
		finalObservation.seqno < reference.MinimumMasterSeqno {
		return chain.PaymentState{}, errors.New("TOS payment finality observation moved backwards")
	}
	result := chain.PaymentState{
		Network: a.network, AuthorizationID: reference.AuthorizationID,
		QuoteID: reference.QuoteID, RequestID: reference.RequestID,
		Reference: reference.Reference, Confirmed: state.Found, Finalized: true,
		ObservedMasterSeqno: finalObservation.seqno, ObservedAt: finalObservation.observedAt,
	}
	if state.Found {
		result.Payer = state.Payer
		result.Payee = state.Payee
		result.AmountNanoTOS = state.AmountNanoTOS
	} else {
		// Echoing the authenticated expectations keeps the negative result
		// stateless. No claim about an observed transfer is made: Confirmed is
		// false and TOS finalized blocks do not reorganize.
		result.Payer = payer
		result.Payee = payee
		result.AmountNanoTOS = reference.AmountNanoTOS
	}
	return result, nil
}

func readPayment(
	ctx context.Context,
	node *rpcNode,
	target transactionReference,
) (paymentQuorumState, error) {
	params := struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{
		Address: target.payee, Limit: 1, LT: strconv.FormatUint(target.lt, 10),
		Hash: base64.StdEncoding.EncodeToString(target.hash),
	}
	var transactions []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", params, &transactions); err != nil {
		var rpcError *chain.RPCError
		if errors.As(err, &rpcError) && rpcError.Code == -32603 &&
			strings.Contains(rpcError.Message, "cannot locate transaction") {
			return paymentQuorumState{Found: false}, nil
		}
		return paymentQuorumState{}, err
	}
	if len(transactions) != 1 {
		return paymentQuorumState{}, errors.New("exact TOS transaction query returned an unexpected count")
	}
	payer, payee, amount, err := decodePaymentTransaction(transactions[0], target)
	if err != nil {
		return paymentQuorumState{}, err
	}
	return paymentQuorumState{
		Found: true, Payer: payer, Payee: payee, AmountNanoTOS: amount,
	}, nil
}

func decodePaymentTransaction(
	raw rawTransaction,
	target transactionReference,
) (payer string, payee string, amount uint64, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			payer, payee, amount = "", "", 0
			err = fmt.Errorf("invalid transaction BOC: %v", recovered)
		}
	}()
	if raw.Type != "raw.transaction" || raw.BlockID.Type != "tos.blockIdExt" ||
		raw.TransactionID.Type != "internal.transactionId" ||
		raw.BlockID.Workchain != target.workchain || raw.BlockID.Seqno == 0 || raw.Data == "" {
		return "", "", 0, errors.New("invalid raw TOS transaction response")
	}
	if _, parseErr := decodeBase64Hash(raw.BlockID.RootHash); parseErr != nil {
		return "", "", 0, errors.New("invalid transaction block root hash")
	}
	if _, parseErr := decodeBase64Hash(raw.BlockID.FileHash); parseErr != nil {
		return "", "", 0, errors.New("invalid transaction block file hash")
	}
	lt, parseErr := strconv.ParseUint(raw.TransactionID.LT, 10, 64)
	if parseErr != nil || lt != target.lt {
		return "", "", 0, errors.New("transaction logical time does not match reference")
	}
	responseHash, parseErr := base64.StdEncoding.DecodeString(raw.TransactionID.Hash)
	if parseErr != nil || !bytes.Equal(responseHash, target.hash) {
		return "", "", 0, errors.New("transaction hash does not match reference")
	}
	boc, parseErr := base64.StdEncoding.DecodeString(raw.Data)
	if parseErr != nil {
		return "", "", 0, errors.New("invalid transaction BOC encoding")
	}
	root, parseErr := cell.FromBOC(boc)
	if parseErr != nil || !bytes.Equal(root.Hash(), target.hash) {
		return "", "", 0, errors.New("transaction BOC hash does not match reference")
	}
	var transaction tlb.Transaction
	if parseErr := tlb.LoadFromCell(&transaction, root.BeginParse()); parseErr != nil {
		return "", "", 0, fmt.Errorf("decode TOS transaction: %w", parseErr)
	}
	if transaction.LT != target.lt || !bytes.Equal(transaction.AccountAddr, target.account) ||
		transaction.Now != raw.Utime ||
		!strings.EqualFold(raw.Account, hex.EncodeToString(target.account)) || transaction.IO.In == nil ||
		transaction.IO.In.MsgType != tlb.MsgTypeInternal {
		return "", "", 0, errors.New("transaction does not identify an inbound internal payment")
	}
	message := transaction.IO.In.AsInternal()
	if message == nil || message.Bounced || message.SrcAddr == nil || message.DstAddr == nil ||
		message.SrcAddr.Type() != address.StdAddress || message.DstAddr.Type() != address.StdAddress {
		return "", "", 0, errors.New("transaction inbound message is not a non-bounced standard transfer")
	}
	payer = message.SrcAddr.StringRaw()
	payee = message.DstAddr.StringRaw()
	if payee != target.payee {
		return "", "", 0, errors.New("transaction destination does not match payment reference")
	}
	nano := message.Amount.Nano()
	if nano.Sign() <= 0 || !nano.IsUint64() {
		return "", "", 0, errors.New("transaction payment amount is outside uint64")
	}
	return payer, payee, nano.Uint64(), nil
}

func decodeBase64Hash(value string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("invalid base64 hash")
	}
	return decoded, nil
}

func boundedReference(value string) bool {
	return len(value) >= 1 && len(value) <= 128 && strings.TrimSpace(value) == value
}
