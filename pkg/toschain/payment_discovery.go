package toschain

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

// FindExactPayment performs bounded, read-only discovery in a payee account's
// transaction history. It is intended for a key-custody publisher recovering
// an uncertain send; finality remains the quorum Adapter's responsibility.
func FindExactPayment(ctx context.Context, client *chain.Client, payer, payee string, amount uint64, comment string, lookback int) (string, bool, error) {
	if ctx == nil || client == nil || amount == 0 || lookback < 1 || lookback > 100 {
		return "", false, errors.New("invalid payment discovery request")
	}
	var err error
	payer, err = requireCanonicalAddress(payer)
	if err != nil {
		return "", false, err
	}
	payee, err = requireCanonicalAddress(payee)
	if err != nil {
		return "", false, err
	}
	var info accountInformation
	if err := client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
	}{payee}, &info); err != nil {
		return "", false, err
	}
	if info.LastTransactionID.LT == "" || info.LastTransactionID.LT == "0" {
		return "", false, nil
	}
	lt, err := strconv.ParseUint(info.LastTransactionID.LT, 10, 64)
	if err != nil || lt == 0 {
		return "", false, errors.New("invalid payment discovery cursor")
	}
	hash, err := base64.StdEncoding.DecodeString(info.LastTransactionID.Hash)
	if err != nil || len(hash) != 32 {
		return "", false, errors.New("invalid payment discovery hash")
	}
	var transactions []rawTransaction
	params := struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{payee, lookback, strconv.FormatUint(lt, 10), base64.StdEncoding.EncodeToString(hash)}
	if err := client.Call(ctx, "getTransactions", params, &transactions); err != nil {
		return "", false, err
	}
	parts, _ := parseTransactionReferenceParts(payee)
	for _, raw := range transactions {
		txLT, e := strconv.ParseUint(raw.TransactionID.LT, 10, 64)
		if e != nil || txLT == 0 {
			continue
		}
		txHash, e := base64.StdEncoding.DecodeString(raw.TransactionID.Hash)
		if e != nil || len(txHash) != 32 {
			continue
		}
		target := transactionReference{payee: payee, workchain: parts.workchain, account: parts.account, lt: txLT, hash: txHash}
		gotPayer, gotPayee, gotAmount, gotComment, e := decodePaymentTransaction(raw, target)
		if e == nil && gotPayer == payer && gotPayee == payee && gotAmount == amount && gotComment == comment {
			ref, e := FormatTransactionReference(payee, txLT, txHash)
			return ref, e == nil, e
		}
	}
	return "", false, nil
}

func parseTransactionReferenceParts(payee string) (transactionReference, error) {
	return parseTransactionReference("tos:tx:v1:" + payee + ":1:0000000000000000000000000000000000000000000000000000000000000000")
}
