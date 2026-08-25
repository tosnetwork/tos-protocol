// local-stablecoin-fixture builds the deterministic StateInit and mint body
// used by the real three-node Paid Demand campaign. It is test setup only; an
// OpenFox runtime must consume an already owner-approved asset identity.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type fixture struct {
	MasterAddress        string `json:"master_address"`
	MasterCodeHash       string `json:"master_code_hash"`
	MasterStateInitBOC   string `json:"master_state_init_boc_base64"`
	MasterStateInitHash  string `json:"master_state_init_hash"`
	WalletCodeHash       string `json:"wallet_code_hash"`
	RecipientAddress     string `json:"recipient_address"`
	RecipientWallet      string `json:"recipient_wallet_address"`
	MintAmountAtomic     string `json:"mint_amount_atomic"`
	MintAttachedNanoTOS  uint64 `json:"mint_attached_nanotos"`
	MintBodyBOC          string `json:"mint_body_boc_base64"`
	MintBodyHash         string `json:"mint_body_hash"`
	DeterministicQueryID uint64 `json:"deterministic_query_id"`
}

func main() {
	var masterCodePath, walletCodePath, adminText, recipientText, amountText string
	var queryID, mintAttached uint64
	flag.StringVar(&masterCodePath, "master-code-boc", "", "compiled master code BOC path")
	flag.StringVar(&walletCodePath, "wallet-code-boc", "", "compiled wallet code BOC or base64 path")
	flag.StringVar(&adminText, "admin", "", "raw workchain-zero admin address")
	flag.StringVar(&recipientText, "recipient", "", "raw workchain-zero mint recipient")
	flag.StringVar(&amountText, "amount-atomic", "250000000", "canonical positive atomic amount")
	flag.Uint64Var(&queryID, "query-id", 1, "non-zero deterministic mint query ID")
	flag.Uint64Var(&mintAttached, "mint-attached-nanotos", 500_000_000, "native TOS forwarded to the new wallet")
	flag.Parse()
	admin := rawAddress(adminText)
	recipient := rawAddress(recipientText)
	amount, ok := new(big.Int).SetString(amountText, 10)
	if masterCodePath == "" || walletCodePath == "" || admin == nil || recipient == nil || !ok ||
		amount.Sign() <= 0 || amount.String() != amountText || queryID == 0 || mintAttached == 0 {
		fatal("invalid local stablecoin fixture arguments")
	}
	masterCode := readCode(masterCodePath)
	walletCode := readCode(walletCodePath)
	metadata := cell.BeginCell().EndCell()
	masterData := cell.BeginCell().MustStoreCoins(0).MustStoreAddr(admin).
		MustStoreAddr(address.NewAddressNone()).MustStoreRef(walletCode).MustStoreRef(metadata).EndCell()
	stateInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(masterCode).MustStoreBoolBit(true).MustStoreRef(masterData).
		MustStoreBoolBit(false).EndCell()
	master := address.NewAddress(0, 0, stateInit.Hash())
	walletData := cell.BeginCell().MustStoreUInt(0, 4).MustStoreCoins(0).
		MustStoreAddr(recipient).MustStoreAddr(master).EndCell()
	walletInit := cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(walletCode).MustStoreBoolBit(true).MustStoreRef(walletData).
		MustStoreBoolBit(false).EndCell()
	recipientWallet := address.NewAddress(0, 0, walletInit.Hash())
	internalTransfer := cell.BeginCell().MustStoreUInt(0x178d4519, 32).MustStoreUInt(queryID, 64).
		MustStoreBigCoins(amount).MustStoreAddr(admin).MustStoreAddr(admin).MustStoreCoins(0).
		MustStoreBoolBit(false).EndCell()
	mintBody := cell.BeginCell().MustStoreUInt(0x642b7d07, 32).MustStoreUInt(queryID, 64).
		MustStoreAddr(recipient).MustStoreCoins(mintAttached).MustStoreRef(internalTransfer).EndCell()
	value := fixture{MasterAddress: master.StringRaw(), MasterCodeHash: digest(masterCode),
		MasterStateInitBOC:  base64.StdEncoding.EncodeToString(stateInit.ToBOCWithFlags(false)),
		MasterStateInitHash: digest(stateInit), WalletCodeHash: digest(walletCode),
		RecipientAddress: recipient.StringRaw(), RecipientWallet: recipientWallet.StringRaw(),
		MintAmountAtomic: amountText, MintAttachedNanoTOS: mintAttached,
		MintBodyBOC:  base64.StdEncoding.EncodeToString(mintBody.ToBOCWithFlags(false)),
		MintBodyHash: digest(mintBody), DeterministicQueryID: queryID}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fatal(err.Error())
	}
}

func readCode(path string) *cell.Cell {
	raw, err := os.ReadFile(path)
	if err != nil {
		fatal(err.Error())
	}
	root, err := cell.FromBOC(raw)
	if err == nil {
		return root
	}
	compact := strings.Join(strings.Fields(string(raw)), "")
	decoded, decodeErr := base64.StdEncoding.Strict().DecodeString(compact)
	if decodeErr != nil {
		fatal("contract code is neither binary nor canonical base64 BOC")
	}
	root, err = cell.FromBOC(decoded)
	if err != nil {
		fatal("contract code BOC is invalid")
	}
	return root
}

func rawAddress(value string) *address.Address {
	parsed, err := address.ParseRawAddr(value)
	if err != nil {
		parsed, err = address.ParseAddr(value)
	}
	if err != nil || parsed == nil || parsed.Workchain() != 0 {
		return nil
	}
	return parsed
}

func digest(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
