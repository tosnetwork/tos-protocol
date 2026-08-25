package toschain

import (
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func stablecoinCreditMessage(t *testing.T, sourceWallet, recipientWallet, sourceOwner string,
	query uint64, amount *big.Int) *tlb.Message {
	t.Helper()
	source, err := address.ParseRawAddr(sourceWallet)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := address.ParseRawAddr(recipientWallet)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := address.ParseRawAddr(sourceOwner)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(0x178d4519, 32).MustStoreUInt(query, 64).
		MustStoreBigCoins(amount).MustStoreAddr(owner).MustStoreAddr(owner).MustStoreCoins(0).
		MustStoreBoolBit(false).EndCell()
	return &tlb.Message{MsgType: tlb.MsgTypeInternal, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounce: true, SrcAddr: source, DstAddr: recipient,
		Amount: tlb.ZeroCoins, IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins, Body: body,
	}}
}

func TestStablecoinCreditRequiresExactWalletTransferTuple(t *testing.T) {
	sourceWallet := "0:" + strings.Repeat("1", 64)
	recipientWallet := "0:" + strings.Repeat("2", 64)
	sourceOwner := "0:" + strings.Repeat("3", 64)
	amount := big.NewInt(25_000_000)
	message := stablecoinCreditMessage(t, sourceWallet, recipientWallet, sourceOwner, 19, amount)
	transaction := tlb.Transaction{Now: 200, Hash: []byte(strings.Repeat("h", 32)),
		Description: successfulGiftDescription(0)}
	transaction.IO.In = message

	vote, err := matchStablecoinCredit([]tlb.Transaction{transaction}, sourceWallet, recipientWallet,
		sourceOwner, 19, amount, 100)
	if err != nil || !vote.Credited || !vote.AbsenceKnown || vote.TransactionHash == "" || vote.TransactionTime != 200 {
		t.Fatalf("exact stablecoin credit was not proven: %+v %v", vote, err)
	}

	for name, mutate := range map[string]func(*tlb.Message){
		"query": func(message *tlb.Message) {
			message.AsInternal().Body = stablecoinCreditMessage(t, sourceWallet, recipientWallet, sourceOwner, 20, amount).AsInternal().Body
		},
		"amount": func(message *tlb.Message) {
			message.AsInternal().Body = stablecoinCreditMessage(t, sourceWallet, recipientWallet, sourceOwner, 19, big.NewInt(24_999_999)).AsInternal().Body
		},
		"source wallet": func(message *tlb.Message) {
			message.AsInternal().SrcAddr, _ = address.ParseRawAddr("0:" + strings.Repeat("4", 64))
		},
	} {
		copyMessage := *message
		internal := *message.AsInternal()
		copyMessage.Msg = &internal
		mutate(&copyMessage)
		candidate := transaction
		candidate.IO.In = &copyMessage
		vote, err = matchStablecoinCredit([]tlb.Transaction{candidate}, sourceWallet, recipientWallet,
			sourceOwner, 19, amount, 100)
		if err != nil || vote.Credited || !vote.AbsenceKnown {
			t.Fatalf("%s mutation was accepted: %+v %v", name, vote, err)
		}
	}

	failed := transaction
	failed.Description = tlb.TransactionDescriptionOrdinary{
		ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: false}}}
	if _, err := matchStablecoinCredit([]tlb.Transaction{failed}, sourceWallet, recipientWallet,
		sourceOwner, 19, amount, 100); err == nil {
		t.Fatal("failed exact wallet transaction was accepted")
	}
}

func TestStablecoinCreditAbsenceRequiresHistoryCrossingTheReleaseTime(t *testing.T) {
	history := make([]tlb.Transaction, maxStablecoinCreditHistoryTransactions)
	for index := range history {
		history[index] = tlb.Transaction{Now: 200, PrevTxLT: 1}
	}
	vote, err := matchStablecoinCredit(history, "0:"+strings.Repeat("1", 64),
		"0:"+strings.Repeat("2", 64), "0:"+strings.Repeat("3", 64), 1, big.NewInt(1), 100)
	if err != nil || vote.Credited || vote.AbsenceKnown {
		t.Fatalf("truncated credit history was treated as final: %+v %v", vote, err)
	}
	history[len(history)-1].Now = 99
	vote, err = matchStablecoinCredit(history, "0:"+strings.Repeat("1", 64),
		"0:"+strings.Repeat("2", 64), "0:"+strings.Repeat("3", 64), 1, big.NewInt(1), 100)
	if err != nil || vote.Credited || !vote.AbsenceKnown {
		t.Fatalf("credit history crossing release time did not prove absence: %+v %v", vote, err)
	}
}
