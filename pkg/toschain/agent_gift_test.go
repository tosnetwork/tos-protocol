package toschain

import (
	"encoding/base64"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func testGiftMessage(t *testing.T, kind tlb.MsgType, source, destination string, amount uint64) *tlb.Message {
	t.Helper()
	dest, err := address.ParseRawAddr(destination)
	if err != nil {
		t.Fatal(err)
	}
	if kind == tlb.MsgTypeExternalIn {
		return &tlb.Message{MsgType: kind, Msg: &tlb.ExternalMessage{
			SrcAddr: address.NewAddressNone(), DstAddr: dest, ImportFee: tlb.ZeroCoins,
			Body: cell.BeginCell().EndCell(),
		}}
	}
	src, err := address.ParseRawAddr(source)
	if err != nil {
		t.Fatal(err)
	}
	return &tlb.Message{MsgType: kind, Msg: &tlb.InternalMessage{
		IHRDisabled: true, Bounce: false, SrcAddr: src, DstAddr: dest,
		Amount: tlb.FromNanoTONU(amount), IHRFee: tlb.ZeroCoins, FwdFee: tlb.ZeroCoins,
		Body: cell.BeginCell().EndCell(),
	}}
}

func testGiftOutputs(t *testing.T, messages ...*tlb.Message) *tlb.MessagesList {
	t.Helper()
	dictionary := cell.NewDict(15)
	for index, message := range messages {
		encoded, err := message.ToCell()
		if err != nil {
			t.Fatal(err)
		}
		if err := dictionary.SetIntKey(big.NewInt(int64(index)), cell.BeginCell().MustStoreRef(encoded).EndCell()); err != nil {
			t.Fatal(err)
		}
	}
	return &tlb.MessagesList{List: dictionary}
}

func successfulGiftDescription(amount uint64) tlb.TransactionDescriptionOrdinary {
	return tlb.TransactionDescriptionOrdinary{
		ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: true}},
		CreditPhase:  &tlb.CreditPhase{Credit: tlb.CurrencyCollection{Coins: tlb.FromNanoTONU(amount)}},
	}
}

func TestDecodeFinalizedAgentAccountDataAndDailyReset(t *testing.T) {
	owner, _ := address.ParseRawAddr("-1:" + strings.Repeat("1", 64))
	policy := cell.BeginCell().MustStoreCoins(5_000_000_000).MustStoreCoins(6_000_000_000).
		MustStoreUInt(3600, 64).MustStoreBoolBit(false).MustStoreBoolBit(false).EndCell()
	data := cell.BeginCell().MustStoreAddr(owner).MustStoreSlice([]byte(strings.Repeat("c", 32)), 256).
		MustStoreSlice([]byte(strings.Repeat("d", 32)), 256).
		MustStoreUInt(9, 64).MustStoreUInt(7, 32).MustStoreUInt(1, 32).MustStoreCoins(2_000_000_000).MustStoreRef(policy).EndCell()
	encoded := base64.StdEncoding.EncodeToString(data.ToBOCWithFlags(false))
	account, err := decodeAgentAccountData(encoded, "-1:"+strings.Repeat("2", 64), 9_000_000_000, 42, 2*86400)
	if err != nil {
		t.Fatal(err)
	}
	if account.OwnerAddress != owner.StringRaw() || account.ControllerEpoch != 9 || account.Seqno != 7 || account.MaxPerTxAtomic != 5_000_000_000 || account.DailyRemainingAtomic != 6_000_000_000 || account.GlobalID != 42 || account.DeploymentID == "" {
		t.Fatalf("wrong Agent Account state: %+v", account)
	}
	sameDay, err := decodeAgentAccountData(encoded, account.Address, 9_000_000_000, 42, 86400)
	if err != nil || sameDay.DailyRemainingAtomic != 4_000_000_000 {
		t.Fatalf("same-day spend was not applied: %+v %v", sameDay, err)
	}
}

func TestDecodeAgentAccountRejectsHiddenStateData(t *testing.T) {
	owner, _ := address.ParseRawAddr("-1:" + strings.Repeat("1", 64))
	policy := cell.BeginCell().MustStoreCoins(5).MustStoreCoins(6).MustStoreUInt(1, 64).
		MustStoreBoolBit(false).MustStoreBoolBit(false).MustStoreUInt(1, 1).EndCell()
	data := cell.BeginCell().MustStoreAddr(owner).MustStoreSlice(make([]byte, 32), 256).
		MustStoreSlice([]byte(strings.Repeat("d", 32)), 256).
		MustStoreUInt(0, 64).MustStoreUInt(0, 32).MustStoreUInt(0, 32).MustStoreCoins(0).MustStoreRef(policy).EndCell()
	if _, err := decodeAgentAccountData(base64.StdEncoding.EncodeToString(data.ToBOCWithFlags(false)), "-1:"+strings.Repeat("2", 64), 1, 42, 1); err == nil {
		t.Fatal("hidden Agent Account policy data was accepted")
	}
}

func TestGiftExecutionRequiresExactExternalAndOneExactOutput(t *testing.T) {
	account := "-1:" + strings.Repeat("1", 64)
	destination := "0:" + strings.Repeat("2", 64)
	input := testGiftMessage(t, tlb.MsgTypeExternalIn, "", account, 0)
	inputCell, err := input.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	output := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 500)
	transaction := tlb.Transaction{Now: 200, OutMsgCount: 1, Description: successfulGiftDescription(0)}
	transaction.IO.In = input
	transaction.IO.Out = testGiftOutputs(t, output)

	vote, err := matchGiftExecution([]tlb.Transaction{transaction}, inputCell.Hash(), account, destination, 500, 100)
	if err != nil || !vote.Executed || !vote.ExactOutput || vote.OutputHash == "" {
		t.Fatalf("exact Gift execution was not linked: %+v %v", vote, err)
	}

	second := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 1)
	multiple := transaction
	multiple.OutMsgCount = 2
	multiple.IO.Out = testGiftOutputs(t, output, second)
	vote, err = matchGiftExecution([]tlb.Transaction{multiple}, inputCell.Hash(), account, destination, 500, 100)
	if err != nil || !vote.Executed || vote.ExactOutput {
		t.Fatalf("multi-action Gift execution was accepted: %+v %v", vote, err)
	}

	wrongOutput := transaction
	wrongOutput.IO.Out = testGiftOutputs(t, testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 499))
	vote, err = matchGiftExecution([]tlb.Transaction{wrongOutput}, inputCell.Hash(), account, destination, 500, 100)
	if err != nil || !vote.Executed || vote.ExactOutput {
		t.Fatalf("wrong Gift principal was accepted: %+v %v", vote, err)
	}

	for name, malformed := range map[string]*tlb.Message{
		"wrong source": testGiftMessage(t, tlb.MsgTypeInternal, "-1:"+strings.Repeat("3", 64), destination, 500),
		"bouncing": func() *tlb.Message {
			message := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 500)
			message.AsInternal().Bounce = true
			return message
		}(),
		"body": func() *tlb.Message {
			message := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 500)
			message.AsInternal().Body = cell.BeginCell().MustStoreUInt(1, 1).EndCell()
			return message
		}(),
	} {
		malformedOutput := transaction
		malformedOutput.IO.Out = testGiftOutputs(t, malformed)
		vote, err = matchGiftExecution([]tlb.Transaction{malformedOutput}, inputCell.Hash(), account, destination, 500, 100)
		if err != nil || !vote.Executed || vote.ExactOutput {
			t.Fatalf("%s Gift output was accepted: %+v %v", name, vote, err)
		}
	}

	failed := transaction
	failed.Description = tlb.TransactionDescriptionOrdinary{ComputePhase: tlb.ComputePhase{Phase: tlb.ComputePhaseVM{Success: false}}}
	vote, err = matchGiftExecution([]tlb.Transaction{failed}, inputCell.Hash(), account, destination, 500, 100)
	if err != nil || vote.Executed || !vote.AbsenceKnown {
		t.Fatalf("failed exact external execution was not finalized as unsuccessful: %+v %v", vote, err)
	}

	unrelated := transaction
	unrelated.IO.In = testGiftMessage(t, tlb.MsgTypeExternalIn, "", account, 0)
	unrelated.IO.In.AsExternalIn().Body = cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	unrelated.Now = 99
	otherCell, _ := unrelated.IO.In.ToCell()
	if hex.EncodeToString(otherCell.Hash()) == hex.EncodeToString(inputCell.Hash()) {
		t.Fatal("test did not construct an unrelated external message")
	}
	vote, err = matchGiftExecution([]tlb.Transaction{unrelated}, inputCell.Hash(), account, destination, 500, 100)
	if err != nil || vote.Executed || !vote.AbsenceKnown {
		t.Fatalf("bounded finalized absence was not established: %+v %v", vote, err)
	}
}

func TestGiftCreditRequiresTheExactInternalMessageAndCreditPhase(t *testing.T) {
	account := "-1:" + strings.Repeat("1", 64)
	destination := "0:" + strings.Repeat("2", 64)
	output := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 500)
	outputCell, err := output.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	transaction := tlb.Transaction{Description: successfulGiftDescription(500)}
	transaction.IO.In = output
	credit, err := matchGiftCredit([]tlb.Transaction{transaction}, destination, hex.EncodeToString(outputCell.Hash()), 500, 100)
	if err != nil || !credit.Credited || !credit.AbsenceKnown {
		t.Fatalf("exact destination credit was not linked: credit=%+v err=%v", credit, err)
	}

	wrongCredit := transaction
	wrongCredit.Description = successfulGiftDescription(499)
	credit, err = matchGiftCredit([]tlb.Transaction{wrongCredit}, destination, hex.EncodeToString(outputCell.Hash()), 500, 100)
	if err != nil || credit.Credited || !credit.AbsenceKnown {
		t.Fatalf("internal message without exact destination credit was not finalized as unpaid: %+v %v", credit, err)
	}

	other := testGiftMessage(t, tlb.MsgTypeInternal, account, destination, 500)
	other.AsInternal().CreatedLT = 1
	transaction.IO.In = other
	credit, err = matchGiftCredit([]tlb.Transaction{transaction}, destination, hex.EncodeToString(outputCell.Hash()), 500, 100)
	if err != nil || credit.Credited || !credit.AbsenceKnown {
		t.Fatalf("different internal message was linked: credit=%+v err=%v", credit, err)
	}
}

func TestGiftCreditAbsenceRequiresACompleteBoundedHistory(t *testing.T) {
	destination := "0:" + strings.Repeat("2", 64)
	history := make([]tlb.Transaction, maxGiftHistoryTransactions)
	for index := range history {
		history[index] = tlb.Transaction{Now: 200, PrevTxLT: 1}
	}
	credit, err := matchGiftCredit(history, destination, strings.Repeat("0", 64), 500, 100)
	if err != nil || credit.Credited || credit.AbsenceKnown {
		t.Fatalf("bounded credit miss was treated as final: credit=%+v err=%v", credit, err)
	}

	history[len(history)-1].Now = 99
	credit, err = matchGiftCredit(history, destination, strings.Repeat("0", 64), 500, 100)
	if err != nil || credit.Credited || !credit.AbsenceKnown {
		t.Fatalf("history crossing Gift creation did not prove absence: credit=%+v err=%v", credit, err)
	}
}
