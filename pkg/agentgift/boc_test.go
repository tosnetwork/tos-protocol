package agentgift

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func buildNativeBOC(t *testing.T, opcode uint64, globalID int32, seqno, validUntil uint32, account, destination string, amount uint64, private ed25519.PrivateKey, trailing bool) []byte {
	t.Helper()
	accountAddress, err := address.ParseRawAddr(account)
	if err != nil {
		t.Fatal(err)
	}
	destinationAddress, err := address.ParseRawAddr(destination)
	if err != nil {
		t.Fatal(err)
	}
	payloadBuilder := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreInt(int64(globalID), 32).MustStoreUInt(uint64(seqno), 32).MustStoreUInt(uint64(validUntil), 32).MustStoreAddr(destinationAddress).MustStoreCoins(amount)
	if trailing {
		payloadBuilder.MustStoreUInt(1, 1)
	}
	payload := payloadBuilder.EndCell()
	var payloadHash [32]byte
	copy(payloadHash[:], payload.Hash())
	hash, err := controllerBindingHash(account, globalID, payloadHash)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, hash)
	body := cell.BeginCell().MustStoreSlice(signature, 512).MustStoreBuilder(payload.ToBuilder()).EndCell()
	external := &tlb.ExternalMessage{SrcAddr: address.NewAddressNone(), DstAddr: accountAddress, ImportFee: tlb.ZeroCoins, Body: body}
	root, err := external.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	return root.ToBOCWithFlags(false)
}

func buildCancelBOC(t *testing.T, globalID int32, seqno, validUntil uint32, account string, private ed25519.PrivateKey, trailing bool) []byte {
	t.Helper()
	accountAddress, err := address.ParseRawAddr(account)
	if err != nil {
		t.Fatal(err)
	}
	payloadBuilder := cell.BeginCell().MustStoreUInt(AgentCancelSeqnoOpcode, 32).MustStoreInt(int64(globalID), 32).MustStoreUInt(uint64(seqno), 32).MustStoreUInt(uint64(validUntil), 32)
	if trailing {
		payloadBuilder.MustStoreUInt(1, 1)
	}
	payload := payloadBuilder.EndCell()
	var payloadHash [32]byte
	copy(payloadHash[:], payload.Hash())
	hash, err := controllerBindingHash(account, globalID, payloadHash)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreSlice(ed25519.Sign(private, hash), 512).MustStoreBuilder(payload.ToBuilder()).EndCell()
	root, err := (&tlb.ExternalMessage{SrcAddr: address.NewAddressNone(), DstAddr: accountAddress, ImportFee: tlb.ZeroCoins, Body: body}).ToCell()
	if err != nil {
		t.Fatal(err)
	}
	return root.ToBOCWithFlags(false)
}

func TestParseAndVerifyAgentCancelSeqnoBOC(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	account := testRequest().SenderAgentAccount
	boc := buildCancelBOC(t, 42, 7, 2_000_000_000, account, private, false)
	input := VerifyCancelSeqnoInput{ExactSignedBOC: boc, Account: FinalizedAgentAccount{Active: true, Address: account, CodeHash: AgentAccountCodeHash, GlobalID: 42, TVMVersion: MinimumAgentAccountTVMVersion, ControllerPublicKey: public, Seqno: 7, DefaultTaskTimeoutSecs: 3_600}, ExpectedGlobalID: 42, ExpectedSeqno: 7, ExpectedValidUntil: 2_000_000_000, FinalizedChainTime: 1_999_999_000}
	parsed, err := VerifyAgentCancelSeqno(input)
	if err != nil || parsed.SenderAgentAccount != account || parsed.Seqno != 7 {
		t.Fatalf("valid cancellation failed: %+v %v", parsed, err)
	}
	for name, mutate := range map[string]func(*VerifyCancelSeqnoInput){
		"account": func(v *VerifyCancelSeqnoInput) { v.Account.Address = "-1:" + strings.Repeat("0", 64) },
		"global":  func(v *VerifyCancelSeqnoInput) { v.ExpectedGlobalID++ },
		"seqno":   func(v *VerifyCancelSeqnoInput) { v.ExpectedSeqno++ },
		"valid":   func(v *VerifyCancelSeqnoInput) { v.ExpectedValidUntil++ },
		"key": func(v *VerifyCancelSeqnoInput) {
			other, _, _ := ed25519.GenerateKey(rand.Reader)
			v.Account.ControllerPublicKey = other
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := input
			mutate(&changed)
			if _, err := VerifyAgentCancelSeqno(changed); err == nil {
				t.Fatal("cancellation substitution accepted")
			}
		})
	}
	if _, err := ParseAgentCancelSeqnoBOC(buildCancelBOC(t, 42, 7, 2_000_000_000, account, private, true)); err == nil {
		t.Fatal("cancellation trailing data accepted")
	}
}

func TestParseAndVerifyAgentNativeSendBOC(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := testRequest()
	response := testResponse(t)
	boc := buildNativeBOC(t, AgentNativeSendOpcode, req.GlobalID, 7, response.ResponseNotAfter, req.SenderAgentAccount, response.DestinationAddress, 1_000_000_000, private, false)
	parsed, err := VerifyAgentNativeSend(VerifyNativeSendInput{ExactSignedBOC: boc, Request: req, Response: response,
		Account: FinalizedAgentAccount{Active: true, Address: req.SenderAgentAccount, CodeHash: AgentAccountCodeHash,
			DeploymentID: "state:abc", GlobalID: req.GlobalID, TVMVersion: MinimumAgentAccountTVMVersion,
			ControllerPublicKey: public, Seqno: 7, BalanceAtomic: 2_000_000_000, MaxPerTxAtomic: 1_500_000_000, DailyRemainingAtomic: 1_500_000_000, DefaultTaskTimeoutSecs: 3_600},
		ExpectedSignedGiftID: SignedGiftID(boc), FeeReserveAtomic: 100_000_000,
		FinalizedChainTime: response.ResponseNotAfter - 300, MinimumInclusionMargin: 120})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DestinationAddress != response.DestinationAddress || parsed.AmountAtomic != 1_000_000_000 || parsed.Seqno != 7 {
		t.Fatalf("wrong parsed transfer: %+v", parsed)
	}
}

func TestAgentNativeSendRejectsWrongOperationTrailingDataAndTamper(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	req := testRequest()
	response := testResponse(t)
	for name, boc := range map[string][]byte{
		"task-send": buildNativeBOC(t, 0x41475003, req.GlobalID, 0, response.ResponseNotAfter, req.SenderAgentAccount, response.DestinationAddress, 1, private, false),
		"trailing":  buildNativeBOC(t, AgentNativeSendOpcode, req.GlobalID, 0, response.ResponseNotAfter, req.SenderAgentAccount, response.DestinationAddress, 1, private, true),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAgentNativeSendBOC(boc); err == nil {
				t.Fatal("malicious BOC accepted")
			}
		})
	}
	valid := buildNativeBOC(t, AgentNativeSendOpcode, req.GlobalID, 0, response.ResponseNotAfter, req.SenderAgentAccount, response.DestinationAddress, 1_000_000_000, private, false)
	root, err := cell.FromBOC(valid)
	if err != nil {
		t.Fatal(err)
	}
	var message tlb.Message
	if err := tlb.LoadFromCell(&message, root.MustBeginParse()); err != nil {
		t.Fatal(err)
	}
	external := message.Msg.(*tlb.ExternalMessage)
	external.StateInit = &tlb.StateInit{Code: cell.BeginCell().EndCell()}
	withStateInit, err := external.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAgentNativeSendBOC(withStateInit.ToBOCWithFlags(false)); err == nil {
		t.Fatal("Gift StateInit was accepted")
	}
	external.StateInit = nil
	external.Body = external.Body.ToBuilder().MustStoreRef(cell.BeginCell().MustStoreUInt(1, 1).EndCell()).EndCell()
	withHiddenRef, err := external.ToCell()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAgentNativeSendBOC(withHiddenRef.ToBOCWithFlags(false)); err == nil {
		t.Fatal("hidden Gift action reference was accepted")
	}
	tampered := append([]byte(nil), valid...)
	tampered[len(tampered)-1] ^= 1
	if _, err := ParseAgentNativeSendBOC(tampered); err == nil {
		t.Fatal("tampered BOC accepted")
	}
	_ = public
}

func TestVerifyRejectsIdentityPolicyBalanceAndSignatureSubstitution(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	req := testRequest()
	response := testResponse(t)
	boc := buildNativeBOC(t, AgentNativeSendOpcode, req.GlobalID, 2, response.ResponseNotAfter, req.SenderAgentAccount, response.DestinationAddress, 1_000_000_000, private, false)
	base := VerifyNativeSendInput{ExactSignedBOC: boc, Request: req, Response: response, ExpectedSignedGiftID: SignedGiftID(boc), FeeReserveAtomic: 10,
		FinalizedChainTime: response.ResponseNotAfter - 300, MinimumInclusionMargin: 1,
		Account: FinalizedAgentAccount{Active: true, Address: req.SenderAgentAccount, CodeHash: AgentAccountCodeHash, GlobalID: req.GlobalID,
			TVMVersion: MinimumAgentAccountTVMVersion, ControllerPublicKey: public, Seqno: 2, BalanceAtomic: 2_000_000_000,
			MaxPerTxAtomic: 2_000_000_000, DailyRemainingAtomic: 2_000_000_000, DefaultTaskTimeoutSecs: 3_600}}
	cases := map[string]func(*VerifyNativeSendInput){
		"inactive":  func(v *VerifyNativeSendInput) { v.Account.Active = false },
		"code":      func(v *VerifyNativeSendInput) { v.Account.CodeHash = "tvm-cell-sha256:" + strings.Repeat("0", 64) },
		"TVM":       func(v *VerifyNativeSendInput) { v.Account.TVMVersion = MinimumAgentAccountTVMVersion - 1 },
		"network":   func(v *VerifyNativeSendInput) { v.Account.GlobalID++ },
		"seqno":     func(v *VerifyNativeSendInput) { v.Account.Seqno++ },
		"balance":   func(v *VerifyNativeSendInput) { v.Account.BalanceAtomic = 1 },
		"timeout":   func(v *VerifyNativeSendInput) { v.Account.DefaultTaskTimeoutSecs = 1 },
		"signed ID": func(v *VerifyNativeSendInput) { v.ExpectedSignedGiftID = "sha256:" + strings.Repeat("0", 64) },
		"destination": func(v *VerifyNativeSendInput) {
			v.Response.DestinationAddress = "0:" + strings.Repeat("e", 64)
		},
		"amount": func(v *VerifyNativeSendInput) {
			v.Request.AmountAtomic = "999999999"
			v.Response.AmountAtomic = "999999999"
		},
		"validity": func(v *VerifyNativeSendInput) {
			v.Request.RequestedValidUntil--
			v.Response.ResponseNotAfter--
		},
		"controller": func(v *VerifyNativeSendInput) {
			other, _, _ := ed25519.GenerateKey(rand.Reader)
			v.Account.ControllerPublicKey = other
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if _, err := VerifyAgentNativeSend(value); err == nil {
				t.Fatal("substitution accepted")
			}
		})
	}
}

func TestFinalizedResolverRequiresExactCreditAndFinalizedTime(t *testing.T) {
	base := FinalizedGiftObservation{Available: true, ExecutionFinalityKnown: true, FinalizedChainTime: 100, ExpectedDeploymentID: "deploy-a", CurrentDeploymentID: "deploy-a", SignedSeqno: 3, CurrentSeqno: 3, ValidUntil: 200, ControllerCurrentlyMatches: true, PolicyCurrentlyAllows: true, BalanceAtomic: 200, AmountAtomic: 100, FeeReserveAtomic: 10}
	if got, _ := ResolveFinalizedGift(base); got != ResolutionCurrentlyExecutable {
		t.Fatal(got)
	}
	insufficient := base
	insufficient.BalanceAtomic = 109
	if got, _ := ResolveFinalizedGift(insufficient); got != ResolutionInsufficientFunds {
		t.Fatal(got)
	}
	rotation := base
	rotation.ControllerCurrentlyMatches = false
	if got, _ := ResolveFinalizedGift(rotation); got != ResolutionCurrentlyUnexecutable {
		t.Fatal(got)
	}
	paid := base
	paid.ExactExternalBOCExecuted = true
	paid.ExactDestinationCredit = true
	if got, _ := ResolveFinalizedGift(paid); got != ResolutionFinalizedPaid {
		t.Fatal(got)
	}
	failedOutput := base
	failedOutput.ExactExternalBOCExecuted = true
	failedOutput.DestinationCreditFinalityKnown = true
	if got, _ := ResolveFinalizedGift(failedOutput); got != ResolutionInvalidatedUnpaid {
		t.Fatal(got)
	}
	pendingCredit := base
	pendingCredit.ExactExternalBOCExecuted = true
	if got, _ := ResolveFinalizedGift(pendingCredit); got != ResolutionPending {
		t.Fatal(got)
	}
	expired := base
	expired.FinalizedChainTime = 201
	if got, _ := ResolveFinalizedGift(expired); got != ResolutionExpiredUnpaid {
		t.Fatal(got)
	}
	localOnly := base
	localOnly.Available = false
	localOnly.FinalizedChainTime = 999
	if got, _ := ResolveFinalizedGift(localOnly); got != ResolutionFinalityUnknown {
		t.Fatal(got)
	}
	incompleteHistory := base
	incompleteHistory.ExecutionFinalityKnown = false
	if got, _ := ResolveFinalizedGift(incompleteHistory); got != ResolutionFinalityUnknown {
		t.Fatal(got)
	}
}
