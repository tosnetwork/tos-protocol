package agentgift

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	AgentNativeSendOpcode             = 0x41475004
	AgentCancelSeqnoOpcode            = 0x41475005
	AgentAccountCodeHash              = "tvm-cell-sha256:299c060b66635574c8bd482639bff02012b2e2de52cf58cedf0ef82d3fcf2229"
	AgentControllerSignatureDomainHex = "ede715a9852fbba2c3c234ed0d27329ae34d6263a82cfb6215da87c91683b471"
	MinimumAgentAccountTVMVersion     = 4
	AgentNativeSendMode               = 3
)

type ParsedNativeSend struct {
	ExactBOCDigest     string
	SignedGiftID       string
	SenderAgentAccount string
	GlobalID           int32
	Seqno              uint32
	ValidUntil         uint32
	DestinationAddress string
	AmountAtomic       uint64
	Signature          [64]byte
	PayloadHash        [32]byte
}

type ParsedCancelSeqno struct {
	ExactBOCDigest     string
	SenderAgentAccount string
	GlobalID           int32
	Seqno              uint32
	ValidUntil         uint32
	Signature          [64]byte
	PayloadHash        [32]byte
}

type FinalizedAgentAccount struct {
	Active                 bool
	Address                string
	OwnerAddress           string
	CodeHash               string
	DeploymentID           string
	GlobalID               int32
	TVMVersion             uint32
	ControllerPublicKey    ed25519.PublicKey
	Seqno                  uint32
	BalanceAtomic          uint64
	MaxPerTxAtomic         uint64
	DailyRemainingAtomic   uint64
	DefaultTaskTimeoutSecs uint64
}

type VerifyNativeSendInput struct {
	ExactSignedBOC         []byte
	Request                GiftAddressRequestV1
	Response               GiftAddressResponseV1
	Account                FinalizedAgentAccount
	ExpectedSignedGiftID   string
	FeeReserveAtomic       uint64
	FinalizedChainTime     uint32
	MinimumInclusionMargin uint32
}

type VerifyCancelSeqnoInput struct {
	ExactSignedBOC     []byte
	Account            FinalizedAgentAccount
	ExpectedGlobalID   int32
	ExpectedSeqno      uint32
	ExpectedValidUntil uint32
	FinalizedChainTime uint32
}

func ParseAgentCancelSeqnoBOC(boc []byte) (ParsedCancelSeqno, error) {
	var out ParsedCancelSeqno
	if len(boc) == 0 || len(boc) > MaxSignedBOCBytes {
		return out, errors.New("signed Agent Account cancellation BOC has invalid size")
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(boc, root.ToBOCWithFlags(false)) {
		return out, errors.New("signed Agent Account cancellation BOC is not canonical")
	}
	loader, err := root.BeginParse()
	if err != nil {
		return out, err
	}
	var message tlb.Message
	if tlb.LoadFromCell(&message, loader) != nil || loader.BitsLeft() != 0 || loader.RefsNum() != 0 || message.MsgType != tlb.MsgTypeExternalIn {
		return out, errors.New("cancellation BOC root is not one external inbound message")
	}
	external, ok := message.Msg.(*tlb.ExternalMessage)
	if !ok || external == nil || external.SrcAddr == nil || !external.SrcAddr.IsAddrNone() || external.DstAddr == nil || external.DstAddr.Type() != address.StdAddress || external.DstAddr.BitsLen() != 256 || external.ImportFee.Nano().Sign() != 0 || external.StateInit != nil || external.Body == nil {
		return out, errors.New("cancellation external message does not match Agent Account profile")
	}
	body, err := external.Body.BeginParse()
	if err != nil {
		return out, err
	}
	signature, err := body.LoadSlice(512)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return out, errors.New("missing cancellation controller signature")
	}
	payload := body.Copy()
	payloadCell, err := payload.ToCell()
	if err != nil {
		return out, errors.New("invalid cancellation payload cell")
	}
	copy(out.Signature[:], signature)
	copy(out.PayloadHash[:], payloadCell.Hash())
	op, err := body.LoadUInt(32)
	if err != nil || op != AgentCancelSeqnoOpcode {
		return out, errors.New("BOC is not agent_cancel_seqno")
	}
	globalID, err := body.LoadInt(32)
	if err != nil {
		return out, errors.New("invalid cancellation global ID")
	}
	seqno, err := body.LoadUInt(32)
	if err != nil {
		return out, errors.New("invalid cancellation seqno")
	}
	validUntil, err := body.LoadUInt(32)
	if err != nil || body.BitsLeft() != 0 || body.RefsNum() != 0 {
		return out, errors.New("cancellation payload contains hidden or trailing data")
	}
	out.ExactBOCDigest = ExactSignedBOCDigest(boc)
	out.SenderAgentAccount = external.DstAddr.StringRaw()
	out.GlobalID = int32(globalID)
	out.Seqno = uint32(seqno)
	out.ValidUntil = uint32(validUntil)
	return out, nil
}

func VerifyAgentCancelSeqno(input VerifyCancelSeqnoInput) (ParsedCancelSeqno, error) {
	var zero ParsedCancelSeqno
	parsed, err := ParseAgentCancelSeqnoBOC(input.ExactSignedBOC)
	if err != nil {
		return zero, err
	}
	account := input.Account
	if !account.Active || account.CodeHash != AgentAccountCodeHash || account.TVMVersion < MinimumAgentAccountTVMVersion || account.Address != parsed.SenderAgentAccount || account.GlobalID != input.ExpectedGlobalID || parsed.GlobalID != input.ExpectedGlobalID || parsed.Seqno != input.ExpectedSeqno || account.Seqno != input.ExpectedSeqno || parsed.ValidUntil != input.ExpectedValidUntil || parsed.ValidUntil <= input.FinalizedChainTime || account.DefaultTaskTimeoutSecs == 0 || uint64(parsed.ValidUntil-input.FinalizedChainTime) > account.DefaultTaskTimeoutSecs || len(account.ControllerPublicKey) != ed25519.PublicKeySize {
		return zero, errors.New("cancellation conflicts with finalized Agent Account authority")
	}
	bindingHash, err := controllerBindingHash(account.Address, parsed.GlobalID, parsed.PayloadHash)
	if err != nil || !ed25519.Verify(account.ControllerPublicKey, bindingHash, parsed.Signature[:]) {
		return zero, errors.New("invalid Agent Account cancellation signature")
	}
	return parsed, nil
}

func ParseAgentNativeSendBOC(boc []byte) (ParsedNativeSend, error) {
	var out ParsedNativeSend
	if len(boc) == 0 || len(boc) > MaxSignedBOCBytes {
		return out, errors.New("signed Agent Account BOC has invalid size")
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		return out, fmt.Errorf("decode signed Agent Account BOC: %w", err)
	}
	if !bytes.Equal(boc, root.ToBOCWithFlags(false)) {
		return out, errors.New("signed Agent Account BOC is not in the frozen canonical serialization")
	}
	loader, err := root.BeginParse()
	if err != nil {
		return out, err
	}
	var message tlb.Message
	if err := tlb.LoadFromCell(&message, loader); err != nil {
		return out, fmt.Errorf("decode external message: %w", err)
	}
	if loader.BitsLeft() != 0 || loader.RefsNum() != 0 {
		return out, errors.New("external message has trailing data")
	}
	if message.MsgType != tlb.MsgTypeExternalIn {
		return out, errors.New("Gift BOC root is not one external inbound message")
	}
	external, ok := message.Msg.(*tlb.ExternalMessage)
	if !ok || external == nil || external.SrcAddr == nil || !external.SrcAddr.IsAddrNone() || external.DstAddr == nil || external.DstAddr.Type() != address.StdAddress || external.DstAddr.BitsLen() != 256 || external.ImportFee.Nano().Sign() != 0 || external.StateInit != nil || external.Body == nil {
		return out, errors.New("external message does not match the frozen Agent Account constructor")
	}
	body, err := external.Body.BeginParse()
	if err != nil {
		return out, err
	}
	signature, err := body.LoadSlice(512)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return out, errors.New("missing controller signature")
	}
	payload := body.Copy()
	payloadCell, err := payload.ToCell()
	if err != nil {
		return out, errors.New("invalid native-send payload cell")
	}
	copy(out.Signature[:], signature)
	copy(out.PayloadHash[:], payloadCell.Hash())
	op, err := body.LoadUInt(32)
	if err != nil || op != AgentNativeSendOpcode {
		return out, errors.New("Gift BOC is not agent_native_send")
	}
	globalID, err := body.LoadInt(32)
	if err != nil {
		return out, errors.New("invalid signed global ID")
	}
	seqno, err := body.LoadUInt(32)
	if err != nil {
		return out, errors.New("invalid signed seqno")
	}
	validUntil, err := body.LoadUInt(32)
	if err != nil {
		return out, errors.New("invalid signed validity")
	}
	destination, err := body.LoadAddr()
	if err != nil || destination == nil || destination.Type() != address.StdAddress || destination.BitsLen() != 256 {
		return out, errors.New("invalid native-send destination")
	}
	amount, err := body.LoadCoins()
	if err != nil || amount == 0 {
		return out, errors.New("invalid native-send amount")
	}
	if body.BitsLeft() != 0 || body.RefsNum() != 0 {
		return out, errors.New("native-send payload contains hidden or trailing data")
	}
	out.ExactBOCDigest = ExactSignedBOCDigest(boc)
	out.SignedGiftID = SignedGiftID(boc)
	out.SenderAgentAccount = external.DstAddr.StringRaw()
	out.GlobalID = int32(globalID)
	out.Seqno = uint32(seqno)
	out.ValidUntil = uint32(validUntil)
	out.DestinationAddress = destination.StringRaw()
	out.AmountAtomic = amount
	return out, nil
}

func VerifyAgentNativeSend(input VerifyNativeSendInput) (ParsedNativeSend, error) {
	var zero ParsedNativeSend
	if err := input.Request.Validate(); err != nil {
		return zero, err
	}
	if err := BindResponse(input.Request, input.Response); err != nil {
		return zero, err
	}
	parsed, err := ParseAgentNativeSendBOC(input.ExactSignedBOC)
	if err != nil {
		return zero, err
	}
	if input.ExpectedSignedGiftID == "" || parsed.SignedGiftID != input.ExpectedSignedGiftID {
		return zero, errors.New("SignedGiftID mismatch")
	}
	account := input.Account
	if !account.Active || account.CodeHash != AgentAccountCodeHash || account.TVMVersion < MinimumAgentAccountTVMVersion || account.Address != input.Request.SenderAgentAccount || parsed.SenderAgentAccount != account.Address || account.GlobalID != input.Request.GlobalID || parsed.GlobalID != account.GlobalID || account.DefaultTaskTimeoutSecs == 0 {
		return zero, errors.New("finalized Agent Account identity or network mismatch")
	}
	if len(account.ControllerPublicKey) != ed25519.PublicKeySize || parsed.Seqno != account.Seqno {
		return zero, errors.New("controller or finalized seqno mismatch")
	}
	if parsed.ValidUntil > input.Request.RequestedValidUntil || parsed.ValidUntil > input.Response.ResponseNotAfter || parsed.ValidUntil <= input.FinalizedChainTime || parsed.ValidUntil-input.FinalizedChainTime < input.MinimumInclusionMargin {
		return zero, errors.New("signed validity is outside the authorized finalized-time bounds")
	}
	if account.DefaultTaskTimeoutSecs < uint64(parsed.ValidUntil-input.FinalizedChainTime) {
		return zero, errors.New("signed validity exceeds the Agent Account on-chain timeout")
	}
	wantAmount, _ := ParseAmount(input.Request.AmountAtomic)
	if parsed.AmountAtomic != wantAmount || parsed.DestinationAddress != input.Response.DestinationAddress {
		return zero, errors.New("native send destination or amount substitution")
	}
	if parsed.AmountAtomic > account.MaxPerTxAtomic || parsed.AmountAtomic > account.DailyRemainingAtomic {
		return zero, errors.New("native send exceeds finalized Agent Account policy")
	}
	if input.FeeReserveAtomic > math.MaxUint64-parsed.AmountAtomic || account.BalanceAtomic < parsed.AmountAtomic+input.FeeReserveAtomic {
		return zero, errors.New("insufficient finalized balance plus fee reserve")
	}
	bindingHash, err := controllerBindingHash(account.Address, parsed.GlobalID, parsed.PayloadHash)
	if err != nil {
		return zero, err
	}
	if !ed25519.Verify(account.ControllerPublicKey, bindingHash, parsed.Signature[:]) {
		return zero, errors.New("invalid Agent Account controller signature")
	}
	return parsed, nil
}

func controllerBindingHash(accountRaw string, globalID int32, payloadHash [32]byte) ([]byte, error) {
	account, err := address.ParseRawAddr(accountRaw)
	if err != nil || account.Type() != address.StdAddress || account.BitsLen() != 256 {
		return nil, errors.New("invalid Agent Account address for signature binding")
	}
	domain, err := hex.DecodeString(AgentControllerSignatureDomainHex)
	if err != nil {
		return nil, err
	}
	builder := cell.BeginCell().MustStoreSlice(domain, 256).MustStoreInt(int64(globalID), 32).MustStoreInt(int64(account.Workchain()), 8).MustStoreSlice(account.Data(), 256).MustStoreSlice(payloadHash[:], 256)
	return builder.EndCell().Hash(), nil
}
