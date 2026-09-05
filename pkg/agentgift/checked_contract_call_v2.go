package agentgift

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	AgentCheckedContractCallV2Opcode = uint64(0x41475007)
	AgentCheckedContractCallV2Flags  = uint64(3)
)

type ParsedCheckedContractCallV2 struct {
	ExactBOCDigest     string
	SenderAgentAccount string
	GlobalID           int32
	ControllerEpoch    uint64
	Seqno              uint32
	ValidUntil         uint32
	DestinationAddress string
	AmountAtomic       uint64
	Flags              uint8
	BodyBOC            []byte
	BodyHash           string
	Signature          [ed25519.SignatureSize]byte
	PayloadHash        [32]byte
}

type ExpectedCheckedContractCallV2 struct {
	SenderAgentAccount string
	GlobalID           int32
	ControllerEpoch    uint64
	Seqno              uint32
	ValidUntil         uint32
	DestinationAddress string
	AmountAtomic       uint64
	BodyBOC            []byte
}

// ParseAgentCheckedContractCallV2BOC unwraps the complete external inbound
// message and rejects hidden StateInit, trailing bits/refs, non-standard
// addresses, the wrong mode, and a non-canonical body. Signature authority is
// deliberately verified separately against finalized Agent Account state.
func ParseAgentCheckedContractCallV2BOC(boc []byte) (ParsedCheckedContractCallV2, error) {
	var out ParsedCheckedContractCallV2
	if len(boc) == 0 || len(boc) > MaxSignedBOCBytes {
		return out, errors.New("signed Agent Account checked-contract-call v2 BOC has invalid size")
	}
	root, err := cell.FromBOC(boc)
	if err != nil || root == nil || !bytes.Equal(boc, root.ToBOCWithFlags(false)) {
		return out, errors.New("signed Agent Account checked-contract-call v2 BOC is not canonical")
	}
	loader, err := root.BeginParse()
	if err != nil {
		return out, err
	}
	var message tlb.Message
	if tlb.LoadFromCell(&message, loader) != nil || loader.BitsLeft() != 0 || loader.RefsNum() != 0 ||
		message.MsgType != tlb.MsgTypeExternalIn {
		return out, errors.New("Agent Account checked-call v2 BOC root is not one external inbound message")
	}
	external, ok := message.Msg.(*tlb.ExternalMessage)
	if !ok || external == nil || external.SrcAddr == nil || !external.SrcAddr.IsAddrNone() ||
		external.DstAddr == nil || external.DstAddr.Type() != address.StdAddress || external.DstAddr.BitsLen() != 256 ||
		external.ImportFee.Nano().Sign() != 0 || external.StateInit != nil || external.Body == nil {
		return out, errors.New("external message does not match the Agent Account checked-call v2 profile")
	}
	body, err := external.Body.BeginParse()
	if err != nil {
		return out, err
	}
	signature, err := body.LoadSlice(512)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return out, errors.New("missing Agent Account checked-call v2 controller signature")
	}
	payload := body.Copy()
	payloadCell, err := payload.ToCell()
	if err != nil {
		return out, errors.New("invalid Agent Account checked-call v2 payload cell")
	}
	copy(out.Signature[:], signature)
	copy(out.PayloadHash[:], payloadCell.Hash())
	opcode, err := body.LoadUInt(32)
	if err != nil || opcode != AgentCheckedContractCallV2Opcode {
		return out, errors.New("BOC is not agent_checked_contract_call_v2")
	}
	globalID, err := body.LoadInt(32)
	if err != nil {
		return out, errors.New("invalid Agent Account checked-call v2 global ID")
	}
	controllerEpoch, err := body.LoadUInt(64)
	if err != nil {
		return out, errors.New("invalid Agent Account checked-call v2 controller epoch")
	}
	seqno, err := body.LoadUInt(32)
	if err != nil {
		return out, errors.New("invalid Agent Account checked-call v2 seqno")
	}
	validUntil, err := body.LoadUInt(32)
	if err != nil {
		return out, errors.New("invalid Agent Account checked-call v2 validity")
	}
	destination, err := body.LoadAddr()
	if err != nil || destination == nil || destination.Type() != address.StdAddress || destination.BitsLen() != 256 ||
		destination.StringRaw() == external.DstAddr.StringRaw() {
		return out, errors.New("invalid Agent Account checked-call v2 destination")
	}
	amount, err := body.LoadCoins()
	if err != nil || amount == 0 {
		return out, errors.New("invalid Agent Account checked-call v2 amount")
	}
	flags, err := body.LoadUInt(8)
	if err != nil || flags != AgentCheckedContractCallV2Flags || body.BitsLeft() != 0 || body.RefsNum() != 1 {
		return out, errors.New("Agent Account checked-contract-call v2 action has invalid flags or trailing material")
	}
	callBody, err := body.LoadRefCell()
	if err != nil || callBody == nil || body.BitsLeft() != 0 || body.RefsNum() != 0 {
		return out, errors.New("Agent Account checked-contract-call v2 body is missing or ambiguous")
	}
	callBodySlice, err := callBody.BeginParse()
	if err != nil || callBodySlice.BitsLeft() == 0 && callBodySlice.RefsNum() == 0 {
		return out, errors.New("Agent Account checked-contract-call v2 body is empty")
	}
	bodyBOC := callBody.ToBOCWithFlags(false)
	if decoded, decodeErr := cell.FromBOC(bodyBOC); decodeErr != nil || decoded == nil ||
		!bytes.Equal(decoded.Hash(), callBody.Hash()) {
		return out, errors.New("Agent Account checked-contract-call v2 body is noncanonical")
	}
	out.ExactBOCDigest = ExactSignedBOCDigest(boc)
	out.SenderAgentAccount = external.DstAddr.StringRaw()
	out.GlobalID = int32(globalID)
	out.ControllerEpoch = controllerEpoch
	out.Seqno = uint32(seqno)
	out.ValidUntil = uint32(validUntil)
	out.DestinationAddress = destination.StringRaw()
	out.AmountAtomic = amount
	out.Flags = uint8(flags)
	out.BodyBOC = bodyBOC
	out.BodyHash = "tvm-cell-sha256:" + hex.EncodeToString(callBody.Hash())
	return out, nil
}

func VerifyPreparedAgentCheckedContractCallV2(boc []byte,
	expected ExpectedCheckedContractCallV2,
) (ParsedCheckedContractCallV2, error) {
	var zero ParsedCheckedContractCallV2
	parsed, err := ParseAgentCheckedContractCallV2BOC(boc)
	if err != nil {
		return zero, err
	}
	if parsed.SenderAgentAccount != expected.SenderAgentAccount || parsed.GlobalID != expected.GlobalID ||
		parsed.ControllerEpoch != expected.ControllerEpoch || parsed.Seqno != expected.Seqno ||
		parsed.ValidUntil != expected.ValidUntil || parsed.DestinationAddress != expected.DestinationAddress ||
		parsed.AmountAtomic != expected.AmountAtomic || !bytes.Equal(parsed.BodyBOC, expected.BodyBOC) {
		return zero, errors.New("prepared Agent Account checked-contract-call v2 action differs from the exact expected effect")
	}
	return parsed, nil
}
