// Package safehandoff verifies the portable evidence needed to continue a
// purchase after the gateway that supplied its Quote becomes unavailable.
// Gateways are deliberately absent from the verification interface.
package safehandoff

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/quoteexchange"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type Resolver interface {
	ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error)
}

// Bundle contains portable preimages and buyer-held settlement material. It
// intentionally contains no gateway identity, session, or acknowledgement.
type Bundle struct {
	Network                  *nativev1.NetworkDomain
	QuoteRequest             *nativev1.RequestQuoteProposalRequest
	QuotePackage             *nativev1.QuoteProposalPackageV1
	ExecutionSignerPublicKey []byte
	EscrowAddress            string
	ExpectedEscrowCodeHash   string
	ReceiptBOC               []byte
	SettlementQueryID        uint64
	SettlementSignature      []byte
}

type Result struct {
	QuoteCommitment     string `json:"quote_commitment"`
	ReceiptCommitment   string `json:"receipt_commitment"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
	ReadyToBroadcast    bool   `json:"ready_to_broadcast"`
	AlreadyPending      bool   `json:"already_pending"`
}

// Verify reconstructs all commercial commitments and binds them to finalized
// escrow state. A successful funded result may be submitted through any relay;
// a release-pending result proves that the same settlement is already on-chain.
func Verify(ctx context.Context, resolver Resolver, bundle Bundle) (*Result, error) {
	if ctx == nil || resolver == nil || bundle.EscrowAddress == "" || bundle.SettlementQueryID == 0 ||
		!strings.HasPrefix(bundle.ExpectedEscrowCodeHash, "tvm-cell-sha256:") ||
		len(bundle.ExpectedEscrowCodeHash) != len("tvm-cell-sha256:")+64 ||
		len(bundle.ExecutionSignerPublicKey) != ed25519.PublicKeySize || len(bundle.SettlementSignature) != ed25519.SignatureSize {
		return nil, errors.New("incomplete safe-handoff bundle")
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(bundle.ExpectedEscrowCodeHash, "tvm-cell-sha256:")); err != nil {
		return nil, errors.New("invalid expected escrow code hash")
	}
	validated, err := quoteexchange.ValidatePortable(bundle.Network, bundle.QuoteRequest, bundle.QuotePackage)
	if err != nil {
		return nil, err
	}
	authorization, err := nativecore.BuildEscrowAuthorizationCellV1(bundle.ExecutionSignerPublicKey)
	if err != nil {
		return nil, err
	}
	accepted, quoteCommitment, err := nativecore.BuildAcceptedQuoteCommitment(bundle.Network, validated.Proposal,
		"sha256:"+hexHash(authorization))
	if err != nil {
		return nil, err
	}
	receipt, err := canonicalCell(bundle.ReceiptBOC)
	if err != nil {
		return nil, err
	}
	receiptValue, err := nativecore.DecodeSoftwareWorkReceiptCellV1(receipt)
	if err != nil || receiptValue.QuoteCommitment != quoteCommitment ||
		receiptValue.ProviderAgentID != validated.Proposal.ProviderAgentId {
		return nil, errors.New("Receipt does not bind the Accepted Quote and provider")
	}
	charged, ok := new(big.Int).SetString(receiptValue.ChargedAtomicAmount, 10)
	if !ok {
		return nil, errors.New("invalid Receipt charge")
	}
	intent, err := nativecore.BuildEscrowSettlementIntentV1(bundle.EscrowAddress, accepted, receipt, charged, bundle.SettlementQueryID)
	if err != nil || !ed25519.Verify(bundle.ExecutionSignerPublicKey, intent.Hash(), bundle.SettlementSignature) {
		return nil, errors.New("settlement authorization is invalid")
	}
	finalized, found, err := resolver.ResolveFinalized(ctx, bundle.EscrowAddress)
	if err != nil {
		return nil, err
	}
	if !found || finalized == nil || finalized.State == nil || finalized.Reference == nil ||
		finalized.Reference.Account != bundle.EscrowAddress || finalized.Reference.FinalizedCheckpoint == 0 ||
		finalized.Reference.ContractCodeHash != bundle.ExpectedEscrowCodeHash {
		return nil, errors.New("escrow lacks an authoritative finalized observation")
	}
	state := finalized.State
	if state.QuoteCommitment != quoteCommitment || state.AcceptedQuote == nil ||
		!bytes.Equal(state.AcceptedQuote.Hash(), accepted.Hash()) ||
		!bytes.Equal(state.ExecutionSignerEd25519, bundle.ExecutionSignerPublicKey) {
		return nil, errors.New("portable Quote does not match finalized escrow")
	}
	funded, ok := new(big.Int).SetString(state.FundedAtomicAmount, 10)
	if !ok || funded.Cmp(charged) < 0 {
		return nil, errors.New("finalized escrow cannot cover Receipt charge")
	}
	result := &Result{QuoteCommitment: quoteCommitment, ReceiptCommitment: "tvm-cell-sha256:" + hexHash(receipt),
		FinalizedCheckpoint: finalized.Reference.FinalizedCheckpoint}
	switch state.Status {
	case nativecore.EscrowStatusFunded:
		if state.ReceiptCommitment != "" || state.PendingQueryID != 0 || state.SettledAtomicAmount != "0" {
			return nil, errors.New("funded escrow contains settlement residue")
		}
		result.ReadyToBroadcast = true
	case nativecore.EscrowStatusReleasePending:
		if state.ReceiptCommitment != result.ReceiptCommitment || state.PendingQueryID != bundle.SettlementQueryID ||
			state.SettledAtomicAmount != receiptValue.ChargedAtomicAmount {
			return nil, errors.New("pending settlement differs from portable bundle")
		}
		result.AlreadyPending = true
	default:
		return nil, errors.New("escrow is not at a safe release handoff point")
	}
	return result, nil
}

func canonicalCell(raw []byte) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, errors.New("Receipt BOC outside bounds")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil || !bytes.Equal(roots[0].ToBOC(), raw) {
		return nil, errors.New("Receipt BOC is not canonical single-root encoding")
	}
	return roots[0], nil
}

func hexHash(root *cell.Cell) string {
	const digits = "0123456789abcdef"
	raw := root.Hash()
	encoded := make([]byte, len(raw)*2)
	for i, value := range raw {
		encoded[i*2], encoded[i*2+1] = digits[value>>4], digits[value&15]
	}
	return string(encoded)
}
