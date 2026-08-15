// Package quoteexchange validates portable, complete-preimage Quote Proposal
// packages. A valid package is still non-canonical; only finalized TOS escrow
// state can establish an Accepted Quote.
package quoteexchange

import (
	"bytes"
	"errors"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const MaxPackageBytes = 2 << 20

type Validated struct {
	Proposal         *nativev1.QuoteProposalV1
	Manifest         nativecore.SoftwareWorkManifestV1
	EscrowTerms      nativecore.EscrowTermsV1
	TransportBinding nativecore.TransportBindingV1
}

// Validate proves that every digest in the proposal has the exact preimage
// carried in the package and that the request identity is unchanged.
func Validate(network *nativev1.NetworkDomain, request *nativev1.RequestQuoteProposalRequest,
	value *nativev1.QuoteProposalPackageV1, now time.Time) (*Validated, error) {
	if network == nil || request == nil || value == nil || value.Proposal == nil || now.IsZero() ||
		request.CapabilityId == "" || request.CapabilityVersion == "" || request.BuyerAddress == "" ||
		value.Proposal.CapabilityId != request.CapabilityId || value.Proposal.CapabilityVersion != request.CapabilityVersion ||
		value.Proposal.ProposalId == "" || len(value.Proposal.ProposalId) > 256 ||
		strings.TrimSpace(value.Proposal.ProposalId) != value.Proposal.ProposalId ||
		value.Proposal.ExpiresAtUnixSeconds <= uint64(now.Unix()) ||
		value.Proposal.ExpiresAtUnixSeconds > uint64(now.Add(time.Hour).Unix()) {
		return nil, errors.New("invalid Quote Proposal package identity or expiry")
	}
	total := len(value.CanonicalManifestCbor) + len(value.EscrowTermsBoc) + len(value.TransportBindingBoc) + len(value.DisputePolicyBoc)
	if total <= 0 || total > MaxPackageBytes {
		return nil, errors.New("Quote Proposal package is outside size bounds")
	}
	manifest, err := nativecore.DecodeCanonicalSoftwareWorkManifestCBOR(value.CanonicalManifestCbor)
	if err != nil {
		return nil, errors.New("Quote Proposal carries a non-canonical manifest")
	}
	canonical, manifestDigest, err := nativecore.CanonicalSoftwareWorkManifest(manifest)
	if err != nil || !bytes.Equal(canonical, value.CanonicalManifestCbor) || manifestDigest != value.Proposal.ManifestDigest {
		return nil, errors.New("Quote Proposal manifest preimage mismatch")
	}
	termsCell, err := canonicalCell(value.EscrowTermsBoc)
	if err != nil || "sha256:"+hexHash(termsCell) != value.Proposal.EscrowTermsDigest {
		return nil, errors.New("Quote Proposal escrow terms preimage mismatch")
	}
	terms, err := nativecore.DecodeEscrowTermsCellV1(termsCell)
	if err != nil || terms.BuyerAddress != request.BuyerAddress || terms.FundingDeadline > value.Proposal.ExpiresAtUnixSeconds {
		return nil, errors.New("Quote Proposal escrow terms are invalid for buyer")
	}
	transportCell, err := canonicalCell(value.TransportBindingBoc)
	if err != nil || "sha256:"+hexHash(transportCell) != value.Proposal.TransportBindingDigest {
		return nil, errors.New("Quote Proposal transport preimage mismatch")
	}
	transport, err := nativecore.DecodeTransportBindingCellV1(transportCell)
	if err != nil {
		return nil, errors.New("Quote Proposal transport binding is invalid")
	}
	disputeCell, err := canonicalCell(value.DisputePolicyBoc)
	if err != nil || "sha256:"+hexHash(disputeCell) != value.Proposal.DisputePolicyDigest ||
		nativecore.ValidateObjectiveDisputePolicyCellV1(disputeCell) != nil {
		return nil, errors.New("Quote Proposal dispute policy preimage mismatch")
	}
	// The signer authorization is selected by the buyer later. A fixed non-zero
	// shape-valid digest lets the canonical builder validate every proposal field
	// without pretending that authorization has already been chosen.
	if _, _, err := nativecore.BuildAcceptedQuoteCommitment(network, value.Proposal,
		"sha256:"+strings.Repeat("01", 32)); err != nil {
		return nil, errors.New("Quote Proposal fields are not canonically encodable")
	}
	return &Validated{Proposal: value.Proposal, Manifest: manifest, EscrowTerms: terms, TransportBinding: transport}, nil
}

func canonicalCell(raw []byte) (*cell.Cell, error) {
	if len(raw) == 0 || len(raw) > 64<<10 {
		return nil, errors.New("cell BOC outside bounds")
	}
	roots, err := cell.FromBOCMultiRoot(raw)
	if err != nil || len(roots) != 1 || roots[0] == nil || !bytes.Equal(roots[0].ToBOC(), raw) {
		return nil, errors.New("cell BOC is not canonical single-root encoding")
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
