package nativecore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const acceptedQuoteMagic = 0x4e415131 // NAQ1
var atomicAmountPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// BuildAcceptedQuoteCommitment converts a non-canonical gateway proposal into
// the exact terms commitment that may be made canonical by a finalized TOS
// transaction. proposal_id and ChainReference are intentionally excluded.
func BuildAcceptedQuoteCommitment(network *nativev1.NetworkDomain, proposal *nativev1.QuoteProposalV1, executionSignerAuthorization string) (*cell.Cell, string, error) {
	domain, err := domainCell(network)
	if err != nil {
		return nil, "", err
	}
	if proposal == nil || proposal.MaximumPrice == nil || proposal.ExpiresAtUnixSeconds == 0 ||
		!validProtocolText(proposal.CapabilityVersion, 128) || !validProtocolText(proposal.MaximumPrice.Asset, 32) ||
		len(proposal.MaximumPrice.AtomicAmount) > 128 || !atomicAmountPattern.MatchString(proposal.MaximumPrice.AtomicAmount) {
		return nil, "", errors.New("invalid Native Quote Proposal")
	}
	capability, kind, err := objectID(proposal.CapabilityId)
	if err != nil || kind != 2 {
		return nil, "", errors.New("invalid Native Quote Capability")
	}
	provider, kind, err := objectID(proposal.ProviderAgentId)
	if err != nil || kind != 1 {
		return nil, "", errors.New("invalid Native Quote provider")
	}
	manifest, err := digestBytes(proposal.ManifestDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	transport, err := digestBytes(proposal.TransportBindingDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	escrow, err := digestBytes(proposal.EscrowTermsDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	dispute, err := digestBytes(proposal.DisputePolicyDigest, "sha256:", false)
	if err != nil {
		return nil, "", err
	}
	signer, err := digestBytes(executionSignerAuthorization, "sha256:", false)
	if err != nil {
		return nil, "", errors.New("invalid execution signer authorization")
	}
	versionHash := sha256.Sum256([]byte(proposal.CapabilityVersion))
	version := cell.BeginCell().MustStoreSlice(versionHash[:], 256).MustStoreSlice(manifest, 256).
		MustStoreSlice(transport, 256).MustStoreUInt(proposal.ExpiresAtUnixSeconds, 64).
		MustStoreRef(stringCell(proposal.CapabilityVersion)).EndCell()
	identity := cell.BeginCell().MustStoreSlice(capability, 256).MustStoreSlice(provider, 256).MustStoreRef(version).EndCell()
	economic := cell.BeginCell().MustStoreSlice(escrow, 256).MustStoreSlice(dispute, 256).
		MustStoreRef(stringCell(proposal.MaximumPrice.Asset)).MustStoreRef(stringCell(proposal.MaximumPrice.AtomicAmount)).EndCell()
	authority := cell.BeginCell().MustStoreSlice(signer, 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(1, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(economic).MustStoreRef(authority).EndCell()
	return root, "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), nil
}
