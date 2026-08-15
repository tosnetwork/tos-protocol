package nativecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type AcceptedQuoteTermsV1 struct {
	Network                      *nativev1.NetworkDomain
	Proposal                     *nativev1.QuoteProposalV1
	ExecutionSignerAuthorization string
}

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
		!validProtocolText(proposal.CapabilityVersion, 128) ||
		len(proposal.MaximumPrice.AtomicAmount) > 128 || !atomicAmountPattern.MatchString(proposal.MaximumPrice.AtomicAmount) {
		return nil, "", errors.New("invalid Native Quote Proposal")
	}
	asset, err := quoteAssetCell(proposal.MaximumPrice.Asset)
	if err != nil {
		return nil, "", err
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
		MustStoreRef(asset).MustStoreRef(stringCell(proposal.MaximumPrice.AtomicAmount)).EndCell()
	authority := cell.BeginCell().MustStoreSlice(signer, 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(1, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(economic).MustStoreRef(authority).EndCell()
	return root, "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), nil
}

// DecodeAcceptedQuoteV1 returns every committed commercial field and proves
// that re-encoding it produces the exact supplied TVM cell.
func DecodeAcceptedQuoteV1(root *cell.Cell, network *nativev1.NetworkDomain) (*AcceptedQuoteTermsV1, error) {
	if root == nil {
		return nil, errors.New("missing Accepted Quote")
	}
	expectedDomain, err := domainCell(network)
	if err != nil {
		return nil, err
	}
	s := root.BeginParse()
	magic, err := s.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, errors.New("invalid Accepted Quote magic")
	}
	schema, err := s.LoadUInt(16)
	if err != nil || schema != 1 {
		return nil, errors.New("unsupported Accepted Quote schema")
	}
	domain, err := s.LoadRefCell()
	if err != nil || !bytes.Equal(domain.Hash(), expectedDomain.Hash()) {
		return nil, errors.New("Accepted Quote network mismatch")
	}
	identity, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote identity")
	}
	economic, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote economics")
	}
	authority, err := s.LoadRefCell()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, errors.New("invalid Accepted Quote shape")
	}

	i := identity.BeginParse()
	capability, err := i.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote Capability")
	}
	provider, err := i.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote provider")
	}
	versionCell, err := i.LoadRefCell()
	if err != nil || i.BitsLeft() != 0 || i.RefsNum() != 0 {
		return nil, errors.New("invalid Quote identity shape")
	}
	v := versionCell.BeginParse()
	versionHash, err := v.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote version hash")
	}
	manifest, err := v.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote manifest")
	}
	transport, err := v.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote transport")
	}
	expires, err := v.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid Quote expiry")
	}
	versionTextCell, err := v.LoadRefCell()
	if err != nil || v.BitsLeft() != 0 || v.RefsNum() != 0 {
		return nil, errors.New("invalid Quote version shape")
	}
	versionText, err := decodeProtocolText(versionTextCell, 128)
	computedVersion := sha256.Sum256([]byte(versionText))
	if err != nil || !bytes.Equal(versionHash, computedVersion[:]) {
		return nil, errors.New("invalid Quote version text")
	}

	e := economic.BeginParse()
	escrowTerms, err := e.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote escrow terms")
	}
	dispute, err := e.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote dispute policy")
	}
	assetCell, err := e.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote asset")
	}
	amountCell, err := e.LoadRefCell()
	if err != nil || e.BitsLeft() != 0 || e.RefsNum() != 0 {
		return nil, errors.New("invalid Quote economics shape")
	}
	as := assetCell.BeginParse()
	wc, err := as.LoadInt(32)
	if err != nil {
		return nil, errors.New("invalid Quote asset workchain")
	}
	account, err := as.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote asset account")
	}
	masterCode, err := as.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote asset code")
	}
	walletCode, err := as.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote wallet code")
	}
	decimals, err := as.LoadUInt(8)
	if err != nil || as.BitsLeft() != 0 || as.RefsNum() != 0 {
		return nil, errors.New("invalid Quote asset shape")
	}
	amount, err := decodeProtocolText(amountCell, 128)
	if err != nil {
		return nil, errors.New("invalid Quote amount")
	}
	a := authority.BeginParse()
	authorization, err := a.LoadSlice(256)
	if err != nil || a.BitsLeft() != 0 || a.RefsNum() != 0 {
		return nil, errors.New("invalid Quote authority")
	}
	proposal := &nativev1.QuoteProposalV1{CapabilityId: "cap_" + hex.EncodeToString(capability),
		CapabilityVersion: versionText, ProviderAgentId: "agent_" + hex.EncodeToString(provider),
		ManifestDigest: "sha256:" + hex.EncodeToString(manifest), TransportBindingDigest: "sha256:" + hex.EncodeToString(transport),
		MaximumPrice: &nativev1.MoneyV1{Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: int32(wc), AccountId: account, CodeHash: "tvm-cell-sha256:" + hex.EncodeToString(masterCode)},
			WalletCodeHash: "tvm-cell-sha256:" + hex.EncodeToString(walletCode), Decimals: uint32(decimals)}, AtomicAmount: amount},
		EscrowTermsDigest: "sha256:" + hex.EncodeToString(escrowTerms), DisputePolicyDigest: "sha256:" + hex.EncodeToString(dispute),
		ExpiresAtUnixSeconds: expires}
	auth := "sha256:" + hex.EncodeToString(authorization)
	rebuilt, _, err := BuildAcceptedQuoteCommitment(network, proposal, auth)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("Accepted Quote is not canonical")
	}
	return &AcceptedQuoteTermsV1{Network: proto.Clone(network).(*nativev1.NetworkDomain), Proposal: proposal,
		ExecutionSignerAuthorization: auth}, nil
}

func quoteAssetCell(asset *nativev1.TOSAssetIdentityV1) (*cell.Cell, error) {
	if asset == nil || asset.Master == nil || asset.Master.Workchain != 0 || len(asset.Master.AccountId) != 32 ||
		asset.Decimals == 0 || asset.Decimals > 18 {
		return nil, errors.New("invalid TOS-network stablecoin identity")
	}
	allZero := true
	for _, value := range asset.Master.AccountId {
		allZero = allZero && value == 0
	}
	if allZero {
		return nil, errors.New("invalid TOS-network stablecoin account")
	}
	masterCode, err := digestBytes(asset.Master.CodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return nil, errors.New("invalid TOS-network stablecoin master code hash")
	}
	walletCode, err := digestBytes(asset.WalletCodeHash, "tvm-cell-sha256:", false)
	if err != nil {
		return nil, errors.New("invalid TOS-network stablecoin wallet code hash")
	}
	return cell.BeginCell().MustStoreInt(int64(asset.Master.Workchain), 32).
		MustStoreSlice(asset.Master.AccountId, 256).MustStoreSlice(masterCode, 256).
		MustStoreSlice(walletCode, 256).MustStoreUInt(uint64(asset.Decimals), 8).EndCell(), nil
}
