package nativecore

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const paidDemandExtensionMagic = 0x4e504431 // NPD1

// PaidDemandQuoteExtensionV1 is the reconstructible typed extension carried by
// Accepted Quote schema 2. ProviderOfferCanonical is the complete canonical
// SignedProviderOffer; the contract commits it while the off-chain profile
// verifier interprets every generic Agreement and proof field.
type PaidDemandQuoteExtensionV1 struct {
	ProviderOfferCanonical     []byte
	ProviderOfferBindingDigest string
	ProviderOfferDigest        string
	AcceptByUnix               uint64
	ExecutionDeadline          uint64
}

type AcceptedQuoteTermsV2 struct {
	NativeTermsProjection string
	Terms                 *AcceptedQuoteTermsV1
	Extension             PaidDemandQuoteExtensionV1
}

// BuildAcceptedQuoteCommitmentV2 preserves the complete schema-1 native terms
// as an acyclic projection and adds one typed Paid Demand extension. The schema
// 1 commitment is not an accepted Quote; it is only the exact native-terms
// projection committed by the generic binding.
func BuildAcceptedQuoteCommitmentV2(network *nativev1.NetworkDomain, proposal *nativev1.QuoteProposalV1,
	executionSignerAuthorization string, extension PaidDemandQuoteExtensionV1) (*cell.Cell, string, string, error) {
	projection, projectionDigest, err := BuildAcceptedQuoteCommitment(network, proposal, executionSignerAuthorization)
	if err != nil {
		return nil, "", "", err
	}
	extensionCell, err := buildPaidDemandExtensionCell(extension)
	if err != nil {
		return nil, "", "", err
	}
	parser, _ := projection.BeginParse()
	_, _ = parser.LoadUInt(32)
	_, _ = parser.LoadUInt(16)
	domain, _ := parser.LoadRefCell()
	identity, _ := parser.LoadRefCell()
	economic, _ := parser.LoadRefCell()
	authorityV1, _ := parser.LoadRefCell()
	authorityParser, err := authorityV1.BeginParse()
	if err != nil {
		return nil, "", "", errors.New("invalid Accepted Quote authority")
	}
	signer, err := authorityParser.LoadSlice(256)
	if err != nil || authorityParser.BitsLeft() != 0 || authorityParser.RefsNum() != 0 {
		return nil, "", "", errors.New("invalid Accepted Quote authority")
	}
	authorityV2 := cell.BeginCell().MustStoreSlice(signer, 256).MustStoreRef(extensionCell).EndCell()
	root := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(2, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(economic).MustStoreRef(authorityV2).EndCell()
	return root, "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), projectionDigest, nil
}

func DecodeAcceptedQuoteV2(root *cell.Cell, network *nativev1.NetworkDomain) (*AcceptedQuoteTermsV2, error) {
	if root == nil {
		return nil, errors.New("missing Accepted Quote")
	}
	parser, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("unsupported Accepted Quote schema")
	}
	magic, err := parser.LoadUInt(32)
	if err != nil || magic != acceptedQuoteMagic {
		return nil, errors.New("unsupported Accepted Quote schema")
	}
	schema, err := parser.LoadUInt(16)
	if err != nil || schema != 2 {
		return nil, errors.New("unsupported Accepted Quote schema")
	}
	domain, err := parser.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote domain")
	}
	identity, err := parser.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote identity")
	}
	economic, err := parser.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing Quote economics")
	}
	authorityV2, err := parser.LoadRefCell()
	if err != nil || parser.BitsLeft() != 0 || parser.RefsNum() != 0 {
		return nil, errors.New("invalid Quote shape")
	}
	authorityParser, err := authorityV2.BeginParse()
	if err != nil {
		return nil, errors.New("invalid Quote authority")
	}
	signer, err := authorityParser.LoadSlice(256)
	if err != nil {
		return nil, errors.New("invalid Quote signer")
	}
	extensionCell, err := authorityParser.LoadRefCell()
	if err != nil || authorityParser.BitsLeft() != 0 || authorityParser.RefsNum() != 0 {
		return nil, errors.New("invalid Quote extension authority")
	}
	authorityV1 := cell.BeginCell().MustStoreSlice(signer, 256).EndCell()
	projection := cell.BeginCell().MustStoreUInt(acceptedQuoteMagic, 32).MustStoreUInt(1, 16).
		MustStoreRef(domain).MustStoreRef(identity).MustStoreRef(economic).MustStoreRef(authorityV1).EndCell()
	terms, err := DecodeAcceptedQuoteV1(projection, network)
	if err != nil {
		return nil, err
	}
	extension, err := decodePaidDemandExtensionCell(extensionCell)
	if err != nil {
		return nil, err
	}
	rebuilt, _, projectionDigest, err := BuildAcceptedQuoteCommitmentV2(network, terms.Proposal,
		terms.ExecutionSignerAuthorization, extension)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("Accepted Quote schema 2 is not canonical")
	}
	return &AcceptedQuoteTermsV2{NativeTermsProjection: projectionDigest, Terms: terms, Extension: extension}, nil
}

func buildPaidDemandExtensionCell(value PaidDemandQuoteExtensionV1) (*cell.Cell, error) {
	bindingDigest, err := digestBytes(value.ProviderOfferBindingDigest, "sha256:", false)
	if err != nil || len(value.ProviderOfferCanonical) == 0 || len(value.ProviderOfferCanonical) > 64<<10 {
		return nil, errors.New("invalid Paid Demand binding")
	}
	offerDigest, err := digestBytes(value.ProviderOfferDigest, "sha256:", false)
	if err != nil || value.AcceptByUnix == 0 || value.ExecutionDeadline <= value.AcceptByUnix {
		return nil, errors.New("invalid Paid Demand Offer or deadlines")
	}
	bytesCell, err := buildSnakeBytes(value.ProviderOfferCanonical)
	if err != nil {
		return nil, err
	}
	return cell.BeginCell().MustStoreUInt(paidDemandExtensionMagic, 32).MustStoreUInt(1, 16).
		MustStoreSlice(bindingDigest, 256).MustStoreSlice(offerDigest, 256).
		MustStoreUInt(value.AcceptByUnix, 64).MustStoreUInt(value.ExecutionDeadline, 64).
		MustStoreUInt(uint64(len(value.ProviderOfferCanonical)), 32).MustStoreRef(bytesCell).EndCell(), nil
}

func decodePaidDemandExtensionCell(root *cell.Cell) (PaidDemandQuoteExtensionV1, error) {
	if root == nil {
		return PaidDemandQuoteExtensionV1{}, errors.New("missing Paid Demand extension")
	}
	parser, err := root.BeginParse()
	if err != nil {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand extension")
	}
	magic, err := parser.LoadUInt(32)
	if err != nil || magic != paidDemandExtensionMagic {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand extension")
	}
	schema, err := parser.LoadUInt(16)
	if err != nil || schema != 1 {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand extension")
	}
	binding, err := parser.LoadSlice(256)
	if err != nil {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand binding digest")
	}
	offer, err := parser.LoadSlice(256)
	if err != nil {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand Offer digest")
	}
	acceptBy, err := parser.LoadUInt(64)
	if err != nil {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand acceptance deadline")
	}
	executionDeadline, err := parser.LoadUInt(64)
	if err != nil || acceptBy == 0 || executionDeadline <= acceptBy {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand execution deadline")
	}
	size, err := parser.LoadUInt(32)
	if err != nil || size == 0 || size > 64<<10 {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand binding size")
	}
	bytesCell, err := parser.LoadRefCell()
	if err != nil || parser.BitsLeft() != 0 || parser.RefsNum() != 0 {
		return PaidDemandQuoteExtensionV1{}, errors.New("invalid Paid Demand extension shape")
	}
	canonical, err := decodeSnakeBytes(bytesCell, int(size))
	if err != nil {
		return PaidDemandQuoteExtensionV1{}, err
	}
	return PaidDemandQuoteExtensionV1{ProviderOfferCanonical: canonical, ProviderOfferBindingDigest: "sha256:" + hex.EncodeToString(binding),
		ProviderOfferDigest: "sha256:" + hex.EncodeToString(offer), AcceptByUnix: acceptBy, ExecutionDeadline: executionDeadline}, nil
}

func buildSnakeBytes(value []byte) (*cell.Cell, error) {
	if len(value) == 0 {
		return nil, errors.New("empty snake bytes")
	}
	var next *cell.Cell
	for end := len(value); end > 0; {
		start := end - 120
		if start < 0 {
			start = 0
		}
		builder := cell.BeginCell().MustStoreSlice(value[start:end], uint(len(value[start:end])*8))
		if next != nil {
			builder.MustStoreRef(next)
		}
		next = builder.EndCell()
		end = start
	}
	return next, nil
}

func decodeSnakeBytes(root *cell.Cell, size int) ([]byte, error) {
	result := make([]byte, 0, size)
	current := root
	for current != nil {
		parser, err := current.BeginParse()
		if err != nil || parser.BitsLeft()%8 != 0 || parser.RefsNum() > 1 {
			return nil, errors.New("invalid Paid Demand binding byte chain")
		}
		part, err := parser.LoadSlice(uint(parser.BitsLeft()))
		if err != nil {
			return nil, err
		}
		result = append(result, part...)
		if parser.RefsNum() == 0 {
			current = nil
		} else {
			current, err = parser.LoadRefCell()
			if err != nil {
				return nil, err
			}
		}
	}
	if len(result) != size {
		return nil, errors.New("Paid Demand binding byte length mismatch")
	}
	return result, nil
}

func EncodePaidDemandExtensionBOC(value PaidDemandQuoteExtensionV1) (string, error) {
	root, err := buildPaidDemandExtensionCell(value)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(root.ToBOC()), nil
}
