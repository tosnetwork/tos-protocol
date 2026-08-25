package paiddemand

import (
	"encoding/hex"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const SettlementAdapterURI = "tos.escrow.paid-demand.v1"

type QuoteBuildInput struct {
	Agreement                    commerce.AgentAgreementBody
	ProviderOffer                commerce.SignedProviderOffer
	ProviderOfferResolver        commerce.ProviderOfferKeyResolver
	Network                      *nativev1.NetworkDomain
	Proposal                     *nativev1.QuoteProposalV1
	ExecutionSignerAuthorization string
	EscrowTerms                  nativecore.EscrowTermsV1
	ExecutionDeadlineUnix        uint64
	Now                          time.Time
}

// BuildAcceptedQuote performs every generic/native equality check before
// constructing the schema-2 Quote. No application journal field enters Quote
// identity and no Quote digest is fed back into its own binding.
func BuildAcceptedQuote(input QuoteBuildInput) (*cell.Cell, string, error) {
	if err := validateBuildInput(input); err != nil {
		return nil, "", err
	}
	_, nativeProjection, err := nativecore.BuildAcceptedQuoteCommitment(input.Network, input.Proposal,
		input.ExecutionSignerAuthorization)
	if err != nil || input.ProviderOffer.Binding.NativeQuoteTermsProjectionDigest != nativeProjection {
		return nil, "", errors.New("Paid Demand binding does not commit the exact native Quote terms projection")
	}
	bindingDigest, err := commerce.PaidDemandQuoteBindingDigest(input.ProviderOffer.Binding)
	if err != nil {
		return nil, "", err
	}
	offerDigest, err := commerce.ProviderOfferDigest(input.ProviderOffer)
	if err != nil {
		return nil, "", err
	}
	canonicalOffer, err := codec.Marshal(input.ProviderOffer)
	if err != nil {
		return nil, "", err
	}
	extension := nativecore.PaidDemandQuoteExtensionV1{ProviderOfferCanonical: canonicalOffer,
		ProviderOfferBindingDigest: bindingDigest, ProviderOfferDigest: offerDigest,
		AcceptByUnix: input.ProviderOffer.Binding.AcceptByUnix, ExecutionDeadline: input.ExecutionDeadlineUnix}
	quote, commitment, projection, err := nativecore.BuildAcceptedQuoteCommitmentV2(input.Network, input.Proposal,
		input.ExecutionSignerAuthorization, extension)
	if err != nil || projection != nativeProjection {
		return nil, "", errors.New("native Accepted Quote V2 construction changed its committed projection")
	}
	return quote, commitment, nil
}

func VerifyAcceptedQuote(root *cell.Cell, agreement commerce.AgentAgreementBody, network *nativev1.NetworkDomain,
	escrowTerms nativecore.EscrowTermsV1, resolver commerce.ProviderOfferKeyResolver, now time.Time) (*nativecore.AcceptedQuoteTermsV2, commerce.SignedProviderOffer, error) {
	decoded, err := nativecore.DecodeAcceptedQuoteV2(root, network)
	if err != nil {
		return nil, commerce.SignedProviderOffer{}, err
	}
	var offer commerce.SignedProviderOffer
	if err := codec.Unmarshal(decoded.Extension.ProviderOfferCanonical, &offer); err != nil ||
		commerce.VerifyProviderOffer(offer, resolver, now) != nil || commerce.ValidatePaidDemandAgreementBinding(agreement, offer.Binding) != nil {
		return nil, commerce.SignedProviderOffer{}, errors.New("Accepted Quote carries an invalid Provider Offer")
	}
	bindingDigest, _ := commerce.PaidDemandQuoteBindingDigest(offer.Binding)
	offerDigest, _ := commerce.ProviderOfferDigest(offer)
	if bindingDigest != decoded.Extension.ProviderOfferBindingDigest || offerDigest != decoded.Extension.ProviderOfferDigest ||
		offer.Binding.NativeQuoteTermsProjectionDigest != decoded.NativeTermsProjection || offer.Binding.AcceptByUnix != decoded.Extension.AcceptByUnix {
		return nil, commerce.SignedProviderOffer{}, errors.New("Accepted Quote extension commitment mismatch")
	}
	input := QuoteBuildInput{Agreement: agreement, ProviderOffer: offer, ProviderOfferResolver: resolver,
		Network: network, Proposal: decoded.Terms.Proposal, ExecutionSignerAuthorization: decoded.Terms.ExecutionSignerAuthorization,
		EscrowTerms: escrowTerms, ExecutionDeadlineUnix: decoded.Extension.ExecutionDeadline, Now: now}
	if err := validateBuildInput(input); err != nil {
		return nil, commerce.SignedProviderOffer{}, err
	}
	return decoded, offer, nil
}

func validateBuildInput(input QuoteBuildInput) error {
	if input.Network == nil || input.Proposal == nil || input.Now.IsZero() || input.ExecutionDeadlineUnix == 0 ||
		commerce.ValidatePaidDemandAgreementBinding(input.Agreement, input.ProviderOffer.Binding) != nil ||
		commerce.VerifyProviderOffer(input.ProviderOffer, input.ProviderOfferResolver, input.Now) != nil {
		return errors.New("Paid Demand Quote build input is invalid")
	}
	binding := input.ProviderOffer.Binding
	if input.Agreement.NetworkContext != input.Network.NetworkId || input.Proposal.ProviderAgentId != binding.ProviderAgentID ||
		input.Proposal.ExpiresAtUnixSeconds != binding.AcceptByUnix || input.ExecutionDeadlineUnix <= binding.AcceptByUnix ||
		input.ExecutionDeadlineUnix >= input.EscrowTerms.RefundAvailableAt || input.EscrowTerms.BuyerAddress != binding.BuyerWallet ||
		input.EscrowTerms.ProviderAddress != binding.ProviderWallet {
		return errors.New("Paid Demand participants or deadlines differ from native terms")
	}
	terms, err := nativecore.BuildEscrowTermsCellV1(input.EscrowTerms)
	if err != nil || input.Proposal.EscrowTermsDigest != "sha256:"+hex.EncodeToString(terms.Hash()) {
		return errors.New("Paid Demand escrow terms differ from native Quote")
	}
	if input.Proposal.MaximumPrice == nil || input.Proposal.MaximumPrice.Asset == nil || input.Proposal.MaximumPrice.Asset.Master == nil ||
		len(input.Proposal.MaximumPrice.Asset.Master.AccountId) != 32 {
		return errors.New("Paid Demand native asset is incomplete")
	}
	assetID := "0:" + hex.EncodeToString(input.Proposal.MaximumPrice.Asset.Master.AccountId)
	paymentFound, workFound := false, false
	bound := make(map[string]bool, len(binding.AgreementObligationIDs))
	for _, id := range binding.AgreementObligationIDs {
		bound[id] = true
	}
	for _, obligation := range input.Agreement.Obligations {
		if !bound[obligation.ObligationID] {
			continue
		}
		if obligation.Amount != nil {
			paymentFound = paymentFound || obligation.ObligorAgentID == binding.BuyerAgentID &&
				obligation.BeneficiaryAgentID == binding.ProviderAgentID && obligation.SettlementAdapterURI == SettlementAdapterURI &&
				obligation.Amount.AssetNamespace == "tos.contract" && obligation.Amount.AssetIdentifier == assetID &&
				obligation.Amount.Unit == "atomic" && obligation.Amount.AmountAtomic == input.Proposal.MaximumPrice.AtomicAmount
		} else {
			workFound = workFound || obligation.ObligorAgentID == binding.ProviderAgentID &&
				obligation.BeneficiaryAgentID == binding.BuyerAgentID
		}
	}
	if !paymentFound || !workFound {
		return errors.New("Paid Demand Agreement does not exactly project native payment and work")
	}
	return nil
}
