package paiddemand

import (
	"errors"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

// BuyerAcceptEvidenceVerifier is the chain-specific boundary used by the
// generic Agreement verifier. Implementations must authenticate finalized
// escrow code, Quote bytes, buyer sender, accepted state and rollback-resistant
// checkpoint evidence; a gateway assertion is insufficient.
type BuyerAcceptEvidenceVerifier interface {
	VerifyFinalizedBuyerAccept(commerce.PaidDemandQuoteBindingBody, []byte, uint64, string, time.Time) error
}

// NativeEvidenceVerifier verifies both halves of the Paid Demand Agreement
// profile without treating an off-chain market or Messenger database as
// authoritative.
type NativeEvidenceVerifier struct {
	ProviderOffers commerce.ProviderOfferKeyResolver
	BuyerAccepts   BuyerAcceptEvidenceVerifier
}

func (verifier NativeEvidenceVerifier) VerifyPaidDemandNativeEvidence(binding commerce.PaidDemandQuoteBindingBody,
	kind string, evidence []byte, finalizedAt uint64, finalityReference string, now time.Time) error {
	if commerce.ValidatePaidDemandQuoteBinding(binding) != nil || finalizedAt == 0 || finalizedAt > uint64(now.Add(commerce.MaxIntentClockSkew).Unix()) {
		return errors.New("Paid Demand evidence time or binding is invalid")
	}
	switch kind {
	case "provider_offer":
		if verifier.ProviderOffers == nil {
			return errors.New("Provider Offer authority resolver is unavailable")
		}
		var offer commerce.SignedProviderOffer
		if err := codec.Unmarshal(evidence, &offer); err != nil {
			return errors.New("Provider Offer evidence differs from its Agreement binding")
		}
		wantBinding, err := commerce.PaidDemandQuoteBindingDigest(binding)
		gotBinding, gotErr := commerce.PaidDemandQuoteBindingDigest(offer.Binding)
		if err != nil || gotErr != nil || gotBinding != wantBinding {
			return errors.New("Provider Offer evidence differs from its Agreement binding")
		}
		observed := time.Unix(int64(finalizedAt), 0).UTC()
		if err := commerce.VerifyProviderOffer(offer, verifier.ProviderOffers, observed); err != nil {
			return err
		}
		digest, err := commerce.ProviderOfferDigest(offer)
		if err != nil || digest != finalityReference {
			return errors.New("Provider Offer evidence reference mismatch")
		}
		return nil
	case "buyer_accept":
		if verifier.BuyerAccepts == nil {
			return errors.New("finalized buyer acceptance verifier is unavailable")
		}
		return verifier.BuyerAccepts.VerifyFinalizedBuyerAccept(binding, evidence, finalizedAt, finalityReference, now)
	default:
		return errors.New("unknown Paid Demand evidence kind")
	}
}

var _ commerce.PaidDemandNativeEvidenceVerifier = NativeEvidenceVerifier{}
