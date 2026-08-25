package paiddemand

import (
	"context"
	"errors"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
)

type BuyerAcceptNativeEvidenceV1 struct {
	SchemaVersion      uint16 `json:"schema_version"`
	EscrowAddress      string `json:"escrow_address"`
	QuoteCommitment    string `json:"quote_commitment"`
	BuyerWallet        string `json:"buyer_wallet"`
	AcceptedAtUnix     uint64 `json:"accepted_at_unix"`
	ObservedCheckpoint uint64 `json:"observed_checkpoint"`
}

type FinalizedEscrowV2Resolver interface {
	ResolveFinalizedV2(context.Context, string) (*toschain.FinalizedEscrowV2, bool, error)
}

// BuildBuyerAcceptNativeEvidence creates a stable evidence reference. A
// receiving Agent does not trust this object by itself; it independently
// resolves the same escrow through its configured finalized quorum.
func BuildBuyerAcceptNativeEvidence(binding commerce.PaidDemandQuoteBindingBody, state *toschain.FinalizedEscrowV2,
	network *nativev1.NetworkDomain, resolver commerce.ProviderOfferKeyResolver) ([]byte, string, error) {
	if commerce.ValidatePaidDemandQuoteBinding(binding) != nil || state == nil || state.State == nil || state.Reference == nil ||
		network == nil || network.NetworkId != binding.NetworkContext || resolver == nil ||
		state.State.Status == nativecore.EscrowStatusPendingAcceptanceV2 || state.State.QuoteCommitment == "" ||
		state.State.BuyerAddress != binding.BuyerWallet || state.State.AcceptedAtUnix == 0 ||
		state.State.AcceptedAtUnix > binding.AcceptByUnix || state.Reference.FinalizedCheckpoint == 0 || state.Reference.Account == "" {
		return nil, "", errors.New("finalized buyer acceptance is invalid")
	}
	quote, err := nativecore.DecodeAcceptedQuoteV2(state.State.AcceptedQuote, network)
	if err != nil || quote.Extension.ProviderOfferBindingDigest == "" {
		return nil, "", errors.New("finalized buyer acceptance Quote is invalid")
	}
	var offer commerce.SignedProviderOffer
	if err := codec.Unmarshal(quote.Extension.ProviderOfferCanonical, &offer); err != nil {
		return nil, "", errors.New("finalized buyer acceptance Provider Offer is invalid")
	}
	wantBinding, _ := commerce.PaidDemandQuoteBindingDigest(binding)
	gotBinding, bindingErr := commerce.PaidDemandQuoteBindingDigest(offer.Binding)
	if bindingErr != nil || gotBinding != wantBinding || quote.Extension.ProviderOfferBindingDigest != wantBinding ||
		commerce.VerifyProviderOffer(offer, resolver, time.Unix(int64(state.State.AcceptedAtUnix), 0).UTC()) != nil {
		return nil, "", errors.New("finalized buyer acceptance targets another binding")
	}
	evidence := BuyerAcceptNativeEvidenceV1{SchemaVersion: 1, EscrowAddress: state.Reference.Account,
		QuoteCommitment: state.State.QuoteCommitment, BuyerWallet: state.State.BuyerAddress,
		AcceptedAtUnix: state.State.AcceptedAtUnix, ObservedCheckpoint: state.Reference.FinalizedCheckpoint}
	canonical, err := codec.Marshal(evidence)
	if err != nil {
		return nil, "", err
	}
	reference, err := codec.Digest("tos.paid-demand-buyer-accept-evidence.v1", evidence)
	return canonical, reference, err
}

type QuorumBuyerAcceptVerifier struct {
	Resolver       FinalizedEscrowV2Resolver
	Network        *nativev1.NetworkDomain
	ProviderOffers commerce.ProviderOfferKeyResolver
	Timeout        time.Duration
}

func (verifier QuorumBuyerAcceptVerifier) VerifyFinalizedBuyerAccept(binding commerce.PaidDemandQuoteBindingBody,
	nativeEvidence []byte, finalizedAt uint64, finalityReference string, now time.Time) error {
	if verifier.Resolver == nil || verifier.Network == nil || verifier.ProviderOffers == nil ||
		verifier.Network.NetworkId != binding.NetworkContext || finalizedAt == 0 || finalizedAt > uint64(now.Add(commerce.MaxIntentClockSkew).Unix()) {
		return errors.New("buyer acceptance verifier is incomplete")
	}
	var evidence BuyerAcceptNativeEvidenceV1
	if err := codec.Unmarshal(nativeEvidence, &evidence); err != nil || evidence.SchemaVersion != 1 || evidence.EscrowAddress == "" ||
		evidence.QuoteCommitment == "" || evidence.BuyerWallet != binding.BuyerWallet || evidence.AcceptedAtUnix == 0 ||
		evidence.AcceptedAtUnix > binding.AcceptByUnix || evidence.ObservedCheckpoint == 0 {
		return errors.New("buyer acceptance evidence is malformed")
	}
	reference, err := codec.Digest("tos.paid-demand-buyer-accept-evidence.v1", evidence)
	if err != nil || reference != finalityReference {
		return errors.New("buyer acceptance evidence reference mismatch")
	}
	timeout := verifier.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if timeout < time.Second || timeout > time.Minute {
		return errors.New("buyer acceptance verification timeout is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resolved, found, err := verifier.Resolver.ResolveFinalizedV2(ctx, evidence.EscrowAddress)
	if err != nil || !found || resolved == nil || resolved.State == nil || resolved.Reference == nil ||
		resolved.State.Status == nativecore.EscrowStatusPendingAcceptanceV2 || resolved.Reference.FinalizedCheckpoint < evidence.ObservedCheckpoint ||
		resolved.State.QuoteCommitment != evidence.QuoteCommitment || resolved.State.BuyerAddress != evidence.BuyerWallet ||
		resolved.State.AcceptedAtUnix != evidence.AcceptedAtUnix {
		return errors.New("buyer acceptance is not present in finalized quorum state")
	}
	quote, err := nativecore.DecodeAcceptedQuoteV2(resolved.State.AcceptedQuote, verifier.Network)
	if err != nil || quote.Extension.ProviderOfferBindingDigest == "" {
		return errors.New("finalized buyer acceptance has an invalid Quote")
	}
	var offer commerce.SignedProviderOffer
	if err := codec.Unmarshal(quote.Extension.ProviderOfferCanonical, &offer); err != nil {
		return errors.New("finalized buyer acceptance has no Provider Offer")
	}
	wantBinding, _ := commerce.PaidDemandQuoteBindingDigest(binding)
	gotBinding, bindingErr := commerce.PaidDemandQuoteBindingDigest(offer.Binding)
	if bindingErr != nil || gotBinding != wantBinding || quote.Extension.ProviderOfferBindingDigest != wantBinding ||
		commerce.VerifyProviderOffer(offer, verifier.ProviderOffers, time.Unix(int64(evidence.AcceptedAtUnix), 0).UTC()) != nil {
		return errors.New("finalized buyer acceptance targets another Agreement binding")
	}
	return nil
}

var _ BuyerAcceptEvidenceVerifier = QuorumBuyerAcceptVerifier{}
