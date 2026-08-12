package atosrpc

import (
	"context"
	"errors"
	"math/big"
	"strings"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

const tosAssetDecimals = uint32(9)

func fixedTOSFromAtomic(value string) (string, error) {
	n, ok := new(big.Int).SetString(value, 10)
	if !ok || n.Sign() < 0 || value != n.String() {
		return "", errors.New("invalid canonical nanoTOS amount")
	}
	digits := n.String()
	for len(digits) <= int(tosAssetDecimals) {
		digits = "0" + digits
	}
	return digits[:len(digits)-int(tosAssetDecimals)] + "." + digits[len(digits)-int(tosAssetDecimals):], nil
}

func verifiedQuoteFromEscrowTerms(v *atostosv1.VerifiedEscrowTerms) (*atostosv1.QuoteCommitmentInput, error) {
	if v == nil || v.Reserve == nil || v.Subtotal == nil || v.Fees == nil {
		return nil, errors.New("complete verified escrow terms are required")
	}
	total, err := fixedTOSFromAtomic(v.Reserve.AtomicAmount)
	if err != nil {
		return nil, err
	}
	subtotal, err := fixedTOSFromAtomic(v.Subtotal.AtomicAmount)
	if err != nil {
		return nil, err
	}
	fees, err := fixedTOSFromAtomic(v.Fees.AtomicAmount)
	if err != nil {
		return nil, err
	}
	return &atostosv1.QuoteCommitmentInput{
		Version: quotecommitment.Version, Canonicalization: quotecommitment.Canonicalization,
		NetworkId: v.NetworkId, Domain: v.Domain, QuoteId: v.QuoteId, PrincipalId: v.PrincipalId,
		RequesterAgentId: v.RequesterAgentId, ProviderId: v.ProviderId, CapabilityId: v.CapabilityId,
		CapabilityVersion: v.CapabilityVersion, ManifestDigest: v.ManifestDigest, OwnershipRef: v.OwnershipRef,
		TrustMode: v.TrustMode, ProofProfile: v.ProofProfile,
		Subtotal: &atostosv1.Money{Amount: subtotal, Currency: "TOS"}, Fees: &atostosv1.Money{Amount: fees, Currency: "TOS"},
		TotalMax: &atostosv1.Money{Amount: total, Currency: "TOS"}, AssetDecimals: v.AssetDecimals,
		TermsDigest: v.TermsDigest, DisputePolicyDigest: v.DisputePolicyDigest,
		AcceptanceDeadlineUnixMillis: v.AcceptanceDeadlineUnixMillis, ExpiresUnixMillis: v.AcceptanceDeadlineUnixMillis,
		ExecutionDeadlineUnixMillis: v.ExecutionDeadlineUnixMillis, SettlementBackend: v.SettlementBackend,
		SettlementAsset: v.SettlementAsset, UnderlyingServiceQuoteRef: v.UnderlyingServiceQuoteRef,
		SignerAuthorizationId: v.SignerAuthorizationId, SignerAuthorizationRef: v.SignerAuthorizationRef,
	}, nil
}

func (s *Server) validateVerifiedEscrowTerms(ctx context.Context, v *atostosv1.VerifiedEscrowTerms) (*atostosv1.QuoteCommitmentInput, string, *NetworkReference, error) {
	if v == nil {
		return nil, "", nil, invalid("INVALID_ARGUMENT", "verified escrow terms are required")
	}
	if err := quotecommitment.RejectUnknown(v); err != nil {
		return nil, "", nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	if v.Version != escrowcommitment.Version || v.Canonicalization != escrowcommitment.Canonicalization ||
		v.NetworkId != s.authority.Network() || v.Domain != s.config.TrustDomain ||
		v.EscrowId != escrowcommitment.EscrowID(v.NetworkId, v.Domain, v.QuoteId, v.JobId) ||
		v.TrustMode != TrustModeVerified || v.ProofProfile != atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1 ||
		v.AssetDecimals != tosAssetDecimals || v.SettlementBackend != "tos" || v.SettlementAsset != "TOS" ||
		v.Reserve == nil || v.Reserve.Asset != "TOS" || v.Subtotal == nil || v.Subtotal.Asset != "TOS" ||
		v.Fees == nil || v.Fees.Asset != "TOS" || v.QuoteCommitmentRef == nil ||
		v.QuoteCommitmentRef.Network != v.NetworkId || !v.QuoteCommitmentRef.Finalized || v.QuoteCommitmentRef.FinalizedCheckpoint == 0 ||
		strings.TrimSpace(v.QuoteCommitmentRef.Reference) == "" || strings.TrimSpace(v.JobId) == "" || strings.TrimSpace(v.PrincipalId) == "" ||
		strings.TrimSpace(v.ProviderId) == "" || strings.TrimSpace(v.CapabilityVersion) == "" || strings.TrimSpace(v.FundingModel) == "" ||
		v.AcceptanceDeadlineUnixMillis <= 0 || v.ExecutionDeadlineUnixMillis <= 0 || v.EscrowDeadlineUnixMillis <= 0 ||
		v.AcceptanceDeadlineUnixMillis%1000 != 0 || v.ExecutionDeadlineUnixMillis%1000 != 0 || v.EscrowDeadlineUnixMillis%1000 != 0 ||
		v.EscrowDeadlineUnixMillis > v.ExecutionDeadlineUnixMillis || strings.TrimSpace(v.SignerAuthorizationId) == "" {
		return nil, "", nil, invalid("INVALID_ARGUMENT", "verified escrow terms are incomplete or inconsistent")
	}
	reserve, err := parseAtomic(v.Reserve.AtomicAmount)
	if err != nil || reserve.Sign() <= 0 || !reserve.IsUint64() {
		return nil, "", nil, invalid("INVALID_ARGUMENT", "reserve is invalid or outside uint64")
	}
	subtotal, err := parseAtomic(v.Subtotal.AtomicAmount)
	if err != nil {
		return nil, "", nil, invalid("INVALID_ARGUMENT", "subtotal is invalid")
	}
	fees, err := parseAtomic(v.Fees.AtomicAmount)
	if err != nil || fees.Sign() != 0 || new(big.Int).Add(subtotal, fees).Cmp(reserve) != 0 {
		return nil, "", nil, invalid("INVALID_ARGUMENT", "verified fees must be zero and subtotal plus fees must equal reserve")
	}
	expected, err := verifiedQuoteFromEscrowTerms(v)
	if err != nil {
		return nil, "", nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	digest, err := quotecommitment.Digest(expected)
	if err != nil || digest != v.QuoteCommitmentDigest {
		return nil, "", nil, failedPrecondition("QUOTE_MISMATCH", "escrow terms do not reconstruct the committed Quote")
	}
	resolver, ok := s.authority.(CommitmentResolver)
	if !ok {
		return nil, "", nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote live resolver unavailable")
	}
	live, err := resolver.ResolveCommitment(ctx, "quote", v.QuoteId, digest, v.QuoteCommitmentRef)
	if err != nil || !validLiveQuoteReference(s.authority.Network(), live, v.QuoteCommitmentRef) {
		return nil, "", nil, unavailable("NETWORK_UNAVAILABLE", "verified Quote finality could not be re-observed")
	}
	return expected, digest, live, nil
}
