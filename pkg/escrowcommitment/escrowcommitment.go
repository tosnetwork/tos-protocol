// Package escrowcommitment owns the canonical Phase 4B-2 Verified TaskEscrow
// reservation value. Protobuf is transport only; RFC 8949 deterministic CBOR
// is the stable cross-implementation commitment format.
package escrowcommitment

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

const (
	Version          = "atos_verified_task_escrow_v1"
	Canonicalization = "rfc8949_core_deterministic_cbor"
	Domain           = "tos.atos.verified-task-escrow.v1"
)

type ReleaseValue struct {
	ReservationDigest string `json:"reservation_digest"`
	EscrowID          string `json:"escrow_id"`
	JobID             string `json:"job_id"`
	QuoteID           string `json:"quote_id"`
	ReasonCode        string `json:"reason_code"`
}

type reference struct {
	Network   string `json:"network"`
	Reference string `json:"reference"`
}
type amount struct {
	Asset        string `json:"asset"`
	AtomicAmount string `json:"atomic_amount"`
}
type Value struct {
	Version                      string    `json:"version"`
	Canonicalization             string    `json:"canonicalization"`
	NetworkID                    string    `json:"network_id"`
	Domain                       string    `json:"domain"`
	EscrowID                     string    `json:"escrow_id"`
	JobID                        string    `json:"job_id"`
	QuoteID                      string    `json:"quote_id"`
	QuoteCommitmentDigest        string    `json:"quote_commitment_digest"`
	QuoteCommitmentRef           reference `json:"quote_commitment_ref"`
	PrincipalID                  string    `json:"principal_id"`
	RequesterAgentID             string    `json:"requester_agent_id"`
	ProviderID                   string    `json:"provider_id"`
	CapabilityID                 string    `json:"capability_id"`
	CapabilityVersion            string    `json:"capability_version"`
	ManifestDigest               string    `json:"manifest_digest"`
	OwnershipRef                 reference `json:"ownership_ref"`
	TrustMode                    string    `json:"trust_mode"`
	ProofProfile                 string    `json:"proof_profile"`
	Reserve                      amount    `json:"reserve"`
	AssetDecimals                uint32    `json:"asset_decimals"`
	SettlementBackend            string    `json:"settlement_backend"`
	SettlementAsset              string    `json:"settlement_asset"`
	FundingModel                 string    `json:"funding_model"`
	AcceptanceDeadlineUnixMillis int64     `json:"acceptance_deadline_unix_millis"`
	ExecutionDeadlineUnixMillis  int64     `json:"execution_deadline_unix_millis"`
	EscrowDeadlineUnixMillis     int64     `json:"escrow_deadline_unix_millis"`
	UnderlyingServiceQuoteRef    string    `json:"underlying_service_quote_ref"`
	DisputePolicyDigest          string    `json:"dispute_policy_digest"`
	SignerAuthorizationID        string    `json:"signer_authorization_id"`
	SignerAuthorizationRef       reference `json:"signer_authorization_ref"`
	Subtotal                     amount    `json:"subtotal"`
	Fees                         amount    `json:"fees"`
	TermsDigest                  string    `json:"terms_digest"`
}

func ref(v *atostosv1.NetworkReference) reference {
	if v == nil {
		return reference{}
	}
	return reference{v.Network, v.Reference}
}
func digest(v *atostosv1.Digest) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%s:%x", v.Algorithm, v.Value)
}
func cash(v *atostosv1.NetworkAmount) amount {
	if v == nil {
		return amount{}
	}
	return amount{v.Asset, v.AtomicAmount}
}

func CanonicalValue(v *atostosv1.VerifiedEscrowTerms) (Value, error) {
	if v == nil {
		return Value{}, errors.New("verified escrow terms are required")
	}
	if err := quotecommitment.RejectUnknown(v); err != nil {
		return Value{}, err
	}
	return Value{Version: v.Version, Canonicalization: v.Canonicalization, NetworkID: v.NetworkId, Domain: v.Domain,
		EscrowID: v.EscrowId, JobID: v.JobId, QuoteID: v.QuoteId, QuoteCommitmentDigest: v.QuoteCommitmentDigest,
		QuoteCommitmentRef: ref(v.QuoteCommitmentRef), PrincipalID: v.PrincipalId, RequesterAgentID: v.RequesterAgentId,
		ProviderID: v.ProviderId, CapabilityID: v.CapabilityId, CapabilityVersion: v.CapabilityVersion,
		ManifestDigest: digest(v.ManifestDigest), OwnershipRef: ref(v.OwnershipRef), TrustMode: v.TrustMode.String(),
		ProofProfile: v.ProofProfile.String(), Reserve: cash(v.Reserve), AssetDecimals: v.AssetDecimals,
		SettlementBackend: v.SettlementBackend, SettlementAsset: v.SettlementAsset, FundingModel: v.FundingModel,
		AcceptanceDeadlineUnixMillis: v.AcceptanceDeadlineUnixMillis, ExecutionDeadlineUnixMillis: v.ExecutionDeadlineUnixMillis,
		EscrowDeadlineUnixMillis: v.EscrowDeadlineUnixMillis, UnderlyingServiceQuoteRef: v.UnderlyingServiceQuoteRef,
		DisputePolicyDigest: digest(v.DisputePolicyDigest), SignerAuthorizationID: v.SignerAuthorizationId,
		SignerAuthorizationRef: ref(v.SignerAuthorizationRef), Subtotal: cash(v.Subtotal), Fees: cash(v.Fees), TermsDigest: digest(v.TermsDigest)}, nil
}
func Bytes(v *atostosv1.VerifiedEscrowTerms) ([]byte, error) {
	value, err := CanonicalValue(v)
	if err != nil {
		return nil, err
	}
	return codec.Marshal(value)
}
func Digest(v *atostosv1.VerifiedEscrowTerms) (string, error) {
	value, err := CanonicalValue(v)
	if err != nil {
		return "", err
	}
	return codec.Digest(Domain, value)
}

func EscrowID(network, domain, quoteID, jobID string) string {
	h := sha256.New()
	for _, value := range []string{"tos.atos.verified-task-escrow-id.v1", network, domain, quoteID, jobID} {
		h.Write([]byte(value))
		h.Write([]byte{0})
	}
	return "esc_" + hex.EncodeToString(h.Sum(nil))[:32]
}

func ReleaseDigest(reservationDigest, escrowID, jobID, quoteID, reasonCode string) (string, error) {
	if reservationDigest == "" || escrowID == "" || jobID == "" || quoteID == "" || reasonCode == "" {
		return "", errors.New("complete verified escrow release tuple is required")
	}
	return codec.Digest("tos.atos.verified-task-escrow-release.v1", ReleaseValue{
		ReservationDigest: reservationDigest, EscrowID: escrowID, JobID: jobID,
		QuoteID: quoteID, ReasonCode: reasonCode,
	})
}
