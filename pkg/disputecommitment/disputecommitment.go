// Package disputecommitment defines portable Verified dispute commitments.
// Protobuf is transport only and is never hashed directly.
package disputecommitment

import (
	"bytes"
	"errors"
	"sort"
	"strings"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

const (
	OpenDomain       = "tos.atos.verified-dispute-open.v1"
	ResolutionDomain = "tos.atos.verified-dispute-resolution.v1"
)

type digest struct {
	Algorithm string `json:"algorithm"`
	Value     []byte `json:"value"`
}
type amount struct {
	Asset        string `json:"asset"`
	AtomicAmount string `json:"atomic_amount"`
}

type OpenValue struct {
	Version               string   `json:"version"`
	NetworkID             string   `json:"network_id"`
	GatewayDomain         string   `json:"gateway_domain"`
	DisputeID             string   `json:"dispute_id"`
	EscrowID              string   `json:"escrow_id"`
	JobID                 string   `json:"job_id"`
	QuoteID               string   `json:"quote_id"`
	ReceiptID             string   `json:"receipt_id"`
	PrincipalID           string   `json:"principal_id"`
	ProviderID            string   `json:"provider_id"`
	CapabilityID          string   `json:"capability_id"`
	CapabilityVersion     string   `json:"capability_version"`
	QuoteCommitmentDigest string   `json:"quote_commitment_digest"`
	ReservationDigest     string   `json:"reservation_digest"`
	ReceiptDigest         string   `json:"receipt_digest"`
	DisputePolicyDigest   digest   `json:"dispute_policy_digest"`
	ReasonCode            string   `json:"reason_code"`
	EvidenceDigests       []digest `json:"evidence_digests"`
	OpenedUnixMillis      int64    `json:"opened_unix_millis"`
}

type ResolutionValue struct {
	Version             string `json:"version"`
	NetworkID           string `json:"network_id"`
	GatewayDomain       string `json:"gateway_domain"`
	DisputeID           string `json:"dispute_id"`
	EscrowID            string `json:"escrow_id"`
	JobID               string `json:"job_id"`
	QuoteID             string `json:"quote_id"`
	ReceiptID           string `json:"receipt_id"`
	DisputeDigest       string `json:"dispute_digest"`
	Outcome             string `json:"outcome"`
	ReviewerPrincipalID string `json:"reviewer_principal_id"`
	Reserved            amount `json:"reserved"`
	ProviderPayout      amount `json:"provider_payout"`
	RequesterRefund     amount `json:"requester_refund"`
	ResolvedUnixMillis  int64  `json:"resolved_unix_millis"`
}

func dg(v *atostosv1.Digest) digest {
	if v == nil {
		return digest{}
	}
	return digest{v.Algorithm, append([]byte(nil), v.Value...)}
}
func amt(v *atostosv1.NetworkAmount) amount {
	if v == nil {
		return amount{}
	}
	return amount{v.Asset, v.AtomicAmount}
}

func OpenDigest(v *atostosv1.VerifiedDisputeOpen) (string, error) {
	if v == nil {
		return "", errors.New("verified dispute open tuple is required")
	}
	if err := quotecommitment.RejectUnknown(v); err != nil {
		return "", err
	}
	if v.Version != "atos_verified_dispute_open_v1" || v.OpenedUnixMillis <= 0 {
		return "", errors.New("invalid verified dispute open version or time")
	}
	for name, value := range map[string]string{"network": v.NetworkId, "domain": v.GatewayDomain, "dispute": v.DisputeId, "escrow": v.EscrowId, "job": v.JobId, "quote": v.QuoteId, "receipt": v.ReceiptId, "principal": v.PrincipalId, "provider": v.ProviderId, "capability": v.CapabilityId, "capability_version": v.CapabilityVersion, "quote_digest": v.QuoteCommitmentDigest, "reservation_digest": v.ReservationDigest, "receipt_digest": v.ReceiptDigest, "reason": v.ReasonCode} {
		if strings.TrimSpace(value) == "" {
			return "", errors.New("missing verified dispute field: " + name)
		}
	}
	for name, value := range map[string]string{"quote_digest": v.QuoteCommitmentDigest, "reservation_digest": v.ReservationDigest, "receipt_digest": v.ReceiptDigest} {
		if !validDigestString(value) {
			return "", errors.New("invalid verified dispute digest: " + name)
		}
	}
	if !validDigest(v.DisputePolicyDigest) {
		return "", errors.New("invalid dispute policy digest")
	}
	evidence := make([]digest, len(v.EvidenceDigests))
	for i := range v.EvidenceDigests {
		if !validDigest(v.EvidenceDigests[i]) {
			return "", errors.New("invalid evidence digest")
		}
		evidence[i] = dg(v.EvidenceDigests[i])
	}
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].Algorithm != evidence[j].Algorithm {
			return evidence[i].Algorithm < evidence[j].Algorithm
		}
		return string(evidence[i].Value) < string(evidence[j].Value)
	})
	for i := 1; i < len(evidence); i++ {
		if evidence[i-1].Algorithm == evidence[i].Algorithm && bytes.Equal(evidence[i-1].Value, evidence[i].Value) {
			return "", errors.New("duplicate evidence digest")
		}
	}
	x := OpenValue{v.Version, v.NetworkId, v.GatewayDomain, v.DisputeId, v.EscrowId, v.JobId, v.QuoteId, v.ReceiptId, v.PrincipalId, v.ProviderId, v.CapabilityId, v.CapabilityVersion, v.QuoteCommitmentDigest, v.ReservationDigest, v.ReceiptDigest, dg(v.DisputePolicyDigest), v.ReasonCode, evidence, v.OpenedUnixMillis}
	return codec.Digest(OpenDomain, x)
}

func ResolutionDigest(v *atostosv1.VerifiedDisputeResolution) (string, error) {
	if v == nil {
		return "", errors.New("verified dispute resolution tuple is required")
	}
	if err := quotecommitment.RejectUnknown(v); err != nil {
		return "", err
	}
	if v.Version != "atos_verified_dispute_resolution_v1" || v.ResolvedUnixMillis <= 0 {
		return "", errors.New("invalid verified dispute resolution version or time")
	}
	for name, value := range map[string]string{"network": v.NetworkId, "domain": v.GatewayDomain, "dispute": v.DisputeId, "escrow": v.EscrowId, "job": v.JobId, "quote": v.QuoteId, "receipt": v.ReceiptId, "dispute_digest": v.DisputeDigest, "outcome": v.Outcome, "reviewer": v.ReviewerPrincipalId} {
		if strings.TrimSpace(value) == "" {
			return "", errors.New("missing verified dispute resolution field: " + name)
		}
	}
	if !validDigestString(v.DisputeDigest) {
		return "", errors.New("invalid dispute digest")
	}
	if !validAmount(v.Reserved) || !validAmount(v.ProviderPayout) || !validAmount(v.RequesterRefund) || v.Reserved.Asset != v.ProviderPayout.Asset || v.Reserved.Asset != v.RequesterRefund.Asset {
		return "", errors.New("invalid dispute resolution amounts")
	}
	x := ResolutionValue{v.Version, v.NetworkId, v.GatewayDomain, v.DisputeId, v.EscrowId, v.JobId, v.QuoteId, v.ReceiptId, v.DisputeDigest, v.Outcome, v.ReviewerPrincipalId, amt(v.Reserved), amt(v.ProviderPayout), amt(v.RequesterRefund), v.ResolvedUnixMillis}
	return codec.Digest(ResolutionDomain, x)
}

func validDigest(v *atostosv1.Digest) bool {
	return v != nil && strings.EqualFold(strings.TrimSpace(v.Algorithm), "sha256") && len(v.Value) == 32
}

func validAmount(v *atostosv1.NetworkAmount) bool {
	if v == nil || strings.TrimSpace(v.Asset) == "" || strings.TrimSpace(v.AtomicAmount) == "" {
		return false
	}
	for _, r := range v.AtomicAmount {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validDigestString(v string) bool {
	v = strings.TrimSpace(v)
	if len(v) != 71 || !strings.HasPrefix(v, "sha256:") {
		return false
	}
	for _, r := range v[7:] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}
