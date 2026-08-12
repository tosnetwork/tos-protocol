// Package verifiedproof implements the canonical tos_verified_v1 portable
// proof package. It has no ATOS database dependency and exposes only read-only
// verification authority interfaces.
package verifiedproof

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

const (
	Version          = "tos_verified_v1"
	Canonicalization = "rfc8949_core_deterministic_cbor"
	Domain           = "tos.atos.portable-proof.v1"
	ReceiptDomain    = "tos.atos.execution-receipt.v2"
)

type Reference struct {
	Network             string `json:"network"`
	Reference           string `json:"reference"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
}

type Capability struct {
	CapabilityID      string    `json:"capability_id"`
	CapabilityVersion string    `json:"capability_version"`
	ManifestDigest    string    `json:"manifest_digest"`
	OwnershipRef      Reference `json:"ownership_ref"`
}

type Quote struct {
	QuoteID                     string    `json:"quote_id"`
	CommitmentDigest            string    `json:"commitment_digest"`
	CommitmentRef               Reference `json:"commitment_ref"`
	TermsDigest                 string    `json:"terms_digest"`
	TrustMode                   string    `json:"trust_mode"`
	ProofProfile                string    `json:"proof_profile"`
	SettlementBackend           string    `json:"settlement_backend"`
	SettlementAsset             string    `json:"settlement_asset"`
	AssetDecimals               uint32    `json:"asset_decimals"`
	SubtotalAtomic              string    `json:"subtotal_atomic"`
	FeesAtomic                  string    `json:"fees_atomic"`
	TotalMaxAtomic              string    `json:"total_max_atomic"`
	AcceptanceDeadlineUnixNanos int64     `json:"acceptance_deadline_unix_nanos"`
	QuoteExpiryUnixNanos        int64     `json:"quote_expiry_unix_nanos"`
	ExecutionDeadlineUnixNanos  int64     `json:"execution_deadline_unix_nanos"`
	UnderlyingServiceQuoteRef   string    `json:"underlying_service_quote_ref"`
	DisputePolicyDigest         string    `json:"dispute_policy_digest"`
	CanonicalCBOR               []byte    `json:"canonical_cbor"`
}

type Escrow struct {
	EscrowID                string    `json:"escrow_id"`
	JobID                   string    `json:"job_id"`
	ContractRef             Reference `json:"contract_ref"`
	ContractCodeHash        string    `json:"contract_code_hash"`
	ReservationDigest       string    `json:"reservation_digest"`
	ReservationRef          Reference `json:"reservation_ref"`
	ReservedAtomic          string    `json:"reserved_atomic"`
	EscrowDeadlineUnixNanos int64     `json:"escrow_deadline_unix_nanos"`
	FundingModel            string    `json:"funding_model"`
	CanonicalCBOR           []byte    `json:"canonical_cbor"`
}

type SignerAuthorization struct {
	AuthorizationID     string    `json:"authorization_id"`
	ExecutionSignerID   string    `json:"execution_signer_id"`
	AuthorizationRef    Reference `json:"authorization_ref"`
	SignatureAlgorithm  string    `json:"signature_algorithm"`
	SignerPublicKey     []byte    `json:"signer_public_key"`
	ValidFromUnixNanos  int64     `json:"valid_from_unix_nanos"`
	ValidUntilUnixNanos int64     `json:"valid_until_unix_nanos"`
}

type Receipt struct {
	ReceiptID          string    `json:"receipt_id"`
	ReceiptDigest      string    `json:"receipt_digest"`
	ReceiptRef         Reference `json:"receipt_ref"`
	Result             string    `json:"result"`
	InputCommitment    string    `json:"input_commitment"`
	OutputCommitment   string    `json:"output_commitment"`
	UsageCommitment    string    `json:"usage_commitment"`
	StartedUnixNanos   int64     `json:"started_unix_nanos"`
	CompletedUnixNanos int64     `json:"completed_unix_nanos"`
	ChargedAtomic      string    `json:"charged_atomic"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	Signature          []byte    `json:"signature"`
	CanonicalCBOR      []byte    `json:"canonical_cbor"`
}

type Outcome struct {
	Kind             string    `json:"kind"`
	OutcomeRef       Reference `json:"outcome_ref"`
	ChargedAtomic    string    `json:"charged_atomic"`
	RefundedAtomic   string    `json:"refunded_atomic"`
	ReleaseDigest    string    `json:"release_digest,omitempty"`
	ReasonCode       string    `json:"reason_code,omitempty"`
	DisputeDigest    string    `json:"dispute_digest,omitempty"`
	DisputeRef       Reference `json:"dispute_ref,omitempty"`
	ResolutionDigest string    `json:"resolution_digest,omitempty"`
	DisputeOutcome   string    `json:"dispute_outcome,omitempty"`
}

type ProofOfService struct {
	EvidenceID     string    `json:"evidence_id"`
	EvidenceDigest string    `json:"evidence_digest"`
	EvidenceRef    Reference `json:"evidence_ref"`
	ContentDigest  string    `json:"content_digest"`
	RetrievalRef   string    `json:"retrieval_ref,omitempty"`
	CanonicalCBOR  []byte    `json:"canonical_cbor"`
}

type Package struct {
	Version              string               `json:"version"`
	Canonicalization     string               `json:"canonicalization"`
	NetworkID            string               `json:"network_id"`
	GatewayDomain        string               `json:"gateway_domain"`
	PrincipalID          string               `json:"principal_id"`
	RequesterAgentID     string               `json:"requester_agent_id"`
	RequesterIdentityRef Reference            `json:"requester_identity_ref"`
	ProviderID           string               `json:"provider_id"`
	ProviderIdentityRef  Reference            `json:"provider_identity_ref"`
	Capability           Capability           `json:"capability"`
	Quote                Quote                `json:"quote"`
	Escrow               Escrow               `json:"escrow"`
	SignerAuthorization  *SignerAuthorization `json:"signer_authorization,omitempty"`
	Receipt              *Receipt             `json:"receipt,omitempty"`
	Outcome              Outcome              `json:"outcome"`
	ProofOfService       *ProofOfService      `json:"proof_of_service,omitempty"`
}

func Marshal(p Package) ([]byte, error) { return codec.Marshal(p) }

func Parse(data []byte) (Package, error) {
	var p Package
	if err := codec.Unmarshal(data, &p); err != nil {
		return Package{}, err
	}
	return p, nil
}

func Digest(p Package) (string, error) { return codec.Digest(Domain, p) }

func PackageID(p Package) (string, error) {
	digest, err := Digest(p)
	if err != nil {
		return "", err
	}
	return "proof_" + strings.TrimPrefix(digest, "sha256:")[:32], nil
}

type receiptSigningValue struct {
	NetworkID          string     `json:"network_id"`
	GatewayDomain      string     `json:"gateway_domain"`
	PrincipalID        string     `json:"principal_id"`
	RequesterAgentID   string     `json:"requester_agent_id"`
	ProviderID         string     `json:"provider_id"`
	Capability         Capability `json:"capability"`
	QuoteID            string     `json:"quote_id"`
	EscrowID           string     `json:"escrow_id"`
	JobID              string     `json:"job_id"`
	ReceiptID          string     `json:"receipt_id"`
	Result             string     `json:"result"`
	InputCommitment    string     `json:"input_commitment"`
	OutputCommitment   string     `json:"output_commitment"`
	UsageCommitment    string     `json:"usage_commitment"`
	StartedUnixNanos   int64      `json:"started_unix_nanos"`
	CompletedUnixNanos int64      `json:"completed_unix_nanos"`
	ChargedAtomic      string     `json:"charged_atomic"`
	SignatureAlgorithm string     `json:"signature_algorithm"`
}

func ReceiptSigningDigest(p Package) ([]byte, string, error) {
	if p.Receipt == nil {
		return nil, "", errors.New("receipt is required")
	}
	d, err := codec.DigestCanonical(ReceiptDomain, p.Receipt.CanonicalCBOR)
	if err != nil {
		return nil, "", err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
	return raw, d, err
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil && value == strings.ToLower(value)
}

func validTVMCodeHash(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil && value == strings.ToLower(value)
}

func ValidateReference(network string, ref Reference) error {
	if ref.Network != network || strings.TrimSpace(ref.Reference) == "" || ref.FinalizedCheckpoint == 0 {
		return fmt.Errorf("invalid finalized reference for network %q", network)
	}
	return nil
}

var ErrInvalid = errors.New("invalid portable proof package")
