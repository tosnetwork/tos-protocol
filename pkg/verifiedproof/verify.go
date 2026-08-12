package verifiedproof

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

type Code string

const (
	CodeMalformed   Code = "MALFORMED_PACKAGE"
	CodeUnsupported Code = "UNSUPPORTED_VERSION"
	CodeDigest      Code = "DIGEST_MISMATCH"
	CodeTuple       Code = "TUPLE_MISMATCH"
	CodeNetwork     Code = "NETWORK_MISMATCH"
	CodeDomain      Code = "DOMAIN_MISMATCH"
	CodeSigner      Code = "SIGNER_UNAUTHORIZED"
	CodeSignature   Code = "SIGNATURE_INVALID"
	CodeFinality    Code = "FINALITY_INVALID"
	CodeRegression  Code = "FINALITY_REGRESSION"
	CodeUnavailable Code = "AUTHORITY_UNAVAILABLE"
	CodeNotFound    Code = "EVIDENCE_NOT_FOUND"
	CodeOutcome     Code = "OUTCOME_INVALID"
)

type Failure struct {
	Code    Code   `json:"code"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
}
type Result struct {
	Valid             bool      `json:"valid"`
	PackageDigest     string    `json:"package_digest,omitempty"`
	PackageID         string    `json:"package_id,omitempty"`
	Version           string    `json:"version,omitempty"`
	Network           string    `json:"network,omitempty"`
	QuoteID           string    `json:"quote_id,omitempty"`
	JobID             string    `json:"job_id,omitempty"`
	CapabilityID      string    `json:"capability_id,omitempty"`
	EscrowID          string    `json:"escrow_id,omitempty"`
	Outcome           string    `json:"outcome,omitempty"`
	ExecutionSignerID string    `json:"execution_signer_id,omitempty"`
	Checkpoints       []uint64  `json:"finality_checkpoints,omitempty"`
	Failures          []Failure `json:"failures,omitempty"`
}

type EvidenceRequest struct {
	Kind, ObjectID, Digest string
	Reference              Reference
}
type EvidenceObservation struct {
	Found                                      bool
	Network, Kind, ObjectID, Digest, Reference string
	Finalized                                  bool
	FinalizedCheckpoint                        uint64
}
type SignerObservation struct {
	Found, Revoked                                                                                                 bool
	RevokedUnixNanos                                                                                               int64
	Network, AuthorizationID, ProviderID, CapabilityID, CapabilityVersion, SignerID, Reference, SignatureAlgorithm string
	PublicKey                                                                                                      []byte
	ValidFromUnixNanos, ValidUntilUnixNanos                                                                        int64
	FinalizedCheckpoint                                                                                            uint64
}
type Observer interface {
	Observe(context.Context, EvidenceRequest) (EvidenceObservation, error)
	ResolveSigner(context.Context, Package) (SignerObservation, error)
}

type Verifier struct {
	Observer               Observer
	Network, GatewayDomain string
	MinimumCheckpoint      uint64
}

func (v Verifier) VerifyBytes(ctx context.Context, data []byte) Result {
	p, err := Parse(data)
	if err != nil {
		return Result{Failures: []Failure{{CodeMalformed, "package", err.Error()}}}
	}
	return v.Verify(ctx, p)
}

func (v Verifier) Verify(ctx context.Context, p Package) Result {
	r := Result{Version: p.Version, Network: p.NetworkID, QuoteID: p.Quote.QuoteID, JobID: p.Escrow.JobID, CapabilityID: p.Capability.CapabilityID, EscrowID: p.Escrow.EscrowID, Outcome: p.Outcome.Kind, ExecutionSignerID: p.SignerAuthorization.ExecutionSignerID}
	add := func(code Code, field, msg string) { r.Failures = append(r.Failures, Failure{code, field, msg}) }
	if p.Version != Version || p.Canonicalization != Canonicalization {
		add(CodeUnsupported, "version", "unsupported package version or canonicalization")
		return r
	}
	if v.Network != "" && p.NetworkID != v.Network {
		add(CodeNetwork, "network_id", "package network differs from verifier")
	}
	if v.GatewayDomain != "" && p.GatewayDomain != v.GatewayDomain {
		add(CodeDomain, "gateway_domain", "package domain differs from verifier")
	}
	if p.Quote.TrustMode != "verified" || p.Quote.ProofProfile != "tos_verified_v1" || p.Quote.SettlementBackend != "tos" || p.Quote.SettlementAsset != "TOS" || p.Quote.AssetDecimals != 9 || p.Quote.FeesAtomic != "0" || p.Escrow.FundingModel != "task_escrow_v1" {
		add(CodeTuple, "quote", "unsupported Verified commercial tuple")
	}
	for field, value := range map[string]string{"manifest_digest": p.Capability.ManifestDigest, "quote.commitment_digest": p.Quote.CommitmentDigest, "quote.terms_digest": p.Quote.TermsDigest, "quote.dispute_policy_digest": p.Quote.DisputePolicyDigest, "escrow.reservation_digest": p.Escrow.ReservationDigest, "escrow.contract_code_hash": p.Escrow.ContractCodeHash, "receipt.receipt_digest": p.Receipt.ReceiptDigest, "receipt.input_commitment": p.Receipt.InputCommitment, "receipt.output_commitment": p.Receipt.OutputCommitment, "receipt.usage_commitment": p.Receipt.UsageCommitment, "proof_of_service.evidence_digest": p.ProofOfService.EvidenceDigest, "proof_of_service.content_digest": p.ProofOfService.ContentDigest} {
		if !validDigest(value) {
			add(CodeDigest, field, "invalid SHA-256 digest")
		}
	}
	amounts := map[string]string{"subtotal": p.Quote.SubtotalAtomic, "fees": p.Quote.FeesAtomic, "total_max": p.Quote.TotalMaxAtomic, "reserved": p.Escrow.ReservedAtomic, "receipt.charge": p.Receipt.ChargedAtomic, "outcome.charge": p.Outcome.ChargedAtomic, "outcome.refund": p.Outcome.RefundedAtomic}
	parsed := map[string]*big.Int{}
	for k, s := range amounts {
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.Sign() < 0 || (len(s) > 1 && s[0] == '0') {
			add(CodeTuple, k, "invalid atomic amount")
		} else {
			parsed[k] = n
		}
	}
	if len(parsed) == len(amounts) {
		if parsed["total_max"].Cmp(parsed["reserved"]) != 0 || parsed["receipt.charge"].Cmp(parsed["outcome.charge"]) != 0 || new(big.Int).Add(parsed["outcome.charge"], parsed["outcome.refund"]).Cmp(parsed["reserved"]) != 0 {
			add(CodeOutcome, "outcome", "monetary conservation failed")
		}
	}
	if p.Receipt.CompletedUnixNanos < p.Receipt.StartedUnixNanos || p.Receipt.CompletedUnixNanos < p.SignerAuthorization.ValidFromUnixNanos || p.Receipt.CompletedUnixNanos >= p.SignerAuthorization.ValidUntilUnixNanos {
		add(CodeSigner, "receipt.completed_unix_nanos", "receipt outside signer validity")
	}
	if _, expectedReceiptDigest, err := ReceiptSigningDigest(p); err != nil || expectedReceiptDigest != p.Receipt.ReceiptDigest {
		add(CodeDigest, "receipt.receipt_digest", "receipt digest does not match canonical receipt tuple")
	}
	switch p.Outcome.Kind {
	case "provider_settlement":
		if p.Outcome.ReleaseDigest != "" || p.Outcome.DisputeDigest != "" {
			add(CodeOutcome, "outcome", "settlement has release/dispute fields")
		}
	case "requester_release":
		if !validDigest(p.Outcome.ReleaseDigest) || p.Outcome.ReasonCode == "" || p.Outcome.DisputeDigest != "" {
			add(CodeOutcome, "outcome", "invalid release tuple")
		}
	case "dispute_resolution":
		if !validDigest(p.Outcome.DisputeDigest) || p.Outcome.DisputeOutcome == "" || p.Outcome.ReleaseDigest != "" {
			add(CodeOutcome, "outcome", "invalid dispute tuple")
		}
	default:
		add(CodeOutcome, "outcome.kind", "unsupported outcome")
	}
	refs := []struct {
		name, kind, id, digest string
		ref                    Reference
	}{{"requester_identity_ref", "identity", p.RequesterAgentID, "", p.RequesterIdentityRef}, {"provider_identity_ref", "identity", p.ProviderID, "", p.ProviderIdentityRef}, {"capability.ownership_ref", "capability-ownership", p.Capability.CapabilityID, p.Capability.ManifestDigest, p.Capability.OwnershipRef}, {"quote.commitment_ref", "verified-quote", p.Quote.QuoteID, p.Quote.CommitmentDigest, p.Quote.CommitmentRef}, {"escrow.reservation_ref", "task-escrow-reservation", p.Escrow.EscrowID, p.Escrow.ReservationDigest, p.Escrow.ReservationRef}, {"escrow.contract_ref", "task-escrow", p.Escrow.EscrowID, p.Escrow.ReservationDigest, p.Escrow.ContractRef}, {"signer.authorization_ref", "execution-signer", p.SignerAuthorization.AuthorizationID, "", p.SignerAuthorization.AuthorizationRef}, {"receipt.receipt_ref", "verified-receipt", p.Receipt.ReceiptID, p.Receipt.ReceiptDigest, p.Receipt.ReceiptRef}, {"outcome.outcome_ref", p.Outcome.Kind, p.Escrow.EscrowID, outcomeDigest(p), p.Outcome.OutcomeRef}, {"proof_of_service.evidence_ref", "proof-of-service", p.ProofOfService.EvidenceID, p.ProofOfService.EvidenceDigest, p.ProofOfService.EvidenceRef}}
	for _, x := range refs {
		if err := ValidateReference(p.NetworkID, x.ref); err != nil {
			add(CodeFinality, x.name, err.Error())
			continue
		}
		r.Checkpoints = append(r.Checkpoints, x.ref.FinalizedCheckpoint)
		if v.MinimumCheckpoint > 0 && x.ref.FinalizedCheckpoint < v.MinimumCheckpoint {
			add(CodeRegression, x.name, "checkpoint below verifier floor")
		}
		if v.Observer != nil {
			o, e := v.Observer.Observe(ctx, EvidenceRequest{x.kind, x.id, x.digest, x.ref})
			if e != nil {
				add(CodeUnavailable, x.name, e.Error())
			} else if !o.Found {
				add(CodeNotFound, x.name, "canonical evidence not found")
			} else if !o.Finalized || o.FinalizedCheckpoint == 0 {
				add(CodeFinality, x.name, "canonical evidence is not final")
			} else if o.Network != p.NetworkID || o.Kind != x.kind || o.ObjectID != x.id || o.Reference != x.ref.Reference || (x.digest != "" && o.Digest != x.digest) {
				add(CodeTuple, x.name, "canonical observation tuple mismatch")
			} else if o.FinalizedCheckpoint < x.ref.FinalizedCheckpoint {
				add(CodeRegression, x.name, "live checkpoint regressed")
			}
		}
	}
	if v.Observer == nil {
		add(CodeUnavailable, "observer", "live observer is required")
	} else {
		s, e := v.Observer.ResolveSigner(ctx, p)
		if e != nil {
			add(CodeUnavailable, "signer_authorization", e.Error())
		} else if !s.Found || s.Revoked && s.RevokedUnixNanos <= p.Receipt.CompletedUnixNanos || s.AuthorizationID != p.SignerAuthorization.AuthorizationID || s.ProviderID != p.ProviderID || s.CapabilityID != p.Capability.CapabilityID || s.CapabilityVersion != p.Capability.CapabilityVersion || s.SignerID != p.SignerAuthorization.ExecutionSignerID || s.Reference != p.SignerAuthorization.AuthorizationRef.Reference || !strings.EqualFold(s.SignatureAlgorithm, "ed25519") || !equalBytes(s.PublicKey, p.SignerAuthorization.SignerPublicKey) || p.Receipt.CompletedUnixNanos < s.ValidFromUnixNanos || p.Receipt.CompletedUnixNanos >= s.ValidUntilUnixNanos {
			add(CodeSigner, "signer_authorization", "live signer authorization mismatch")
		}
	}
	if len(p.SignerAuthorization.SignerPublicKey) != ed25519.PublicKeySize || len(p.Receipt.Signature) != ed25519.SignatureSize {
		add(CodeSignature, "receipt.signature", "invalid Ed25519 key/signature size")
	} else if raw, _, e := ReceiptSigningDigest(p); e != nil || !ed25519.Verify(ed25519.PublicKey(p.SignerAuthorization.SignerPublicKey), raw, p.Receipt.Signature) {
		add(CodeSignature, "receipt.signature", "signature verification failed")
	}
	d, e := Digest(p)
	if e != nil {
		add(CodeMalformed, "package", e.Error())
	} else {
		r.PackageDigest = d
		r.PackageID, _ = PackageID(p)
	}
	r.Valid = len(r.Failures) == 0
	return r
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func outcomeDigest(p Package) string {
	parts := []string{p.Outcome.Kind, p.Escrow.ReservationDigest, p.Escrow.EscrowID, p.Escrow.JobID, p.Quote.QuoteID, p.Outcome.ChargedAtomic, p.Outcome.RefundedAtomic, p.Outcome.ReleaseDigest, p.Outcome.ReasonCode, p.Outcome.DisputeDigest, p.Outcome.DisputeOutcome}
	return digestBytes("tos.atos.portable-proof-outcome.v1", []byte(strings.Join(parts, "\x00")))
}

var _ = errors.New
var _ = fmt.Sprintf
