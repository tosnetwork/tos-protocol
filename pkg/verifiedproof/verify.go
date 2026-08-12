package verifiedproof

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/disputecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/poscommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"math/big"
	"strings"
	"time"
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
	Kind      string    `json:"kind"`
	ObjectID  string    `json:"object_id"`
	Digest    string    `json:"digest"`
	Reference Reference `json:"reference"`
	Package   *Package  `json:"package,omitempty"`
}
type EvidenceObservation struct {
	Found               bool   `json:"found"`
	Network             string `json:"network"`
	Kind                string `json:"kind"`
	ObjectID            string `json:"object_id"`
	Digest              string `json:"digest"`
	Reference           string `json:"reference"`
	Finalized           bool   `json:"finalized"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
}
type SignerObservation struct {
	Found               bool   `json:"found"`
	Revoked             bool   `json:"revoked"`
	RevokedUnixNanos    int64  `json:"revoked_unix_nanos"`
	Network             string `json:"network"`
	AuthorizationID     string `json:"authorization_id"`
	ProviderID          string `json:"provider_id"`
	CapabilityID        string `json:"capability_id"`
	CapabilityVersion   string `json:"capability_version"`
	SignerID            string `json:"signer_id"`
	Reference           string `json:"reference"`
	SignatureAlgorithm  string `json:"signature_algorithm"`
	PublicKey           []byte `json:"public_key"`
	ValidFromUnixNanos  int64  `json:"valid_from_unix_nanos"`
	ValidUntilUnixNanos int64  `json:"valid_until_unix_nanos"`
	FinalizedCheckpoint uint64 `json:"finalized_checkpoint"`
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
	r := Result{Version: p.Version, Network: p.NetworkID, QuoteID: p.Quote.QuoteID, JobID: p.Escrow.JobID, CapabilityID: p.Capability.CapabilityID, EscrowID: p.Escrow.EscrowID, Outcome: p.Outcome.Kind}
	hasExecution := p.Outcome.Kind != "requester_release"
	if hasExecution && (p.SignerAuthorization == nil || p.Receipt == nil || p.ProofOfService == nil) {
		r.Failures = []Failure{{CodeMalformed, "receipt", "execution evidence is required for this outcome"}}
		return r
	}
	if !hasExecution && (p.SignerAuthorization != nil || p.Receipt != nil || p.ProofOfService != nil) {
		r.Failures = []Failure{{CodeOutcome, "outcome", "pre-execution release must omit execution evidence"}}
		return r
	}
	if hasExecution {
		r.ExecutionSignerID = p.SignerAuthorization.ExecutionSignerID
	}
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
	if p.Quote.TrustMode != "verified" || p.Quote.ProofProfile != "tos_verified_v1" || p.Quote.SettlementBackend != "tos" || p.Quote.SettlementAsset != "TOS" || p.Quote.AssetDecimals != 9 || p.Quote.FeesAtomic != "0" || strings.TrimSpace(p.Escrow.FundingModel) == "" {
		add(CodeTuple, "quote", "unsupported Verified commercial tuple")
	}
	validateIdentity := func(field, expectedAgent string, identity Identity) {
		if identity.AgentID != expectedAgent || identity.CanonicalURI == "" || identity.Assurance == "" || strings.EqualFold(identity.Assurance, "self_asserted") || len(identity.Controllers) != 1 {
			add(CodeTuple, field, "incomplete independently anchored identity tuple")
			return
		}
		if _, err := toschain.CanonicalAddress(identity.Controllers[0]); err != nil {
			add(CodeTuple, field+".controllers", "invalid canonical TOS controller")
		}
		if err := ValidateReference(p.NetworkID, identity.IdentityRef); err != nil {
			add(CodeFinality, field+".identity_ref", err.Error())
		}
	}
	validateIdentity("requester_identity", p.RequesterAgentID, p.RequesterIdentity)
	validateIdentity("provider_identity", p.ProviderAgentID, p.ProviderIdentity)
	digests := map[string]string{"manifest_digest": p.Capability.ManifestDigest, "quote.commitment_digest": p.Quote.CommitmentDigest, "quote.terms_digest": p.Quote.TermsDigest, "quote.dispute_policy_digest": p.Quote.DisputePolicyDigest, "escrow.reservation_digest": p.Escrow.ReservationDigest}
	if hasExecution {
		digests["receipt.receipt_digest"] = p.Receipt.ReceiptDigest
		digests["receipt.input_commitment"] = p.Receipt.InputCommitment
		digests["receipt.output_commitment"] = p.Receipt.OutputCommitment
		digests["receipt.usage_commitment"] = p.Receipt.UsageCommitment
		digests["proof_of_service.evidence_digest"] = p.ProofOfService.EvidenceDigest
		digests["proof_of_service.content_digest"] = p.ProofOfService.ContentDigest
	}
	for field, value := range digests {
		if !validDigest(value) {
			add(CodeDigest, field, "invalid SHA-256 digest")
		}
	}
	if !validTVMCodeHash(p.Escrow.ContractCodeHash) {
		add(CodeDigest, "escrow.contract_code_hash", "invalid TVM cell SHA-256 code hash")
	}
	if d, err := codec.DigestCanonical(quotecommitment.Domain, p.Quote.CanonicalCBOR); err != nil || d != p.Quote.CommitmentDigest {
		add(CodeDigest, "quote.canonical_cbor", "canonical Quote bytes do not match commitment digest")
	} else if q, err := quotecommitment.Parse(p.Quote.CanonicalCBOR); err != nil {
		add(CodeMalformed, "quote.canonical_cbor", "canonical Quote tuple is malformed")
	} else if subtotal, e1 := decimalToAtomic(q.Subtotal.Amount, q.AssetDecimals); e1 != nil || q.Subtotal.Asset != p.Quote.SettlementAsset || subtotal != p.Quote.SubtotalAtomic || func() bool {
		fees, e := decimalToAtomic(q.Fees.Amount, q.AssetDecimals)
		return e != nil || q.Fees.Asset != p.Quote.SettlementAsset || fees != p.Quote.FeesAtomic
	}() || func() bool {
		total, e := decimalToAtomic(q.TotalMax.Amount, q.AssetDecimals)
		return e != nil || q.TotalMax.Asset != p.Quote.SettlementAsset || total != p.Quote.TotalMaxAtomic
	}() || q.QuoteID != p.Quote.QuoteID || q.NetworkID != p.NetworkID || q.Domain != p.GatewayDomain || q.PrincipalID != p.PrincipalID || q.RequesterAgentID != p.RequesterAgentID || q.ProviderID != p.ProviderID || q.CapabilityID != p.Capability.CapabilityID || q.CapabilityVersion != p.Capability.CapabilityVersion || q.ManifestDigest != p.Capability.ManifestDigest || q.TermsDigest != p.Quote.TermsDigest || q.DisputePolicyDigest != p.Quote.DisputePolicyDigest || q.TrustMode != "TRUST_MODE_VERIFIED" || q.ProofProfile != "PROOF_PROFILE_TOS_VERIFIED_V1" || q.SettlementBackend != p.Quote.SettlementBackend || q.SettlementAsset != p.Quote.SettlementAsset || q.AssetDecimals != p.Quote.AssetDecimals || q.AcceptanceDeadlineUnixMillis*int64(time.Millisecond) != p.Quote.AcceptanceDeadlineUnixNanos || q.ExpiresUnixMillis*int64(time.Millisecond) != p.Quote.QuoteExpiryUnixNanos || q.ExecutionDeadlineUnixMillis*int64(time.Millisecond) != p.Quote.ExecutionDeadlineUnixNanos || q.UnderlyingServiceQuoteRef != p.Quote.UnderlyingServiceQuoteRef || (p.SignerAuthorization != nil && (q.SignerAuthorizationID != p.SignerAuthorization.AuthorizationID || q.SignerAuthorizationRef.Network != p.SignerAuthorization.AuthorizationRef.Network || q.SignerAuthorizationRef.Reference != p.SignerAuthorization.AuthorizationRef.Reference)) {
		add(CodeTuple, "quote.canonical_cbor", "canonical Quote tuple differs from package")
	}
	if d, err := codec.DigestCanonical(escrowcommitment.Domain, p.Escrow.CanonicalCBOR); err != nil || d != p.Escrow.ReservationDigest {
		add(CodeDigest, "escrow.canonical_cbor", "canonical reservation bytes do not match digest")
	} else if e, err := escrowcommitment.Parse(p.Escrow.CanonicalCBOR); err != nil || e.EscrowID != p.Escrow.EscrowID || e.JobID != p.Escrow.JobID || e.QuoteID != p.Quote.QuoteID || e.NetworkID != p.NetworkID || e.Domain != p.GatewayDomain || e.QuoteCommitmentDigest != p.Quote.CommitmentDigest || e.QuoteCommitmentRef.Network != p.Quote.CommitmentRef.Network || e.QuoteCommitmentRef.Reference != p.Quote.CommitmentRef.Reference || e.PrincipalID != p.PrincipalID || e.RequesterAgentID != p.RequesterAgentID || e.ProviderID != p.ProviderID || e.CapabilityID != p.Capability.CapabilityID || e.CapabilityVersion != p.Capability.CapabilityVersion || e.ManifestDigest != p.Capability.ManifestDigest || e.ReservedAtomic() != p.Escrow.ReservedAtomic || e.Reserve.Asset != p.Quote.SettlementAsset || e.AssetDecimals != p.Quote.AssetDecimals || e.FundingModel != p.Escrow.FundingModel || e.TrustMode != "TRUST_MODE_VERIFIED" || e.ProofProfile != "PROOF_PROFILE_TOS_VERIFIED_V1" || e.SettlementBackend != p.Quote.SettlementBackend || e.SettlementAsset != p.Quote.SettlementAsset || e.AcceptanceDeadlineUnixMillis*int64(time.Millisecond) != p.Quote.AcceptanceDeadlineUnixNanos || e.ExecutionDeadlineUnixMillis*int64(time.Millisecond) != p.Quote.ExecutionDeadlineUnixNanos || e.EscrowDeadlineUnixMillis*int64(time.Millisecond) != p.Escrow.EscrowDeadlineUnixNanos || e.UnderlyingServiceQuoteRef != p.Quote.UnderlyingServiceQuoteRef || e.DisputePolicyDigest != p.Quote.DisputePolicyDigest || e.TermsDigest != p.Quote.TermsDigest || e.Subtotal.AtomicAmount != p.Quote.SubtotalAtomic || e.Fees.AtomicAmount != p.Quote.FeesAtomic || (p.SignerAuthorization != nil && (e.SignerAuthorizationID != p.SignerAuthorization.AuthorizationID || e.SignerAuthorizationRef.Network != p.SignerAuthorization.AuthorizationRef.Network || e.SignerAuthorizationRef.Reference != p.SignerAuthorization.AuthorizationRef.Reference)) {
		add(CodeTuple, "escrow.canonical_cbor", "canonical reservation tuple differs from package")
	}
	if hasExecution {
		if d, err := codec.DigestCanonical(poscommitment.Domain, p.ProofOfService.CanonicalCBOR); err != nil || d != p.ProofOfService.EvidenceDigest {
			add(CodeDigest, "proof_of_service.canonical_cbor", "canonical Proof-of-Service bytes do not match authority digest")
		} else if claims, err := poscommitment.Parse(p.ProofOfService.CanonicalCBOR); err != nil || claims.EvidenceID != p.ProofOfService.EvidenceID || claims.ReceiptID != p.Receipt.ReceiptID || claims.ProviderID != p.ProviderID || claims.CapabilityID != p.Capability.CapabilityID || claims.CapabilityVersion != p.Capability.CapabilityVersion || claims.EvidenceDigest != p.ProofOfService.ContentDigest {
			add(CodeTuple, "proof_of_service.canonical_cbor", "canonical Proof-of-Service tuple differs from package")
		}
	}
	amounts := map[string]string{"subtotal": p.Quote.SubtotalAtomic, "fees": p.Quote.FeesAtomic, "total_max": p.Quote.TotalMaxAtomic, "reserved": p.Escrow.ReservedAtomic, "outcome.charge": p.Outcome.ChargedAtomic, "outcome.refund": p.Outcome.RefundedAtomic}
	if hasExecution {
		amounts["receipt.charge"] = p.Receipt.ChargedAtomic
	}
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
		receiptMustEqualOutcome := hasExecution && p.Outcome.Kind == "provider_settlement"
		if new(big.Int).Add(parsed["subtotal"], parsed["fees"]).Cmp(parsed["total_max"]) != 0 || parsed["total_max"].Cmp(parsed["reserved"]) != 0 || (receiptMustEqualOutcome && parsed["receipt.charge"].Cmp(parsed["outcome.charge"]) != 0) || new(big.Int).Add(parsed["outcome.charge"], parsed["outcome.refund"]).Cmp(parsed["reserved"]) != 0 {
			add(CodeOutcome, "outcome", "monetary conservation failed")
		}
	}
	if hasExecution && (p.Receipt.CompletedUnixNanos < p.Receipt.StartedUnixNanos || p.Receipt.CompletedUnixNanos < p.SignerAuthorization.ValidFromUnixNanos || p.Receipt.CompletedUnixNanos >= p.SignerAuthorization.ValidUntilUnixNanos) {
		add(CodeSigner, "receipt.completed_unix_nanos", "receipt outside signer validity")
	}
	if hasExecution {
		if _, expectedReceiptDigest, err := ReceiptSigningDigest(p); err != nil || expectedReceiptDigest != p.Receipt.ReceiptDigest {
			add(CodeDigest, "receipt.receipt_digest", "receipt digest does not match canonical receipt tuple")
		}
		if c, err := receiptcommitment.Parse(p.Receipt.CanonicalCBOR); err != nil {
			add(CodeMalformed, "receipt.canonical_cbor", err.Error())
		} else if c.ReceiptID != p.Receipt.ReceiptID || c.QuoteID != p.Quote.QuoteID || c.EscrowID != p.Escrow.EscrowID || c.JobID != p.Escrow.JobID || c.PrincipalID != p.PrincipalID || c.ProviderID != p.ProviderID || c.CapabilityID != p.Capability.CapabilityID || c.CapabilityVersion != p.Capability.CapabilityVersion || c.TrustMode != "TRUST_MODE_VERIFIED" || c.ProofProfile != "PROOF_PROFILE_TOS_VERIFIED_V1" || strings.TrimPrefix(strings.ToLower(c.Result), "execution_result_") != strings.ToLower(p.Receipt.Result) || c.InputCommitment != p.Receipt.InputCommitment || c.OutputCommitment != p.Receipt.OutputCommitment || c.UsageCommitment != p.Receipt.UsageCommitment || c.ExecutionSignerID != p.SignerAuthorization.ExecutionSignerID || c.SignerAuthorizationID != p.SignerAuthorization.AuthorizationID || c.SignatureAlgorithm != strings.ToLower(p.Receipt.SignatureAlgorithm) || c.SignatureAlgorithm != strings.ToLower(p.SignerAuthorization.SignatureAlgorithm) || c.StartedUnixMillis*int64(time.Millisecond) != p.Receipt.StartedUnixNanos || c.CompletedUnixMillis*int64(time.Millisecond) != p.Receipt.CompletedUnixNanos || c.NetworkChargeAtomic != p.Receipt.ChargedAtomic {
			add(CodeTuple, "receipt.canonical_cbor", "signed Receipt tuple differs from package")
		}
	}
	switch p.Outcome.Kind {
	case "provider_settlement":
		if p.Outcome.ReleaseDigest != "" || p.Outcome.DisputeDigest != "" {
			add(CodeOutcome, "outcome", "settlement has release/dispute fields")
		}
	case "requester_release":
		if !validDigest(p.Outcome.ReleaseDigest) || p.Outcome.ReasonCode == "" || p.Outcome.DisputeDigest != "" || p.Outcome.ChargedAtomic != "0" || p.Outcome.RefundedAtomic != p.Escrow.ReservedAtomic {
			add(CodeOutcome, "outcome", "invalid release tuple")
		}
	case "dispute_resolution":
		if !validDigest(p.Outcome.DisputeDigest) || !validDigest(p.Outcome.ResolutionDigest) || p.Outcome.DisputeOutcome == "" || p.Outcome.ReleaseDigest != "" || len(p.Outcome.ResolutionCBOR) == 0 {
			add(CodeOutcome, "outcome", "invalid dispute tuple")
		}
		resolution, resolutionErr := disputecommitment.ParseResolution(p.Outcome.ResolutionCBOR)
		resolutionDigest, digestErr := codec.DigestCanonical(disputecommitment.ResolutionDomain, p.Outcome.ResolutionCBOR)
		if resolutionErr != nil || digestErr != nil || resolutionDigest != p.Outcome.ResolutionDigest || resolution.NetworkID != p.NetworkID || resolution.GatewayDomain != p.GatewayDomain || resolution.EscrowID != p.Escrow.EscrowID || resolution.JobID != p.Escrow.JobID || resolution.QuoteID != p.Quote.QuoteID || resolution.ReceiptID != p.Receipt.ReceiptID || resolution.DisputeDigest != p.Outcome.DisputeDigest || resolution.Outcome != p.Outcome.DisputeOutcome || resolution.Reserved.Asset != p.Quote.SettlementAsset || resolution.Reserved.AtomicAmount != p.Escrow.ReservedAtomic || resolution.ProviderPayout.AtomicAmount != p.Outcome.ChargedAtomic || resolution.RequesterRefund.AtomicAmount != p.Outcome.RefundedAtomic || resolution.ProviderPayout.Asset != p.Quote.SettlementAsset || resolution.RequesterRefund.Asset != p.Quote.SettlementAsset {
			add(CodeOutcome, "outcome.resolution_cbor", "canonical dispute resolution tuple differs from package")
		}
		if err := ValidateReference(p.NetworkID, p.Outcome.DisputeRef); err != nil {
			add(CodeFinality, "outcome.dispute_ref", err.Error())
		}
		if err := ValidateReference(p.NetworkID, p.Outcome.ResolutionRef); err != nil {
			add(CodeFinality, "outcome.resolution_ref", err.Error())
		}
	default:
		add(CodeOutcome, "outcome.kind", "unsupported outcome")
	}
	refs := []struct {
		name, kind, id, digest string
		ref                    Reference
	}{{"requester_identity_ref", "principal-binding", p.PrincipalID, p.RequesterAgentID, p.RequesterIdentityRef}, {"requester_identity.identity_ref", "identity", p.RequesterAgentID, "", p.RequesterIdentity.IdentityRef}, {"provider_identity_ref", "principal-binding", p.ProviderID, p.ProviderAgentID, p.ProviderIdentityRef}, {"provider_identity.identity_ref", "identity", p.ProviderAgentID, "", p.ProviderIdentity.IdentityRef}, {"capability.ownership_ref", "capability-ownership", p.Capability.CapabilityID, p.Capability.ManifestDigest, p.Capability.OwnershipRef}, {"quote.commitment_ref", "verified-quote", p.Quote.QuoteID, p.Quote.CommitmentDigest, p.Quote.CommitmentRef}, {"escrow.reservation_ref", "task-escrow-reservation", p.Escrow.EscrowID, p.Escrow.ReservationDigest, p.Escrow.ReservationRef}, {"escrow.contract_ref", "task-escrow", p.Escrow.EscrowID, p.Escrow.ReservationDigest, p.Escrow.ContractRef}, {"outcome.outcome_ref", p.Outcome.Kind, p.Escrow.EscrowID, outcomeDigest(p), p.Outcome.OutcomeRef}}
	if hasExecution {
		refs = append(refs, struct {
			name, kind, id, digest string
			ref                    Reference
		}{"signer.authorization_ref", "execution-signer", p.SignerAuthorization.AuthorizationID, "", p.SignerAuthorization.AuthorizationRef}, struct {
			name, kind, id, digest string
			ref                    Reference
		}{"receipt.receipt_ref", "verified-receipt", p.Receipt.ReceiptID, p.Receipt.ReceiptDigest, p.Receipt.ReceiptRef}, struct {
			name, kind, id, digest string
			ref                    Reference
		}{"proof_of_service.evidence_ref", "proof-of-service", p.ProofOfService.EvidenceID, p.ProofOfService.EvidenceDigest, p.ProofOfService.EvidenceRef})
	}
	if p.Outcome.Kind == "dispute_resolution" {
		refs = append(refs, struct {
			name, kind, id, digest string
			ref                    Reference
		}{"outcome.resolution_ref", "dispute-resolution", func() string {
			resolution, _ := disputecommitment.ParseResolution(p.Outcome.ResolutionCBOR)
			return resolution.DisputeID
		}(), p.Outcome.ResolutionDigest, p.Outcome.ResolutionRef})
	}
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
			o, e := v.Observer.Observe(ctx, EvidenceRequest{Kind: x.kind, ObjectID: x.id, Digest: x.digest, Reference: x.ref, Package: &p})
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
	} else if hasExecution {
		s, e := v.Observer.ResolveSigner(ctx, p)
		if e != nil {
			add(CodeUnavailable, "signer_authorization", e.Error())
		} else if !s.Found || s.Revoked && s.RevokedUnixNanos <= p.Receipt.CompletedUnixNanos || s.AuthorizationID != p.SignerAuthorization.AuthorizationID || s.ProviderID != p.ProviderID || s.CapabilityID != p.Capability.CapabilityID || s.CapabilityVersion != p.Capability.CapabilityVersion || s.SignerID != p.SignerAuthorization.ExecutionSignerID || s.Reference != p.SignerAuthorization.AuthorizationRef.Reference || !strings.EqualFold(s.SignatureAlgorithm, "ed25519") || !equalBytes(s.PublicKey, p.SignerAuthorization.SignerPublicKey) || p.Receipt.CompletedUnixNanos < s.ValidFromUnixNanos || p.Receipt.CompletedUnixNanos >= s.ValidUntilUnixNanos {
			add(CodeSigner, "signer_authorization", "live signer authorization mismatch")
		}
	}
	if hasExecution && (len(p.SignerAuthorization.SignerPublicKey) != ed25519.PublicKeySize || len(p.Receipt.Signature) != ed25519.SignatureSize) {
		add(CodeSignature, "receipt.signature", "invalid Ed25519 key/signature size")
	} else if hasExecution {
		if raw, _, e := ReceiptSigningDigest(p); e != nil || !ed25519.Verify(ed25519.PublicKey(p.SignerAuthorization.SignerPublicKey), raw, p.Receipt.Signature) {
			add(CodeSignature, "receipt.signature", "signature verification failed")
		}
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

func decimalToAtomic(value string, decimals uint32) (string, error) {
	if value == "" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
		return "", errors.New("invalid decimal amount")
	}
	parts := strings.Split(value, ".")
	if len(parts) > 2 || parts[0] == "" {
		return "", errors.New("invalid decimal amount")
	}
	fraction := ""
	if len(parts) == 2 {
		fraction = parts[1]
	}
	if len(fraction) > int(decimals) {
		return "", errors.New("amount exceeds asset precision")
	}
	for len(fraction) < int(decimals) {
		fraction += "0"
	}
	n, ok := new(big.Int).SetString(parts[0]+fraction, 10)
	if !ok || n.Sign() < 0 {
		return "", errors.New("invalid decimal amount")
	}
	return n.String(), nil
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
	type outcomeCommitment struct {
		Kind, ReservationDigest, EscrowID, JobID, QuoteID           string
		ChargedAtomic, RefundedAtomic                               string
		ReleaseDigest, ReasonCode                                   string
		DisputeDigest, DisputeRef, ResolutionDigest, DisputeOutcome string
	}
	digest, err := codec.Digest("tos.atos.portable-proof-outcome.v1", outcomeCommitment{
		p.Outcome.Kind, p.Escrow.ReservationDigest, p.Escrow.EscrowID, p.Escrow.JobID,
		p.Quote.QuoteID, p.Outcome.ChargedAtomic, p.Outcome.RefundedAtomic,
		p.Outcome.ReleaseDigest, p.Outcome.ReasonCode, p.Outcome.DisputeDigest, p.Outcome.DisputeRef.Reference, p.Outcome.ResolutionDigest, p.Outcome.DisputeOutcome,
	})
	if err != nil {
		return ""
	}
	return digest
}

var _ = errors.New
var _ = fmt.Sprintf
