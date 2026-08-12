// Package receiptcommitment owns the language-independent Execution Receipt
// signature and digest representation. Protobuf is transport only.
package receiptcommitment

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

const Domain = "tos.atos.execution-receipt.v2"

type digest struct {
	Algorithm string `json:"algorithm"`
	Value     []byte `json:"value"`
}
type money struct {
	Amount string `json:"amount"`
	Asset  string `json:"asset"`
}
type networkAmount struct {
	Asset        string `json:"asset"`
	AtomicAmount string `json:"atomic_amount"`
}
type artifact struct {
	ID        string `json:"artifact_id"`
	MediaType string `json:"media_type"`
	SizeBytes uint64 `json:"size_bytes"`
	Digest    digest `json:"digest"`
}
type usage struct {
	InputBytes      uint64 `json:"input_bytes"`
	OutputBytes     uint64 `json:"output_bytes"`
	InputTokens     uint64 `json:"input_tokens"`
	OutputTokens    uint64 `json:"output_tokens"`
	ExecutionMillis uint64 `json:"execution_millis"`
}
type aipow struct {
	CapabilityClass          string `json:"capability_class"`
	Unit                     string `json:"unit"`
	WorkUnits                uint64 `json:"work_units"`
	RateCardVersion          string `json:"rate_card_version"`
	EvidenceLevel            string `json:"evidence_level"`
	EarnerIdentityCommitment digest `json:"earner_identity_commitment"`
	PayerIdentityCommitment  digest `json:"payer_identity_commitment"`
	ChallengeTask            bool   `json:"challenge_task"`
}
type Value struct {
	ReceiptID             string        `json:"receipt_id"`
	QuoteID               string        `json:"quote_id"`
	EscrowID              string        `json:"escrow_id"`
	JobID                 string        `json:"job_id"`
	PrincipalID           string        `json:"principal_id"`
	ProviderID            string        `json:"provider_id"`
	CapabilityID          string        `json:"capability_id"`
	CapabilityVersion     string        `json:"capability_version"`
	TrustMode             string        `json:"trust_mode"`
	ProofProfile          string        `json:"proof_profile"`
	Result                string        `json:"result"`
	InputCommitment       digest        `json:"input_commitment"`
	OutputCommitment      digest        `json:"output_commitment"`
	UsageCommitment       digest        `json:"usage_commitment"`
	Artifacts             []artifact    `json:"artifacts"`
	Usage                 usage         `json:"usage"`
	ClientCharge          money         `json:"client_charge"`
	NetworkCharge         networkAmount `json:"network_charge"`
	ExecutionSignerID     string        `json:"execution_signer_id"`
	SignerAuthorizationID string        `json:"signer_authorization_id"`
	SignatureAlgorithm    string        `json:"signature_algorithm"`
	StartedUnixMillis     int64         `json:"started_unix_millis"`
	CompletedUnixMillis   int64         `json:"completed_unix_millis"`
	ErrorCode             string        `json:"error_code"`
	Aipow                 *aipow        `json:"aipow,omitempty"`
}

type Claims struct {
	ReceiptID, QuoteID, EscrowID, JobID, PrincipalID, ProviderID, CapabilityID, CapabilityVersion, TrustMode, ProofProfile, Result, InputCommitment, OutputCommitment, UsageCommitment, ExecutionSignerID, SignerAuthorizationID, SignatureAlgorithm, NetworkChargeAtomic string
	StartedUnixMillis, CompletedUnixMillis                                                                                                                                                                                                                                int64
}

func text(v digest) string { return v.Algorithm + ":" + hex.EncodeToString(v.Value) }
func Parse(data []byte) (Claims, error) {
	var v Value
	if err := codec.Unmarshal(data, &v); err != nil {
		return Claims{}, err
	}
	return Claims{v.ReceiptID, v.QuoteID, v.EscrowID, v.JobID, v.PrincipalID, v.ProviderID, v.CapabilityID, v.CapabilityVersion, v.TrustMode, v.ProofProfile, v.Result, text(v.InputCommitment), text(v.OutputCommitment), text(v.UsageCommitment), v.ExecutionSignerID, v.SignerAuthorizationID, v.SignatureAlgorithm, v.NetworkCharge.AtomicAmount, v.StartedUnixMillis, v.CompletedUnixMillis}, nil
}
func Proto(data []byte) (*atostosv1.ExecutionReceiptEnvelope, error) {
	var v Value
	if err := codec.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	r := &atostosv1.ExecutionReceiptEnvelope{ReceiptId: v.ReceiptID, QuoteId: v.QuoteID, EscrowId: v.EscrowID, JobId: v.JobID, PrincipalId: v.PrincipalID, ProviderId: v.ProviderID, CapabilityId: v.CapabilityID, CapabilityVersion: v.CapabilityVersion, TrustMode: atostosv1.TrustMode(atostosv1.TrustMode_value[v.TrustMode]), ProofProfile: atostosv1.ProofProfile(atostosv1.ProofProfile_value[v.ProofProfile]), Result: atostosv1.ExecutionResult(atostosv1.ExecutionResult_value[v.Result]), InputCommitment: protoDigest(v.InputCommitment), OutputCommitment: protoDigest(v.OutputCommitment), UsageCommitment: protoDigest(v.UsageCommitment), Usage: &atostosv1.Usage{InputBytes: v.Usage.InputBytes, OutputBytes: v.Usage.OutputBytes, InputTokens: v.Usage.InputTokens, OutputTokens: v.Usage.OutputTokens, ExecutionMillis: v.Usage.ExecutionMillis}, ClientCharge: &atostosv1.Money{Amount: v.ClientCharge.Amount, Currency: v.ClientCharge.Asset}, NetworkCharge: &atostosv1.NetworkAmount{Asset: v.NetworkCharge.Asset, AtomicAmount: v.NetworkCharge.AtomicAmount}, ExecutionSignerId: v.ExecutionSignerID, SignerAuthorizationId: v.SignerAuthorizationID, SignatureAlgorithm: v.SignatureAlgorithm, StartedUnixMillis: v.StartedUnixMillis, CompletedUnixMillis: v.CompletedUnixMillis, ErrorCode: v.ErrorCode}
	for _, a := range v.Artifacts {
		r.Artifacts = append(r.Artifacts, &atostosv1.ArtifactCommitment{ArtifactId: a.ID, ContentType: a.MediaType, SizeBytes: a.SizeBytes, Digest: protoDigest(a.Digest)})
	}
	if v.Aipow != nil {
		r.Aipow = &atostosv1.AipowWorkAttribution{CapabilityClass: v.Aipow.CapabilityClass, Unit: v.Aipow.Unit, WorkUnits: v.Aipow.WorkUnits, RateCardVersion: v.Aipow.RateCardVersion, EvidenceLevel: atostosv1.AipowEvidenceLevel(atostosv1.AipowEvidenceLevel_value[v.Aipow.EvidenceLevel]), EarnerIdentityCommitment: protoDigest(v.Aipow.EarnerIdentityCommitment), PayerIdentityCommitment: protoDigest(v.Aipow.PayerIdentityCommitment), ChallengeTask: v.Aipow.ChallengeTask}
	}
	return r, nil
}
func protoDigest(v digest) *atostosv1.Digest {
	return &atostosv1.Digest{Algorithm: v.Algorithm, Value: append([]byte(nil), v.Value...)}
}

func dg(v *atostosv1.Digest) digest {
	if v == nil {
		return digest{}
	}
	return digest{v.Algorithm, append([]byte(nil), v.Value...)}
}
func CanonicalValue(r *atostosv1.ExecutionReceiptEnvelope) (Value, error) {
	if r == nil {
		return Value{}, errors.New("receipt is required")
	}
	if err := quotecommitment.RejectUnknown(r); err != nil {
		return Value{}, err
	}
	v := Value{ReceiptID: r.ReceiptId, QuoteID: r.QuoteId, EscrowID: r.EscrowId, JobID: r.JobId, PrincipalID: r.PrincipalId, ProviderID: r.ProviderId, CapabilityID: r.CapabilityId, CapabilityVersion: r.CapabilityVersion, TrustMode: r.TrustMode.String(), ProofProfile: r.ProofProfile.String(), Result: r.Result.String(), InputCommitment: dg(r.InputCommitment), OutputCommitment: dg(r.OutputCommitment), UsageCommitment: dg(r.UsageCommitment), ExecutionSignerID: r.ExecutionSignerId, SignerAuthorizationID: r.SignerAuthorizationId, SignatureAlgorithm: strings.ToLower(r.SignatureAlgorithm), StartedUnixMillis: r.StartedUnixMillis, CompletedUnixMillis: r.CompletedUnixMillis, ErrorCode: r.ErrorCode}
	if r.ClientCharge != nil {
		v.ClientCharge = money{r.ClientCharge.Amount, r.ClientCharge.Currency}
	}
	if r.NetworkCharge != nil {
		v.NetworkCharge = networkAmount{r.NetworkCharge.Asset, r.NetworkCharge.AtomicAmount}
	}
	if r.Usage != nil {
		v.Usage = usage{r.Usage.InputBytes, r.Usage.OutputBytes, r.Usage.InputTokens, r.Usage.OutputTokens, r.Usage.ExecutionMillis}
	}
	for _, a := range r.Artifacts {
		if a == nil {
			return Value{}, errors.New("nil artifact")
		}
		v.Artifacts = append(v.Artifacts, artifact{a.ArtifactId, a.ContentType, a.SizeBytes, dg(a.Digest)})
	}
	if r.Aipow != nil {
		v.Aipow = &aipow{r.Aipow.CapabilityClass, r.Aipow.Unit, r.Aipow.WorkUnits, r.Aipow.RateCardVersion, r.Aipow.EvidenceLevel.String(), dg(r.Aipow.EarnerIdentityCommitment), dg(r.Aipow.PayerIdentityCommitment), r.Aipow.ChallengeTask}
	}
	return v, nil
}
func Bytes(r *atostosv1.ExecutionReceiptEnvelope) ([]byte, error) {
	v, e := CanonicalValue(r)
	if e != nil {
		return nil, e
	}
	return codec.Marshal(v)
}
func Digest(r *atostosv1.ExecutionReceiptEnvelope) (string, error) {
	v, e := CanonicalValue(r)
	if e != nil {
		return "", e
	}
	return codec.Digest(Domain, v)
}
func SigningBytes(r *atostosv1.ExecutionReceiptEnvelope) ([]byte, error) {
	d, e := Digest(r)
	if e != nil {
		return nil, e
	}
	raw, e := hex.DecodeString(strings.TrimPrefix(d, "sha256:"))
	if e != nil {
		return nil, fmt.Errorf("decode receipt digest: %w", e)
	}
	return raw, nil
}
