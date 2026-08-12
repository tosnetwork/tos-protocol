// Package poscommitment defines the language-independent Proof-of-Service
// authority commitment. Protobuf is transport only.
package poscommitment

import (
	"errors"
	"fmt"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
)

const Domain = "tos.atos.proof-of-service.v1"

type digest struct {
	Algorithm string `json:"algorithm"`
	Value     []byte `json:"value"`
}
type amount struct {
	Asset        string `json:"asset"`
	AtomicAmount string `json:"atomic_amount"`
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
	EvidenceID         string `json:"evidence_id"`
	ReceiptID          string `json:"receipt_id"`
	ProviderID         string `json:"provider_id"`
	CapabilityID       string `json:"capability_id"`
	CapabilityVersion  string `json:"capability_version"`
	Result             string `json:"result"`
	LatencyMillis      uint64 `json:"latency_millis"`
	SettlementVolume   amount `json:"settlement_volume"`
	Disputed           bool   `json:"disputed"`
	DisputeOutcome     string `json:"dispute_outcome"`
	EvidenceDigest     digest `json:"evidence_digest"`
	ObservedUnixMillis int64  `json:"observed_unix_millis"`
	Aipow              *aipow `json:"aipow,omitempty"`
}
type Claims struct {
	EvidenceID, ReceiptID, ProviderID, CapabilityID, CapabilityVersion, Result, EvidenceDigest string
	LatencyMillis                                                                              uint64
	ObservedUnixMillis                                                                         int64
}

func dg(v *atostosv1.Digest) digest {
	if v == nil {
		return digest{}
	}
	return digest{Algorithm: v.Algorithm, Value: append([]byte(nil), v.Value...)}
}

func CanonicalValue(v *atostosv1.ProofOfServiceEvidenceInput) (Value, error) {
	if v == nil {
		return Value{}, errors.New("proof-of-service evidence is required")
	}
	if err := quotecommitment.RejectUnknown(v); err != nil {
		return Value{}, err
	}
	out := Value{EvidenceID: v.EvidenceId, ReceiptID: v.ReceiptId, ProviderID: v.ProviderId, CapabilityID: v.CapabilityId, CapabilityVersion: v.CapabilityVersion, Result: v.Result.String(), LatencyMillis: v.LatencyMillis, Disputed: v.Disputed, DisputeOutcome: v.DisputeOutcome, EvidenceDigest: dg(v.EvidenceDigest), ObservedUnixMillis: v.ObservedUnixMillis}
	if v.SettlementVolume != nil {
		out.SettlementVolume = amount{v.SettlementVolume.Asset, v.SettlementVolume.AtomicAmount}
	}
	if v.Aipow != nil {
		out.Aipow = &aipow{v.Aipow.CapabilityClass, v.Aipow.Unit, v.Aipow.WorkUnits, v.Aipow.RateCardVersion, v.Aipow.EvidenceLevel.String(), dg(v.Aipow.EarnerIdentityCommitment), dg(v.Aipow.PayerIdentityCommitment), v.Aipow.ChallengeTask}
	}
	return out, nil
}
func Bytes(v *atostosv1.ProofOfServiceEvidenceInput) ([]byte, error) {
	x, e := CanonicalValue(v)
	if e != nil {
		return nil, e
	}
	return codec.Marshal(x)
}
func Digest(v *atostosv1.ProofOfServiceEvidenceInput) (string, error) {
	x, e := CanonicalValue(v)
	if e != nil {
		return "", e
	}
	return codec.Digest(Domain, x)
}
func Parse(data []byte) (Claims, error) {
	var v Value
	if e := codec.Unmarshal(data, &v); e != nil {
		return Claims{}, e
	}
	return Claims{v.EvidenceID, v.ReceiptID, v.ProviderID, v.CapabilityID, v.CapabilityVersion, v.Result, v.EvidenceDigest.Algorithm + ":" + fmt.Sprintf("%x", v.EvidenceDigest.Value), v.LatencyMillis, v.ObservedUnixMillis}, nil
}
func Proto(data []byte) (*atostosv1.ProofOfServiceEvidenceInput, error) {
	var v Value
	if e := codec.Unmarshal(data, &v); e != nil {
		return nil, e
	}
	out := &atostosv1.ProofOfServiceEvidenceInput{EvidenceId: v.EvidenceID, ReceiptId: v.ReceiptID, ProviderId: v.ProviderID, CapabilityId: v.CapabilityID, CapabilityVersion: v.CapabilityVersion, Result: atostosv1.ExecutionResult(atostosv1.ExecutionResult_value[v.Result]), LatencyMillis: v.LatencyMillis, SettlementVolume: &atostosv1.NetworkAmount{Asset: v.SettlementVolume.Asset, AtomicAmount: v.SettlementVolume.AtomicAmount}, Disputed: v.Disputed, DisputeOutcome: v.DisputeOutcome, EvidenceDigest: &atostosv1.Digest{Algorithm: v.EvidenceDigest.Algorithm, Value: append([]byte(nil), v.EvidenceDigest.Value...)}, ObservedUnixMillis: v.ObservedUnixMillis}
	if v.Aipow != nil {
		out.Aipow = &atostosv1.AipowWorkAttribution{CapabilityClass: v.Aipow.CapabilityClass, Unit: v.Aipow.Unit, WorkUnits: v.Aipow.WorkUnits, RateCardVersion: v.Aipow.RateCardVersion, EvidenceLevel: atostosv1.AipowEvidenceLevel(atostosv1.AipowEvidenceLevel_value[v.Aipow.EvidenceLevel]), EarnerIdentityCommitment: &atostosv1.Digest{Algorithm: v.Aipow.EarnerIdentityCommitment.Algorithm, Value: append([]byte(nil), v.Aipow.EarnerIdentityCommitment.Value...)}, PayerIdentityCommitment: &atostosv1.Digest{Algorithm: v.Aipow.PayerIdentityCommitment.Algorithm, Value: append([]byte(nil), v.Aipow.PayerIdentityCommitment.Value...)}, ChallengeTask: v.Aipow.ChallengeTask}
	}
	return out, nil
}
