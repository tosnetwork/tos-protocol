package trustedcapability

import (
	"crypto/sha256"
	"errors"
)

// ActionOutcomeEvidenceV1 is a narrowly scoped, signed sink observation used
// only to reconcile an already-ambiguous side effect. It never authorizes a
// new action and cannot alter the original semantic identity.
type ActionOutcomeEvidenceV1 struct {
	SchemaVersion      uint16   `cbor:"1,keyasint" json:"schema_version"`
	EvidenceID         []byte   `cbor:"2,keyasint" json:"evidence_id"`
	OwnerID            []byte   `cbor:"3,keyasint" json:"owner_id"`
	AgentID            []byte   `cbor:"4,keyasint" json:"agent_id"`
	ActionKind         string   `cbor:"5,keyasint" json:"action_kind"`
	ActionID           []byte   `cbor:"6,keyasint" json:"action_id"`
	ExactRequestDigest []byte   `cbor:"7,keyasint" json:"exact_request_digest"`
	ExecutionID        *[]byte  `cbor:"8,keyasint" json:"execution_id"`
	Disposition        string   `cbor:"9,keyasint" json:"disposition"`
	ResultDigest       []byte   `cbor:"10,keyasint" json:"result_digest"`
	SinkAuthorityID    []byte   `cbor:"11,keyasint" json:"sink_authority_id"`
	SinkEpoch          uint64   `cbor:"12,keyasint" json:"sink_epoch"`
	ObservedAtUnix     uint64   `cbor:"13,keyasint" json:"observed_at_unix"`
	NotBeforeUnix      uint64   `cbor:"14,keyasint" json:"not_before_unix"`
	ExpiresAtUnix      uint64   `cbor:"15,keyasint" json:"expires_at_unix"`
	Extensions         [][]byte `cbor:"16,keyasint" json:"extensions"`
}

func ValidateActionOutcomeEvidence(value ActionOutcomeEvidenceV1, now uint64) error {
	if value.SchemaVersion != SchemaVersion || len(value.EvidenceID) != 16 || len(value.OwnerID) == 0 || len(value.AgentID) == 0 ||
		(value.ActionKind != "mcp-tool" && value.ActionKind != "capability-use") || len(value.ActionID) != sha256.Size ||
		len(value.ExactRequestDigest) != sha256.Size || len(value.ResultDigest) != sha256.Size || len(value.SinkAuthorityID) == 0 ||
		value.SinkEpoch == 0 || value.ObservedAtUnix == 0 || value.NotBeforeUnix == 0 || value.NotBeforeUnix > value.ObservedAtUnix ||
		value.ObservedAtUnix >= value.ExpiresAtUnix || now < value.NotBeforeUnix || now >= value.ExpiresAtUnix {
		return errors.New("action outcome evidence is incomplete, stale, or unsupported")
	}
	if value.Disposition != "succeeded" && value.Disposition != "failed" && value.Disposition != "killed" && value.Disposition != "rejected" {
		return errors.New("action outcome evidence disposition is not terminal")
	}
	if value.ActionKind == "mcp-tool" && value.ExecutionID != nil || value.ActionKind == "capability-use" && (value.ExecutionID == nil || len(*value.ExecutionID) != sha256.Size) {
		return errors.New("action outcome execution identity is inconsistent")
	}
	return nil
}
