package agentcommerce

import (
	"errors"
	"strings"
)

type OutcomeErrorCode string

type OutcomeErrorDescriptorV1 struct {
	Code       OutcomeErrorCode `json:"code" cbor:"1,keyasint"`
	RetryClass string           `json:"retry_class" cbor:"2,keyasint"`
	Meaning    string           `json:"meaning" cbor:"3,keyasint"`
}

type OutcomeErrorRegistryDocumentV1 struct {
	Schema  string                     `json:"schema" cbor:"1,keyasint"`
	Version uint32                     `json:"version" cbor:"2,keyasint"`
	Entries []OutcomeErrorDescriptorV1 `json:"entries" cbor:"3,keyasint"`
}

const (
	OutcomeErrMalformed          OutcomeErrorCode = "outcome.malformed"
	OutcomeErrResourceBound      OutcomeErrorCode = "outcome.resource_bound"
	OutcomeErrUnsupportedProfile OutcomeErrorCode = "outcome.unsupported_profile"
	OutcomeErrDigestBinding      OutcomeErrorCode = "outcome.digest_binding"
	OutcomeErrAuthority          OutcomeErrorCode = "outcome.authority"
	OutcomeErrConflict           OutcomeErrorCode = "outcome.conflict"
	OutcomeErrPrivacy            OutcomeErrorCode = "outcome.privacy"
	OutcomeErrStaleWriter        OutcomeErrorCode = "outcome.stale_writer"
	OutcomeErrUnavailable        OutcomeErrorCode = "outcome.unavailable"
)

// OutcomeErrorRegistryV1 is the released, language-neutral error registry.
// Keep entries sorted by code so generated artifacts and independent
// implementations compare exact bytes instead of prose or Go error strings.
func OutcomeErrorRegistryV1() OutcomeErrorRegistryDocumentV1 {
	return OutcomeErrorRegistryDocumentV1{Schema: "tos.operation-outcome-error-registry.v1", Version: 1,
		Entries: []OutcomeErrorDescriptorV1{
			{OutcomeErrAuthority, "after_external_state_change", "Required signature, historical authority, qualification, or finality proof is absent or invalid."},
			{OutcomeErrConflict, "never_same_bytes", "The same immutable identity is already bound to different canonical bytes or state."},
			{OutcomeErrDigestBinding, "never_same_bytes", "Canonical bytes, digest, size, request, envelope, artifact, or receipt binding does not match."},
			{OutcomeErrMalformed, "never_same_bytes", "The request is structurally invalid and no narrower released error applies."},
			{OutcomeErrPrivacy, "after_external_state_change", "Audience, purpose, disclosure, encryption, or retrieval policy denies the operation."},
			{OutcomeErrResourceBound, "after_external_state_change", "A released byte, item, proof-work, queue, storage, or query bound was exceeded."},
			{OutcomeErrStaleWriter, "after_external_state_change", "The Writer Fence is expired, superseded, out of scope, or below the authority high-water."},
			{OutcomeErrUnavailable, "exact_query_or_retry", "Required retained bytes, authority history, sink resolution, or evidence is currently unavailable."},
			{OutcomeErrUnsupportedProfile, "after_external_state_change", "A required profile or version has no released verifier in this implementation."},
		},
	}
}

type OutcomeProtocolError struct {
	Code  OutcomeErrorCode
	Cause error
}

func (failure *OutcomeProtocolError) Error() string {
	if failure == nil {
		return ""
	}
	return string(failure.Code) + ": " + failure.Cause.Error()
}
func (failure *OutcomeProtocolError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

// OutcomeErrorCodeOf is the stable error boundary for language-neutral APIs.
// Implementations return the code on the wire and keep Cause in local logs;
// callers must not authorize behavior from error text.
func OutcomeErrorCodeOf(err error) OutcomeErrorCode {
	if err == nil {
		return ""
	}
	var typed *OutcomeProtocolError
	if errors.As(err, &typed) && typed.Code != "" {
		return typed.Code
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "stale writer") || strings.Contains(message, "writer fence"):
		return OutcomeErrStaleWriter
	case strings.Contains(message, "unknown") || strings.Contains(message, "unsupported") || strings.Contains(message, "no released verifier"):
		return OutcomeErrUnsupportedProfile
	case strings.Contains(message, "authority") || strings.Contains(message, "qualification") || strings.Contains(message, "signature") || strings.Contains(message, "proof"):
		return OutcomeErrAuthority
	case strings.Contains(message, "digest") || strings.Contains(message, "binding") || strings.Contains(message, "canonical") || strings.Contains(message, "checksum"):
		return OutcomeErrDigestBinding
	case strings.Contains(message, "oversized") || strings.Contains(message, "too many") || strings.Contains(message, "bound") || strings.Contains(message, "capacity"):
		return OutcomeErrResourceBound
	case strings.Contains(message, "audience") || strings.Contains(message, "recipient") || strings.Contains(message, "visibility") || strings.Contains(message, "disclosure"):
		return OutcomeErrPrivacy
	case strings.Contains(message, "conflict") || strings.Contains(message, "duplicate") || strings.Contains(message, "replay"):
		return OutcomeErrConflict
	case strings.Contains(message, "unavailable") || strings.Contains(message, "missing") || strings.Contains(message, "absent"):
		return OutcomeErrUnavailable
	default:
		return OutcomeErrMalformed
	}
}

func NewOutcomeProtocolError(code OutcomeErrorCode, cause error) error {
	if code == "" || cause == nil {
		return errors.New("invalid outcome protocol error")
	}
	return &OutcomeProtocolError{Code: code, Cause: cause}
}
