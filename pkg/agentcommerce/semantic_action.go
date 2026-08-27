// Package agentcommerce implements the business-neutral objects shared by
// Intent discovery, Agreement authorization, execution, and settlement.
package agentcommerce

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	SemanticActionRegistryVersion uint16 = 1
	SemanticActionEntryVersion    uint16 = 1
	MaxSemanticFieldBytes                = 1 << 20
	MaxActionRequestBytes                = 4 << 20
)

var canonicalDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type SemanticFieldType string

const (
	SemanticID       SemanticFieldType = "id"
	SemanticDigest32 SemanticFieldType = "digest32"
	SemanticU64      SemanticFieldType = "u64"
	SemanticKind     SemanticFieldType = "kind"
	SemanticState    SemanticFieldType = "state"
)

type SuccessorPolicy string

const (
	SuccessorNone              SuccessorPolicy = "none"
	SuccessorTerminal          SuccessorPolicy = "terminal_successor"
	SuccessorAuthorityInstance SuccessorPolicy = "authority_instance"
)

type SemanticFieldDefinition struct {
	Name string            `json:"field_name"`
	Type SemanticFieldType `json:"field_type"`
}

type SemanticActionEntry struct {
	RegistryVersion uint16                    `json:"registry_version"`
	EntryVersion    uint16                    `json:"entry_version"`
	ActionKind      string                    `json:"action_kind"`
	DomainTag       string                    `json:"domain_tag"`
	Fields          []SemanticFieldDefinition `json:"ordered_semantic_fields"`
	SuccessorPolicy SuccessorPolicy           `json:"successor_policy"`
}

// SemanticValue is deliberately typed. Callers cannot smuggle a display
// string into a digest or an integer into an identifier and obtain a valid ID.
type SemanticValue struct {
	typeOf SemanticFieldType
	bytes  []byte
}

// SemanticFieldValue is the language-neutral transport form used when a
// side-effect broker, rather than the coordinating process, must independently
// derive and verify a stable semantic action identity. Exactly one of Text and
// Number is populated according to Type.
type SemanticFieldValue struct {
	Name   string            `json:"name"`
	Type   SemanticFieldType `json:"type"`
	Text   string            `json:"text,omitempty"`
	Number *uint64           `json:"number,omitempty"`
}

func ID(value string) SemanticValue       { return semanticText(SemanticID, value) }
func Kind(value string) SemanticValue     { return semanticText(SemanticKind, value) }
func State(value string) SemanticValue    { return semanticText(SemanticState, value) }
func Digest32(value string) SemanticValue { return semanticText(SemanticDigest32, value) }

func U64(value uint64) SemanticValue {
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, value)
	return SemanticValue{typeOf: SemanticU64, bytes: encoded}
}

func semanticText(kind SemanticFieldType, value string) SemanticValue {
	return SemanticValue{typeOf: kind, bytes: []byte(value)}
}

// ExportSemanticFields returns a stable, registry-ordered transport form.
// It deliberately requires an action kind so extra and missing fields fail at
// the same boundary as DeriveStableActionID.
func ExportSemanticFields(actionKind string, values map[string]SemanticValue) ([]SemanticFieldValue, error) {
	entry, found := semanticActionRegistry[actionKind]
	if !found || len(values) != len(entry.Fields) {
		return nil, errors.New("semantic action field set is invalid")
	}
	if _, _, err := DeriveStableActionID(actionKind, values); err != nil {
		return nil, err
	}
	result := make([]SemanticFieldValue, 0, len(entry.Fields))
	for _, definition := range entry.Fields {
		value := values[definition.Name]
		wire := SemanticFieldValue{Name: definition.Name, Type: definition.Type}
		if definition.Type == SemanticU64 {
			number := binary.BigEndian.Uint64(value.bytes)
			wire.Number = &number
		} else {
			wire.Text = string(value.bytes)
		}
		result = append(result, wire)
	}
	return result, nil
}

// ImportSemanticFields rejects non-registry order, duplicate names, ambiguous
// text/number encodings, and any type substitution before rebuilding values.
func ImportSemanticFields(actionKind string, fields []SemanticFieldValue) (map[string]SemanticValue, error) {
	entry, found := semanticActionRegistry[actionKind]
	if !found || len(fields) != len(entry.Fields) {
		return nil, errors.New("semantic action field set is invalid")
	}
	values := make(map[string]SemanticValue, len(fields))
	for index, definition := range entry.Fields {
		wire := fields[index]
		if wire.Name != definition.Name || wire.Type != definition.Type {
			return nil, errors.New("semantic action fields are not in canonical registry order")
		}
		if definition.Type == SemanticU64 {
			if wire.Number == nil || wire.Text != "" {
				return nil, errors.New("u64 semantic field has an ambiguous encoding")
			}
			values[wire.Name] = U64(*wire.Number)
		} else {
			if wire.Number != nil || wire.Text == "" {
				return nil, errors.New("text semantic field has an ambiguous encoding")
			}
			values[wire.Name] = semanticText(wire.Type, wire.Text)
		}
	}
	if _, _, err := DeriveStableActionID(actionKind, values); err != nil {
		return nil, err
	}
	return values, nil
}

func (v SemanticValue) cloneBytes() []byte { return append([]byte(nil), v.bytes...) }

var semanticActionRegistry = buildSemanticActionRegistry()

func buildSemanticActionRegistry() map[string]SemanticActionEntry {
	entries := []SemanticActionEntry{
		entry("publication.publish", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("carrier_id", SemanticID), f("intent_object_id", SemanticID), f("revision", SemanticU64), f("operation_digest", SemanticDigest32)),
		entry("authority.instance", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("purpose_kind", SemanticKind), f("mandate_digest", SemanticDigest32), f("allocation_request_digest", SemanticDigest32), f("authority_allocation_sequence", SemanticU64)),
		entry("publication.reply", SuccessorAuthorityInstance, f("owner_id", SemanticID), f("agent_id", SemanticID), f("carrier_id", SemanticID), f("parent_operation_digest", SemanticDigest32), f("authority_instance_id", SemanticDigest32)),
		entry("publication.withdraw", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("carrier_id", SemanticID), f("intent_object_id", SemanticID), f("withdrawn_revision", SemanticU64), f("withdrawal_operation_digest", SemanticDigest32)),
		entry("messenger.contact", SuccessorAuthorityInstance, f("owner_id", SemanticID), f("agent_id", SemanticID), f("recipient_agent_id", SemanticID), f("intent_reference_digest", SemanticDigest32), f("authority_instance_id", SemanticDigest32)),
		entry("messenger.send", SuccessorAuthorityInstance, f("owner_id", SemanticID), f("agent_id", SemanticID), f("recipient_set_digest", SemanticDigest32), f("conversation_scope_digest", SemanticDigest32), f("authority_instance_id", SemanticDigest32)),
		entry("agreement.propose", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("recipient_set_digest", SemanticDigest32)),
		entry("agreement.authorize", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("authority_subject_digest", SemanticDigest32), f("predicate_set_digest", SemanticDigest32), f("evidence_profile_digest", SemanticDigest32)),
		entry("agreement.withdraw", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("proposal_action_id", SemanticDigest32)),
		entry("provider.offer", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("demand_mutation_digest", SemanticDigest32), f("buyer_agent_id", SemanticID), f("provider_offer_id", SemanticID), f("binding_digest", SemanticDigest32)),
		entry("portfolio.reserve", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("reservation_scope_digest", SemanticDigest32), f("target_revision", SemanticU64)),
		entry("portfolio.release", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("reservation_id", SemanticDigest32), f("target_revision", SemanticU64), f("terminal_evidence_set_digest", SemanticDigest32)),
		entry("schedule.entry.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("schedule_entry_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("execution_id", SemanticDigest32), f("expected_state_revision", SemanticU64), f("target_state", SemanticState), f("target_dispatch_generation", SemanticU64)),
		entry("schedule.dependency.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("upstream_agreement_digest", SemanticDigest32), f("upstream_obligation_id", SemanticID), f("downstream_agreement_digest", SemanticDigest32), f("downstream_obligation_id", SemanticID), f("dependency_type", SemanticKind), f("dependency_class", SemanticKind), f("transition_kind", SemanticKind), f("graph_base_revision", SemanticU64)),
		entry("execution.slot", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("execution_obligation_id", SemanticID), f("canonical_plan_digest", SemanticDigest32), f("accepted_input_manifest_digest", SemanticDigest32), f("attempt_index", SemanticU64), f("predecessor_terminal_resolution_digest", SemanticDigest32)),
		entry("execution.prepare", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("execution_id", SemanticDigest32)),
		entry("execution.start", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("execution_id", SemanticDigest32)),
		entry("executor.effect", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("execution_id", SemanticDigest32), f("plan_effect_id", SemanticID), f("effect_profile_digest", SemanticDigest32), f("target_digest", SemanticDigest32), f("operation_kind", SemanticKind), f("effect_semantic_key_digest", SemanticDigest32)),
		entry("credential.issue", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("execution_id", SemanticDigest32), f("recipient_id", SemanticID), f("capability_descriptor_digest", SemanticDigest32)),
		entry("disclosure.release", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("recipient_id", SemanticID), f("content_digest", SemanticDigest32), f("purpose_digest", SemanticDigest32)),
		entry("content.upload", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("handoff_id", SemanticID), f("sender_id", SemanticID), f("receiver_id", SemanticID), f("content_manifest_digest", SemanticDigest32)),
		entry("content.delete", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("handoff_id", SemanticID), f("content_manifest_digest", SemanticDigest32), f("retention_policy_digest", SemanticDigest32)),
		entry("delivery.release", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("recipient_id", SemanticID), f("deliverable_manifest_digest", SemanticDigest32)),
		entry("gift.send", SuccessorAuthorityInstance, f("owner_id", SemanticID), f("agent_id", SemanticID), f("authority_instance_id", SemanticDigest32), f("recipient_id", SemanticID), f("network_id", SemanticID), f("asset_digest", SemanticDigest32), f("amount_atomic", SemanticID), f("destination_digest", SemanticDigest32)),
		entry("payment.direct", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_instance_id", SemanticDigest32), f("payer_id", SemanticID), f("payee_id", SemanticID), f("network_id", SemanticID), f("asset_digest", SemanticDigest32), f("amount_atomic", SemanticID), f("destination_digest", SemanticDigest32)),
		entry("payment.domain-bound", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_instance_id", SemanticDigest32), f("payer_id", SemanticID), f("payee_id", SemanticID), f("network_domain_digest", SemanticDigest32), f("asset_digest", SemanticDigest32), f("amount_atomic", SemanticID), f("destination_digest", SemanticDigest32)),
		entry("settlement.external", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_instance_id", SemanticDigest32), f("adapter_profile_digest", SemanticDigest32), f("payer_id", SemanticID), f("payee_id", SemanticID), f("system_id", SemanticID), f("asset_digest", SemanticDigest32), f("amount_digest", SemanticDigest32), f("destination_digest", SemanticDigest32)),
		entry("escrow.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("quote_commitment", SemanticDigest32), f("escrow_account_id", SemanticID), f("transition_kind", SemanticKind), f("expected_state_digest", SemanticDigest32)),
		entry("billing.materialize", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("agreement_obligation_id", SemanticID), f("sequence", SemanticU64)),
		entry("billing.resolve", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("obligation_instance_id", SemanticDigest32), f("target_state", SemanticState), f("evidence_set_digest", SemanticDigest32)),
		entry("accounting.record", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("entry_id", SemanticDigest32), f("classification", SemanticKind), f("evidence_set_digest", SemanticDigest32)),
		entry("reconcile.apply", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("scope_digest", SemanticDigest32), f("base_revision", SemanticU64), f("evidence_cut_digest", SemanticDigest32)),
		entry("commercial.quote.issue", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("quote_request_digest", SemanticDigest32), f("recipient_set_digest", SemanticDigest32), f("authority_instance_id", SemanticDigest32), f("offer_terms_digest", SemanticDigest32)),
		entry("commercial.quote.close", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("authority_instance_id", SemanticDigest32), f("reservation_id", SemanticDigest32), f("expected_offer_state_revision", SemanticU64), f("target_state", SemanticState)),
		entry("conditional.claim.ingress", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("claim_id", SemanticID), f("claim_revision", SemanticU64)),
		entry("conditional.claim.submit", SuccessorAuthorityInstance, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("authority_instance_id", SemanticDigest32), f("claim_body_digest", SemanticDigest32)),
		entry("conditional.claim-filing.close", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("claim_admission_log_id", SemanticID), f("expected_coverage_revision", SemanticU64), f("expected_claim_filing_state_revision", SemanticU64), f("filing_cutoff_unix", SemanticU64), f("target_state", SemanticState)),
		entry("conditional.claim-decision.admit", SuccessorNone, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("claim_id", SemanticID), f("admission_mode", SemanticKind), f("source_claim_revision", SemanticU64), f("source_claim_state_revision", SemanticU64), f("source_head_digest", SemanticDigest32), f("decision_sequence", SemanticU64), f("mode_specific_identity_digest", SemanticDigest32)),
		entry("conditional.claim.decide", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("authorized_claim_envelope_digest", SemanticDigest32), f("decision_application_token_id", SemanticDigest32), f("expected_coverage_revision", SemanticU64), f("expected_claim_revision", SemanticU64), f("expected_claim_state_revision", SemanticU64), f("decision_sequence", SemanticU64), f("decision_revision", SemanticU64), f("target_state", SemanticState)),
		entry("conditional.claim.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("claim_id", SemanticID), f("expected_claim_state_revision", SemanticU64), f("transition_kind", SemanticKind), f("target_state", SemanticState), f("evidence_set_digest", SemanticDigest32)),
		entry("conditional.obligation.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("expected_state_revision", SemanticU64), f("target_state", SemanticState), f("evidence_set_digest", SemanticDigest32)),
		entry("collateral.transition", SuccessorTerminal, f("owner_id", SemanticID), f("agent_id", SemanticID), f("agreement_body_digest", SemanticDigest32), f("obligation_id", SemanticID), f("collateral_position_id", SemanticID), f("transition_binding_digest", SemanticDigest32), f("expected_state_revision", SemanticU64), f("transition_kind", SemanticKind)),
	}
	registry := make(map[string]SemanticActionEntry, len(entries))
	for _, candidate := range entries {
		if _, duplicate := registry[candidate.ActionKind]; duplicate {
			panic("duplicate semantic action registry entry: " + candidate.ActionKind)
		}
		registry[candidate.ActionKind] = candidate
	}
	return registry
}

func f(name string, kind SemanticFieldType) SemanticFieldDefinition {
	return SemanticFieldDefinition{Name: name, Type: kind}
}

func entry(kind string, successor SuccessorPolicy, fields ...SemanticFieldDefinition) SemanticActionEntry {
	return SemanticActionEntry{
		RegistryVersion: SemanticActionRegistryVersion,
		EntryVersion:    SemanticActionEntryVersion,
		ActionKind:      kind,
		DomainTag:       "tos.semantic-action." + kind + ".v1",
		Fields:          fields,
		SuccessorPolicy: successor,
	}
}

// SemanticActionRegistry returns a defensive copy ordered by action kind.
func SemanticActionRegistry() map[string]SemanticActionEntry {
	output := make(map[string]SemanticActionEntry, len(semanticActionRegistry))
	for kind, candidate := range semanticActionRegistry {
		candidate.Fields = append([]SemanticFieldDefinition(nil), candidate.Fields...)
		output[kind] = candidate
	}
	return output
}

// DeriveStableActionID implements SemanticActionIdentityPreimageV1. The map is
// only a lookup surface: fields are always emitted in the released registry
// order and any missing or additional field fails closed.
func DeriveStableActionID(actionKind string, values map[string]SemanticValue) (string, []byte, error) {
	candidate, found := semanticActionRegistry[actionKind]
	if !found {
		return "", nil, errors.New("unknown semantic action kind")
	}
	if len(values) != len(candidate.Fields) {
		return "", nil, errors.New("semantic action field set is incomplete or contains extras")
	}
	var preimage bytes.Buffer
	preimage.Write([]byte{'T', 'O', 'S', '-', 'S', 'A', 'I', 0})
	writeU16(&preimage, candidate.RegistryVersion)
	writeU16(&preimage, candidate.EntryVersion)
	if err := writeLP16(&preimage, []byte(candidate.DomainTag)); err != nil {
		return "", nil, err
	}
	if err := writeLP16(&preimage, []byte(candidate.ActionKind)); err != nil {
		return "", nil, err
	}
	writeU16(&preimage, uint16(len(candidate.Fields)))
	for _, definition := range candidate.Fields {
		value, ok := values[definition.Name]
		if !ok || value.typeOf != definition.Type {
			return "", nil, fmt.Errorf("semantic action field %q is missing or has the wrong type", definition.Name)
		}
		canonical, err := canonicalSemanticValue(definition, value)
		if err != nil {
			return "", nil, fmt.Errorf("semantic action field %q: %w", definition.Name, err)
		}
		if err := writeLP16(&preimage, []byte(definition.Name)); err != nil {
			return "", nil, err
		}
		if err := writeLP32(&preimage, canonical); err != nil {
			return "", nil, err
		}
	}
	encoded := preimage.Bytes()
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), append([]byte(nil), encoded...), nil
}

func canonicalSemanticValue(definition SemanticFieldDefinition, value SemanticValue) ([]byte, error) {
	raw := value.cloneBytes()
	if len(raw) == 0 || len(raw) > MaxSemanticFieldBytes {
		return nil, errors.New("value length is invalid")
	}
	switch definition.Type {
	case SemanticID:
		if len(raw) > 4096 || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
			return nil, errors.New("identifier is not canonical UTF-8")
		}
		if definition.Name == "amount_atomic" && !canonicalUnsignedDecimal(string(raw)) {
			return nil, errors.New("atomic amount is not a canonical unsigned integer")
		}
		return raw, nil
	case SemanticDigest32:
		text := string(raw)
		if !canonicalDigestPattern.MatchString(text) {
			return nil, errors.New("digest is not canonical sha256 text")
		}
		decoded, err := hex.DecodeString(strings.TrimPrefix(text, "sha256:"))
		if err != nil || len(decoded) != sha256.Size {
			return nil, errors.New("digest is invalid")
		}
		return decoded, nil
	case SemanticU64:
		if len(raw) != 8 {
			return nil, errors.New("u64 is not eight bytes")
		}
		return raw, nil
	case SemanticKind, SemanticState:
		if !canonicalLowerToken(string(raw)) {
			return nil, errors.New("token is not canonical lower-case ASCII")
		}
		return raw, nil
	default:
		return nil, errors.New("unknown semantic field type")
	}
}

func canonicalLowerToken(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range []byte(value) {
		if (character >= 'a' && character <= 'z') || (index > 0 && character >= '0' && character <= '9') || (index > 0 && strings.ContainsRune("._-", rune(character))) {
			continue
		}
		return false
	}
	return true
}

func canonicalUnsignedDecimal(value string) bool {
	if value == "0" {
		return true
	}
	if len(value) == 0 || len(value) > 78 || value[0] == '0' {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// ExactRequestDigest binds the exact canonical side-effect body independently
// from writer, lease, transport, session, route, retry, and wall-clock data.
func ExactRequestDigest(canonicalActionRequestBody []byte) (string, error) {
	if len(canonicalActionRequestBody) == 0 || len(canonicalActionRequestBody) > MaxActionRequestBytes {
		return "", errors.New("canonical action request body has invalid size")
	}
	hasher := sha256.New()
	hasher.Write([]byte("tos.action-request.v1\x00"))
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonicalActionRequestBody)))
	hasher.Write(length[:])
	hasher.Write(canonicalActionRequestBody)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func writeU16(output *bytes.Buffer, value uint16) {
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], value)
	output.Write(encoded[:])
}

func writeLP16(output *bytes.Buffer, value []byte) error {
	if len(value) > int(^uint16(0)) {
		return errors.New("lp16 value is too large")
	}
	writeU16(output, uint16(len(value)))
	output.Write(value)
	return nil
}

func writeLP32(output *bytes.Buffer, value []byte) error {
	if uint64(len(value)) > uint64(^uint32(0)) {
		return errors.New("lp32 value is too large")
	}
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], uint32(len(value)))
	output.Write(encoded[:])
	output.Write(value)
	return nil
}
