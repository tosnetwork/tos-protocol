package agentcommerce

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	OperationOutcomeSchemaV1                uint16 = 1
	OperationOutcomeEventDomain                    = "tos.operation-outcome.event-body.v1"
	OperationOutcomeEvidenceManifestDomain         = "tos.operation-outcome.evidence-manifest.v1"
	OperationOutcomeExtensionSetDomain             = "tos.operation-outcome.extension-set.v1"
	OperationOutcomeAssertionPayloadDomain         = "tos.operation-outcome.assertion-payload.v1"
	OperationOutcomeProfileDescriptorDomain        = "tos.operation-outcome.profile-descriptor.v1"
	MaxOutcomeCausalPredecessors                   = 8
	MaxOutcomeAuthorityProofRefs                   = 16
	MaxOutcomeEvidenceItems                        = 64
	MaxOutcomeExtensions                           = 32
	MaxOutcomeAssertionPayloadBytes                = 1 << 20
	MaxOutcomeEvidenceObjectBytes                  = 64 << 20
	MaxOutcomeAuthorityProofBytes                  = 8 << 10
	MaxOutcomeAuthorityMaterialBytes               = 64 << 10
)

type OperationOutcomeEventKind string

const (
	OutcomeObservation             OperationOutcomeEventKind = "observation"
	OutcomeTransitionObservation   OperationOutcomeEventKind = "transition_observation"
	OutcomeTerminalObservation     OperationOutcomeEventKind = "terminal_observation"
	OutcomeAvailabilityObservation OperationOutcomeEventKind = "availability_observation"
	OutcomeCohortCheckpoint        OperationOutcomeEventKind = "cohort_checkpoint"
)

type OutcomeSubjectRefV1 struct {
	SubjectProfileURI string `json:"subject_profile_uri"`
	SubjectID         string `json:"subject_id"`
}

type OutcomeAssertionRefV1 struct {
	NetworkID               string `json:"network_id"`
	ActorAgentID            string `json:"actor_agent_id"`
	OperationID             string `json:"operation_id"`
	OperationEnvelopeDigest string `json:"operation_envelope_digest"`
}

type OperationOutcomeEventBodyV1 struct {
	SchemaVersion                  uint16                    `json:"schema_version"`
	EventKind                      OperationOutcomeEventKind `json:"event_kind"`
	PrimarySubjectRef              OutcomeSubjectRefV1       `json:"primary_subject_ref"`
	CausalPredecessorAssertionRefs []OutcomeAssertionRefV1   `json:"causal_predecessor_assertion_refs"`
	AssertionProfileURI            string                    `json:"assertion_profile_uri"`
	AssertionPayloadDigest         string                    `json:"assertion_payload_digest"`
	AssertionPayloadSize           uint64                    `json:"assertion_payload_size"`
	EvidenceManifestDigest         string                    `json:"evidence_manifest_digest"`
	ExtensionSetDigest             string                    `json:"extension_set_digest"`
}

type OutcomeAuthorityProofRefV1 struct {
	ProofProfileURI string `json:"proof_profile_uri"`
	ObjectDigest    string `json:"object_digest"`
	CanonicalSize   uint64 `json:"canonical_size"`
}

type OutcomeEvidenceItemV1 struct {
	EvidenceRole                   string `json:"evidence_role"`
	EvidenceProfileURI             string `json:"evidence_profile_uri"`
	SourceObjectProfileURI         string `json:"source_object_profile_uri"`
	SourceObjectDigest             string `json:"source_object_digest"`
	ObjectDigest                   string `json:"object_digest"`
	CanonicalSize                  uint64 `json:"canonical_size"`
	MediaType                      string `json:"media_type"`
	IssuerDescriptor               string `json:"issuer_descriptor"`
	SubjectDescriptor              string `json:"subject_descriptor"`
	ClaimedObservationTimeUnix     uint64 `json:"claimed_observation_time_unix"`
	AuthorityTimeProofDigest       string `json:"authority_time_proof_digest"`
	IssuerQualificationProofDigest string `json:"issuer_qualification_proof_digest"`
	Visibility                     string `json:"visibility"`
	AudienceDigest                 string `json:"audience_digest"`
	RetentionPolicyDigest          string `json:"retention_policy_digest"`
	RetrievalPolicyDigest          string `json:"retrieval_policy_digest"`
}

type OutcomeEvidenceManifestV1 struct {
	SchemaVersion      uint16                       `json:"schema_version"`
	ManifestPurpose    string                       `json:"manifest_purpose"`
	AuthorityProofRefs []OutcomeAuthorityProofRefV1 `json:"authority_proof_refs"`
	EvidenceItems      []OutcomeEvidenceItemV1      `json:"evidence_items"`
}

type OutcomeExtensionV1 struct {
	ProfileURI     string `json:"profile_uri"`
	CanonicalValue []byte `json:"canonical_value"`
}

type OutcomeExtensionSetV1 struct {
	SchemaVersion uint16               `json:"schema_version"`
	Extensions    []OutcomeExtensionV1 `json:"extensions"`
}

// OperationOutcomeArtifactBundleV1 contains the exact content-addressed
// objects needed to interpret an event. Referenced large evidence objects stay
// in the selected evidence store; authority proof material is bounded and may
// be retained here for offline verification.
type OperationOutcomeArtifactBundleV1 struct {
	AssertionPayload []byte                            `json:"assertion_payload"`
	EvidenceManifest OutcomeEvidenceManifestV1         `json:"evidence_manifest"`
	ExtensionSet     OutcomeExtensionSetV1             `json:"extension_set"`
	AuthorityProofs  []OutcomeAuthorityProofMaterialV1 `json:"authority_proofs"`
}

type AuthorityTimeProofV1 struct {
	ProfileURI              string `json:"profile_uri"`
	AuthorityOrCheckpointID string `json:"authority_or_checkpoint_id"`
	IntervalStartUnix       uint64 `json:"interval_start_unix"`
	IntervalEndUnix         uint64 `json:"interval_end_unix"`
	FinalizedHighWater      uint64 `json:"finalized_high_water"`
	FinalizedRootDigest     string `json:"finalized_root_digest"`
	ProofDigest             string `json:"proof_digest"`
}

type IssuerQualificationProofV1 struct {
	RootAuthorityID              string `json:"root_authority_id"`
	IssuerAgentID                string `json:"issuer_agent_id"`
	IssuerKeyDigest              string `json:"issuer_key_digest"`
	OrderedDelegationChainDigest string `json:"ordered_delegation_chain_digest"`
	ScopeProfileURI              string `json:"scope_profile_uri"`
	SubjectScopeDigest           string `json:"subject_scope_digest"`
	ValidFromUnix                uint64 `json:"valid_from_unix"`
	ValidUntilUnix               uint64 `json:"valid_until_unix"`
	RevocationHandleSetDigest    string `json:"revocation_handle_set_digest"`
	AuthorityTimeProofDigest     string `json:"authority_time_proof_digest"`
	RevocationHighWater          uint64 `json:"revocation_high_water"`
	RevocationRootDigest         string `json:"revocation_root_digest"`
}

const (
	OutcomeAuthorityTimeProofProfileV1       = "tos.outcome.authority-time-proof.v1"
	OutcomeIssuerQualificationProofProfileV1 = "tos.outcome.issuer-qualification-proof.v1"
	OutcomeAuthorityProofObjectDomain        = "tos.operation-outcome.authority-proof-object.v1"
)

// OutcomeAuthorityProofMaterialV1 supplies already retrieved, bounded proof
// bytes to authority verification. Structural verification never performs a
// network fetch; callers decide how bytes are retrieved and authenticated.
type OutcomeAuthorityProofMaterialV1 struct {
	ProofProfileURI string `json:"proof_profile_uri"`
	CanonicalObject []byte `json:"canonical_object"`
}

// OutcomeEvidenceAuthorityVerifierV1 is the profile-specific cryptographic
// and historical authority boundary. The generic protocol code checks all
// byte, digest, cardinality, time and cross-object bindings before invoking it.
// Implementations must resolve delegation and revocation at authorityTime,
// never at a publisher-selected wall-clock time.
type OutcomeEvidenceAuthorityVerifierV1 interface {
	VerifyOutcomeAuthorityTime(AuthorityTimeProofV1, OutcomeEvidenceItemV1, time.Time) error
	VerifyOutcomeIssuerQualification(IssuerQualificationProofV1, OutcomeEvidenceItemV1, AuthorityTimeProofV1, time.Time) error
}

type OutcomeAuthorityAssessmentV1 struct {
	AuthorityQualified      bool     `json:"authority_qualified"`
	VerifiedEvidenceDigests []string `json:"verified_evidence_digests"`
	AuthorityTimeHighWater  uint64   `json:"authority_time_high_water"`
}

func OutcomeAuthorityProofObjectDigestV1(material OutcomeAuthorityProofMaterialV1) (string, error) {
	if !outcomeToken(material.ProofProfileURI, MaxProfileURIBytes) || len(material.CanonicalObject) == 0 ||
		len(material.CanonicalObject) > MaxOutcomeAuthorityProofBytes {
		return "", errors.New("outcome authority proof material is invalid")
	}
	var decoded interface{}
	if err := codec.Unmarshal(material.CanonicalObject, &decoded); err != nil {
		return "", errors.New("outcome authority proof material is not canonical CBOR")
	}
	return codec.Digest(OutcomeAuthorityProofObjectDomain, material)
}

// OperationOutcomeProfileRefV1 returns the immutable dispatch profile. The
// digest identifies the released descriptor, not an implementation binary.
func OperationOutcomeProfileRefV1() ProfileRefV1 {
	digest, err := codec.Digest(OperationOutcomeProfileDescriptorDomain, struct {
		ProfileURI string `json:"profile_uri"`
		Version    uint64 `json:"version"`
		BodyDomain string `json:"body_domain"`
	}{OperationOutcomePayloadProfileURI, 1, OperationOutcomeEventDomain})
	if err != nil {
		panic(err)
	}
	return ProfileRefV1{ProfileURI: OperationOutcomePayloadProfileURI, ProfileVersion: 1, ProfileDigest: digest}
}

func EmptyOutcomeEvidenceManifestV1(purpose string) OutcomeEvidenceManifestV1 {
	return OutcomeEvidenceManifestV1{SchemaVersion: 1, ManifestPurpose: purpose,
		AuthorityProofRefs: []OutcomeAuthorityProofRefV1{}, EvidenceItems: []OutcomeEvidenceItemV1{}}
}

func EmptyOutcomeExtensionSetV1() OutcomeExtensionSetV1 {
	return OutcomeExtensionSetV1{SchemaVersion: 1, Extensions: []OutcomeExtensionV1{}}
}

func OutcomeAssertionPayloadDigestV1(profileURI string, payload []byte) (string, error) {
	if !outcomeToken(profileURI, MaxProfileURIBytes) || len(payload) == 0 || len(payload) > MaxOutcomeAssertionPayloadBytes {
		return "", errors.New("outcome assertion payload is invalid")
	}
	var decoded interface{}
	if err := codec.Unmarshal(payload, &decoded); err != nil {
		return "", errors.New("outcome assertion payload is not canonical CBOR")
	}
	return codec.Digest(OperationOutcomeAssertionPayloadDomain, struct {
		ProfileURI string `json:"profile_uri"`
		Payload    []byte `json:"payload"`
	}{profileURI, payload})
}

func OutcomeEvidenceManifestDigestV1(manifest OutcomeEvidenceManifestV1) (string, error) {
	if err := ValidateOutcomeEvidenceManifestV1(manifest); err != nil {
		return "", err
	}
	return codec.Digest(OperationOutcomeEvidenceManifestDomain, manifest)
}

func OutcomeExtensionSetDigestV1(set OutcomeExtensionSetV1) (string, error) {
	if err := ValidateOutcomeExtensionSetV1(set); err != nil {
		return "", err
	}
	return codec.Digest(OperationOutcomeExtensionSetDomain, set)
}

func OperationOutcomeEventContentIDV1(body OperationOutcomeEventBodyV1) (string, []byte, error) {
	if err := ValidateOperationOutcomeEventBodyV1(body); err != nil {
		return "", nil, err
	}
	canonical, err := codec.Marshal(body)
	if err != nil {
		return "", nil, err
	}
	digest, err := AgentOperationPayloadDigest(OperationOutcomeProfileRefV1(), canonical)
	return digest, canonical, err
}

// BuildOperationOutcomeEventV1 constructs all one-way commitments. The
// assertion payload, manifest and extension bytes are returned separately for
// content-addressed storage; no nested object can point back to the event.
func BuildOperationOutcomeEventV1(kind OperationOutcomeEventKind, subject OutcomeSubjectRefV1,
	predecessors []OutcomeAssertionRefV1, assertionProfileURI string, assertionPayload []byte,
	manifest OutcomeEvidenceManifestV1, extensions OutcomeExtensionSetV1) (OperationOutcomeEventBodyV1, error) {
	assertionDigest, err := OutcomeAssertionPayloadDigestV1(assertionProfileURI, assertionPayload)
	if err != nil {
		return OperationOutcomeEventBodyV1{}, err
	}
	manifestDigest, err := OutcomeEvidenceManifestDigestV1(manifest)
	if err != nil {
		return OperationOutcomeEventBodyV1{}, err
	}
	extensionDigest, err := OutcomeExtensionSetDigestV1(extensions)
	if err != nil {
		return OperationOutcomeEventBodyV1{}, err
	}
	canonicalPredecessors := make([]OutcomeAssertionRefV1, len(predecessors))
	copy(canonicalPredecessors, predecessors)
	body := OperationOutcomeEventBodyV1{SchemaVersion: 1, EventKind: kind, PrimarySubjectRef: subject,
		CausalPredecessorAssertionRefs: canonicalPredecessors, AssertionProfileURI: assertionProfileURI,
		AssertionPayloadDigest: assertionDigest, AssertionPayloadSize: uint64(len(assertionPayload)),
		EvidenceManifestDigest: manifestDigest, ExtensionSetDigest: extensionDigest}
	if err := ValidateOperationOutcomeEventBodyV1(body); err != nil {
		return OperationOutcomeEventBodyV1{}, err
	}
	return body, nil
}

func ValidateOperationOutcomeEventBodyV1(body OperationOutcomeEventBodyV1) error {
	if body.SchemaVersion != 1 || !validOutcomeEventKind(body.EventKind) ||
		!outcomeToken(body.PrimarySubjectRef.SubjectProfileURI, MaxProfileURIBytes) ||
		!outcomeToken(body.PrimarySubjectRef.SubjectID, 4096) || !outcomeToken(body.AssertionProfileURI, MaxProfileURIBytes) ||
		!digest32(body.AssertionPayloadDigest) || body.AssertionPayloadSize == 0 || body.AssertionPayloadSize > MaxOutcomeAssertionPayloadBytes ||
		!digest32(body.EvidenceManifestDigest) || !digest32(body.ExtensionSetDigest) ||
		body.CausalPredecessorAssertionRefs == nil || len(body.CausalPredecessorAssertionRefs) > MaxOutcomeCausalPredecessors {
		return errors.New("operation outcome event body is invalid")
	}
	return validateCanonicalOutcomeSlice(body.CausalPredecessorAssertionRefs, func(value OutcomeAssertionRefV1) error {
		if !outcomeToken(value.NetworkID, 256) || !outcomeToken(value.ActorAgentID, 256) ||
			!outcomeToken(value.OperationID, 256) || !digest32(value.OperationEnvelopeDigest) {
			return errors.New("outcome assertion reference is invalid")
		}
		return nil
	})
}

func ValidateOutcomeEvidenceManifestV1(manifest OutcomeEvidenceManifestV1) error {
	if manifest.SchemaVersion != 1 || !outcomeToken(manifest.ManifestPurpose, 128) ||
		len(manifest.AuthorityProofRefs) > MaxOutcomeAuthorityProofRefs || len(manifest.EvidenceItems) > MaxOutcomeEvidenceItems {
		return errors.New("outcome evidence manifest is invalid")
	}
	total := uint64(0)
	if err := validateCanonicalOutcomeSlice(manifest.AuthorityProofRefs, func(ref OutcomeAuthorityProofRefV1) error {
		if !outcomeToken(ref.ProofProfileURI, MaxProfileURIBytes) || !digest32(ref.ObjectDigest) ||
			ref.CanonicalSize == 0 || ref.CanonicalSize > MaxOutcomeAuthorityProofBytes {
			return errors.New("outcome authority proof reference is invalid")
		}
		total += ref.CanonicalSize
		return nil
	}); err != nil {
		return err
	}
	if total > MaxOutcomeAuthorityMaterialBytes {
		return errors.New("outcome authority material exceeds its aggregate bound")
	}
	return validateCanonicalOutcomeSlice(manifest.EvidenceItems, validateOutcomeEvidenceItemV1)
}

func validateOutcomeEvidenceItemV1(item OutcomeEvidenceItemV1) error {
	if !outcomeToken(item.EvidenceRole, 128) || !outcomeToken(item.EvidenceProfileURI, MaxProfileURIBytes) ||
		!outcomeToken(item.SourceObjectProfileURI, MaxProfileURIBytes) || !digest32(item.SourceObjectDigest) ||
		!digest32(item.ObjectDigest) || item.CanonicalSize == 0 || item.CanonicalSize > MaxOutcomeEvidenceObjectBytes ||
		!boundedMediaType(item.MediaType) || !outcomeToken(item.IssuerDescriptor, 4096) ||
		!outcomeToken(item.SubjectDescriptor, 4096) || item.ClaimedObservationTimeUnix > uint64(^uint64(0)>>1) ||
		!digest32(item.AuthorityTimeProofDigest) || !digest32(item.IssuerQualificationProofDigest) ||
		!validOutcomeVisibility(item.Visibility) || !digest32(item.AudienceDigest) || !digest32(item.RetentionPolicyDigest) ||
		!digest32(item.RetrievalPolicyDigest) {
		return errors.New("outcome evidence item is invalid")
	}
	return nil
}

func ValidateOutcomeExtensionSetV1(set OutcomeExtensionSetV1) error {
	if set.SchemaVersion != 1 || len(set.Extensions) > MaxOutcomeExtensions {
		return errors.New("outcome extension set is invalid")
	}
	return validateCanonicalOutcomeSlice(set.Extensions, func(extension OutcomeExtensionV1) error {
		if !outcomeToken(extension.ProfileURI, MaxProfileURIBytes) || len(extension.CanonicalValue) == 0 ||
			len(extension.CanonicalValue) > MaxAgentOperationExtensionBytes {
			return errors.New("outcome extension is invalid")
		}
		var decoded interface{}
		if err := codec.Unmarshal(extension.CanonicalValue, &decoded); err != nil {
			return errors.New("outcome extension value is not canonical CBOR")
		}
		return nil
	})
}

func ValidateAuthorityTimeProofV1(proof AuthorityTimeProofV1) error {
	if !outcomeToken(proof.ProfileURI, MaxProfileURIBytes) || !outcomeToken(proof.AuthorityOrCheckpointID, 256) ||
		proof.IntervalStartUnix == 0 || proof.IntervalEndUnix <= proof.IntervalStartUnix ||
		!digest32(proof.FinalizedRootDigest) || !digest32(proof.ProofDigest) {
		return errors.New("authority time proof is invalid")
	}
	return nil
}

func ValidateIssuerQualificationProofV1(proof IssuerQualificationProofV1) error {
	if !outcomeToken(proof.RootAuthorityID, 256) || !outcomeToken(proof.IssuerAgentID, 256) ||
		!digest32(proof.IssuerKeyDigest) || !digest32(proof.OrderedDelegationChainDigest) ||
		!outcomeToken(proof.ScopeProfileURI, MaxProfileURIBytes) || !digest32(proof.SubjectScopeDigest) ||
		proof.ValidFromUnix == 0 || proof.ValidUntilUnix <= proof.ValidFromUnix ||
		!digest32(proof.RevocationHandleSetDigest) || !digest32(proof.AuthorityTimeProofDigest) ||
		!digest32(proof.RevocationRootDigest) {
		return errors.New("issuer qualification proof is invalid")
	}
	return nil
}

// VerifyOperationOutcomeEnvelopeV1 applies both the root operation verifier
// and the outcome-specific payload bindings. Assertion/evidence profile
// verification remains the selected profile verifier's responsibility.
func VerifyOperationOutcomeEnvelopeV1(envelope AgentOperationEnvelopeV1, payload []byte,
	resolver AgentOperationAuthorityResolver, now time.Time) (OperationOutcomeEventBodyV1, error) {
	if envelope.Body.PayloadProfile != OperationOutcomeProfileRefV1() {
		return OperationOutcomeEventBodyV1{}, errors.New("operation outcome payload profile is not released V1")
	}
	if err := VerifyAgentOperationV1(envelope, payload, resolver, now); err != nil {
		return OperationOutcomeEventBodyV1{}, err
	}
	var body OperationOutcomeEventBodyV1
	if err := codec.Unmarshal(payload, &body); err != nil || ValidateOperationOutcomeEventBodyV1(body) != nil {
		return OperationOutcomeEventBodyV1{}, errors.New("operation outcome payload is invalid")
	}
	contentID, canonical, err := OperationOutcomeEventContentIDV1(body)
	if err != nil || !bytes.Equal(canonical, payload) || envelope.Body.ObjectID != contentID ||
		envelope.Body.PayloadDigest != contentID || envelope.Body.PayloadSize != uint64(len(payload)) {
		return OperationOutcomeEventBodyV1{}, errors.New("operation outcome outer binding is invalid")
	}
	return body, nil
}

func validateCanonicalOutcomeSlice[T any](values []T, validate func(T) error) error {
	var previous []byte
	for _, value := range values {
		if err := validate(value); err != nil {
			return err
		}
		canonical, err := codec.Marshal(value)
		if err != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("outcome collection is not strictly canonical")
		}
		previous = canonical
	}
	return nil
}

func SortOutcomeAssertionRefsV1(values []OutcomeAssertionRefV1) error {
	return sortCanonicalOutcomeSlice(values)
}

func SortOutcomeAuthorityProofRefsV1(values []OutcomeAuthorityProofRefV1) error {
	return sortCanonicalOutcomeSlice(values)
}

func SortOutcomeEvidenceItemsV1(values []OutcomeEvidenceItemV1) error {
	return sortCanonicalOutcomeSlice(values)
}

func SortOutcomeExtensionsV1(values []OutcomeExtensionV1) error {
	return sortCanonicalOutcomeSlice(values)
}

func SortOutcomeAuthorityProofMaterialsV1(values []OutcomeAuthorityProofMaterialV1) error {
	return sortCanonicalOutcomeSlice(values)
}

func sortCanonicalOutcomeSlice[T any](values []T) error {
	type encoded struct {
		value     T
		canonical []byte
	}
	items := make([]encoded, len(values))
	for index, value := range values {
		canonical, err := codec.Marshal(value)
		if err != nil {
			return err
		}
		items[index] = encoded{value, canonical}
	}
	sort.Slice(items, func(i, j int) bool { return bytes.Compare(items[i].canonical, items[j].canonical) < 0 })
	for index := range items {
		if index > 0 && bytes.Equal(items[index-1].canonical, items[index].canonical) {
			return errors.New("outcome collection contains duplicate values")
		}
		values[index] = items[index].value
	}
	return nil
}

func validOutcomeEventKind(kind OperationOutcomeEventKind) bool {
	switch kind {
	case OutcomeObservation, OutcomeTransitionObservation, OutcomeTerminalObservation, OutcomeAvailabilityObservation, OutcomeCohortCheckpoint:
		return true
	default:
		return false
	}
}

func validOutcomeVisibility(value string) bool {
	return value == "local_private" || value == "named_participants" || value == "named_recipients" || value == "audience_encrypted" || value == "public"
}

func outcomeToken(value string, maximum int) bool { return operationToken(value, maximum) }

func outcomeError(field string) error { return fmt.Errorf("operation outcome %s is invalid", field) }
