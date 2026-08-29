package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	trusted "github.com/tosnetwork/tos-service-protocol/pkg/trustedcapability"
)

type vector struct {
	Name              string `json:"name"`
	ObjectKind        string `json:"object_kind"`
	Body              any    `json:"body"`
	CanonicalCBORHex  string `json:"canonical_cbor_hex"`
	DigestPreimageHex string `json:"digest_preimage_hex"`
	ObjectDigestHex   string `json:"object_digest_hex"`
}
type document struct {
	Schema                   string                          `json:"schema"`
	RegistryCanonicalCBORHex string                          `json:"registry_canonical_cbor_hex"`
	RegistryDigestHex        string                          `json:"registry_digest_hex"`
	RegistryObjectKinds      []string                        `json:"registry_object_kinds"`
	OwnerCommandKinds        []string                        `json:"owner_command_kinds"`
	OwnerCommandProfiles     []trusted.OwnerCommandProfileV1 `json:"owner_command_profiles"`
	BodySchemas              []trusted.BodySchemaV1          `json:"body_schemas"`
	Vectors                  []vector                        `json:"vectors"`
	NegativeVectors          []negativeVector                `json:"negative_vectors"`
}

type negativeVector struct {
	Name             string `json:"name"`
	ObjectKind       string `json:"object_kind"`
	Failure          string `json:"failure"`
	CanonicalCBORHex string `json:"canonical_cbor_hex"`
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 4 {
		panic("usage: trusted-capability-fixtures VECTOR_OUTPUT [BODY_SCHEMA_OUTPUT] [REGISTRY_SCHEMA_OUTPUT]")
	}
	d := func(value byte) []byte { return bytes.Repeat([]byte{value}, sha256.Size) }
	body := trusted.CapabilityAdmissionBodyV1{SchemaVersion: 1, AdmissionID: bytes.Repeat([]byte{1}, 16), OwnerID: []byte("owner:test"), AgentID: []byte("agent:test"),
		ArtifactVersionDigest: d(2), PermissionManifestDigest: d(3), RequirementScopeDigest: d(4), EvaluationManifestDigest: d(5), SourcingDecisionDigest: d(6),
		RuntimeCompatibilityDigest: d(7), PolicyRevision: 4, PolicyDigest: d(8), AuthoritySubject: []byte("owner-key"), AuthorityProfileDigest: d(9),
		AdmittedAtUnix: 2_000_000_000, NotBeforeUnix: 2_000_000_000, ExpiresAtUnix: 2_000_003_600, RevocationGeneration: 1,
		InFlightRevocationPolicy: "kill-and-reconcile", Extensions: [][]byte{}}
	object, err := trusted.NewObject(trusted.DomainOwnerLocal, []byte("owner-domain:test"), "capability-admission", body)
	must(err)
	canonical, err := trusted.EncodeObject(object)
	must(err)
	digest, err := trusted.ObjectDigest(object)
	must(err)
	prefix := []byte(trusted.ProfileURI + "/capability-admission.v1")
	prefix = append(prefix, 0)
	prefix = append(prefix, byte(len(canonical)>>24), byte(len(canonical)>>16), byte(len(canonical)>>8), byte(len(canonical)))
	prefix = append(prefix, canonical...)
	seed := d(42)
	key := ed25519.NewKeyFromSeed(seed)
	keyReference := trusted.Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	proof := trusted.ProfileAuthorizationProofV1{Algorithm: trusted.Ed25519ProofProfile, KeyReference: keyReference, NotBeforeUnix: body.NotBeforeUnix, ExpiresAtUnix: body.ExpiresAtUnix}
	agent := []byte("agent:test")
	envelopeBody := trusted.ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: object.DomainKind, DomainID: object.DomainID, BodyKind: object.ObjectKind,
		BodyProfileURI: object.ProfileURI, BodyProfileVersion: object.ProfileVersion, BodyDigest: digest, OwnerID: body.OwnerID, AgentID: &agent,
		AuthorityKind: "capability-admission", AuthorityID: bytes.Repeat([]byte{12}, 16), AuthorityRevision: 0, AuthorityEpoch: 3,
		PolicyRevision: body.PolicyRevision, PolicyDigest: body.PolicyDigest, IssuerSubject: trusted.TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: trusted.Ed25519ProofProfile, Identifier: keyReference},
		ProofProfileURI: trusted.Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: body.NotBeforeUnix, ExpiresAtUnix: body.ExpiresAtUnix,
		PredecessorEnvelopeDigest: nil, ExtensionsDigest: d(0)}
	envelope, err := trusted.SignAuthorization(envelopeBody, []trusted.ProfileAuthorizationProofV1{proof}, []ed25519.PrivateKey{key})
	must(err)
	envelopeObject, err := trusted.NewObject(trusted.DomainOwnerLocal, object.DomainID, "authorization-envelope", envelope)
	must(err)
	envelopeCanonical, err := trusted.EncodeObject(envelopeObject)
	must(err)
	envelopeDigest, err := trusted.ObjectDigest(envelopeObject)
	must(err)
	envelopePrefix := []byte(trusted.ProfileURI + "/authorization-envelope.v1")
	envelopePrefix = append(envelopePrefix, 0)
	envelopePrefix = append(envelopePrefix, byte(len(envelopeCanonical)>>24), byte(len(envelopeCanonical)>>16), byte(len(envelopeCanonical)>>8), byte(len(envelopeCanonical)))
	envelopePrefix = append(envelopePrefix, envelopeCanonical...)
	vectors := []vector{{"capability-admission", object.ObjectKind, body, hex.EncodeToString(canonical), hex.EncodeToString(prefix), hex.EncodeToString(digest)},
		{"authorization-envelope", envelopeObject.ObjectKind, envelope, hex.EncodeToString(envelopeCanonical), hex.EncodeToString(envelopePrefix), hex.EncodeToString(envelopeDigest)}}
	negativeVectors := []negativeVector{}
	for _, kind := range trusted.RegistryObjectKinds() {
		if kind == "capability-admission" || kind == "authorization-envelope" {
			continue
		}
		fixture, fixtureErr := trusted.NewConformanceBodyValue(kind, byte(len(vectors)+1))
		must(fixtureErr)
		wrapper, objectErr := trusted.NewObject(trusted.DomainOwnerLocal, []byte("owner-domain:test"), kind, fixture)
		must(objectErr)
		wire, wireErr := trusted.EncodeObject(wrapper)
		must(wireErr)
		objectDigest, digestErr := trusted.ObjectDigest(wrapper)
		must(digestErr)
		preimage := []byte(trusted.ProfileURI + "/" + kind + ".v1")
		preimage = append(preimage, 0, byte(len(wire)>>24), byte(len(wire)>>16), byte(len(wire)>>8), byte(len(wire)))
		preimage = append(preimage, wire...)
		vectors = append(vectors, vector{"full-body-" + kind, kind, fixture,
			hex.EncodeToString(wire), hex.EncodeToString(preimage), hex.EncodeToString(objectDigest)})
	}
	for index, kind := range trusted.OwnerCommandKindsV1 {
		profile, profileErr := trusted.OwnerCommandProfile(kind)
		must(profileErr)
		agentID := []byte("agent:test")
		ownerID := []byte("owner:test")
		targetID := d(byte(index + 1))
		if profile.TargetObjectKind == "agent" {
			targetID = append([]byte(nil), agentID...)
		} else if profile.TargetObjectKind == "owner" {
			targetID = append([]byte(nil), ownerID...)
		}
		effect := trusted.OwnerCommandEffectV1{SchemaVersion: 1, DomainKind: uint8(trusted.DomainOwnerLocal), DomainID: []byte("owner-domain:test"), OwnerID: ownerID,
			AgentID: &agentID, CommandKind: kind, CommandInstanceID: bytes.Repeat([]byte{byte(index + 1)}, 16), TargetObjectKind: profile.TargetObjectKind, TargetObjectID: targetID,
			SinkAuthorityID: []byte("sink:test"), SinkClusterEpoch: 1, ResolutionNamespace: d(31), ControlScopeGeneration: 1, ExpectedTargetRevision: 1,
			ExactParameterDigest: d(32), PolicyRevision: 1, PolicyDigest: d(33), SemanticConfirmationDigest: d(34), AuthorityPredicateSetDigest: d(35),
			CreatedAtUnix: 2_000_000_000, ExpiresAtUnix: 2_000_003_600, Extensions: [][]byte{}}
		predicateDigest, predicateErr := trusted.OwnerCommandAuthorizationPredicateSetDigest(effect)
		must(predicateErr)
		effect.AuthorityPredicateSetDigest = predicateDigest
		predicateProfile, predicateErr := trusted.OwnerCommandAuthorizationPredicateSet(effect)
		must(predicateErr)
		risk := "bounded"
		if predicateProfile.RequireIndependentApprover {
			risk = "high"
		}
		confirmation := trusted.SemanticConfirmationV1{DisplayProfileURI: trusted.OwnerCommandConfirmationProfileV1, DisplayProfileVersion: 1, RiskClass: risk,
			DomainID: effect.DomainID, OwnerID: effect.OwnerID, ActionID: d(36), CommandKind: effect.CommandKind,
			Target: effect.TargetObjectKind + ":" + hex.EncodeToString(effect.TargetObjectID), PermissionDelta: []byte{}, PolicyDelta: []byte{},
			CriticalParameters: [][]byte{effect.ExactParameterDigest, effect.PolicyDigest, effect.TargetObjectID}, ExpiresAtUnix: effect.ExpiresAtUnix}
		effect.SemanticConfirmationDigest, err = trusted.SemanticConfirmationDigest(confirmation)
		must(err)
		must(trusted.ValidateOwnerCommandEffect(effect))
		must(trusted.ValidateSemanticConfirmation(confirmation, effect, confirmation.ActionID, effect.CreatedAtUnix))
		wrapper, objectErr := trusted.NewObject(trusted.DomainOwnerLocal, effect.DomainID, "owner-command-effect", effect)
		must(objectErr)
		wire, wireErr := trusted.EncodeObject(wrapper)
		must(wireErr)
		objectDigest, digestErr := trusted.ObjectDigest(wrapper)
		must(digestErr)
		preimage := []byte(trusted.ProfileURI + "/owner-command-effect.v1")
		preimage = append(preimage, 0, byte(len(wire)>>24), byte(len(wire)>>16), byte(len(wire)>>8), byte(len(wire)))
		preimage = append(preimage, wire...)
		vectors = append(vectors, vector{"owner-command-" + kind, "owner-command-effect", effect, hex.EncodeToString(wire), hex.EncodeToString(preimage), hex.EncodeToString(objectDigest)})
	}
	for _, item := range vectors {
		wire, _ := hex.DecodeString(item.CanonicalCBORHex)
		decoded, decodeErr := trusted.DecodeObject(wire)
		must(decodeErr)
		var fields map[uint64]any
		must(trusted.UnmarshalBody(decoded.Body, &fields))
		delete(fields, uint64(1))
		missing, encodeErr := trusted.MarshalBody(fields)
		must(encodeErr)
		decoded.Body = missing
		mutated, encodeErr := trusted.MarshalBody(decoded)
		must(encodeErr)
		negativeVectors = append(negativeVectors, negativeVector{"missing-required-field-" + item.Name, item.ObjectKind, "missing-required-field", hex.EncodeToString(mutated)})
		// Unknown keys and type substitutions are independent failure classes;
		// every released kind receives all three shape mutations.
		unknownFields := map[uint64]any{}
		must(trusted.UnmarshalBody(wireBody(item.CanonicalCBORHex), &unknownFields))
		unknownFields[65535] = uint64(1)
		unknownBody, encodeErr := trusted.MarshalBody(unknownFields)
		must(encodeErr)
		decodedUnknown, decodeErr := trusted.DecodeObject(mustHex(item.CanonicalCBORHex))
		must(decodeErr)
		decodedUnknown.Body = unknownBody
		unknownWire, encodeErr := trusted.MarshalBody(decodedUnknown)
		must(encodeErr)
		negativeVectors = append(negativeVectors, negativeVector{"unknown-field-" + item.Name, item.ObjectKind, "unknown-field", hex.EncodeToString(unknownWire)})
		wrongFields := map[uint64]any{}
		must(trusted.UnmarshalBody(wireBody(item.CanonicalCBORHex), &wrongFields))
		wrongFields[uint64(1)] = false
		wrongBody, encodeErr := trusted.MarshalBody(wrongFields)
		must(encodeErr)
		decodedWrong, decodeErr := trusted.DecodeObject(mustHex(item.CanonicalCBORHex))
		must(decodeErr)
		decodedWrong.Body = wrongBody
		wrongWire, encodeErr := trusted.MarshalBody(decodedWrong)
		must(encodeErr)
		negativeVectors = append(negativeVectors, negativeVector{"wrong-type-" + item.Name, item.ObjectKind, "wrong-type", hex.EncodeToString(wrongWire)})
		var semanticKey uint64
		var semanticValue any
		switch item.ObjectKind {
		case "artifact":
			semanticKey, semanticValue = 2, "unsupported-artifact"
		case "content-manifest":
			semanticKey, semanticValue = 3, d(99)
		case "entrypoint-descriptor":
			semanticKey, semanticValue = 2, []byte{1}
		case "permission-manifest":
			semanticKey, semanticValue = 14, "01"
		case "dependency-manifest":
			semanticKey, semanticValue = 8, d(99)
		case "publisher-envelope":
			semanticKey, semanticValue = 3, "unsupported-artifact"
		case "publisher-revocation-observation":
			semanticKey, semanticValue = 8, uint64(0)
		case "capability-requirement":
			semanticKey, semanticValue = 9, "01"
		case "evaluation-result":
			semanticKey, semanticValue = 15, uint64(0)
		case "evaluation-evidence":
			semanticKey, semanticValue = 2, ""
		case "authorization-envelope":
			semanticKey, semanticValue = 2, []any{}
		case "owner-policy":
			semanticKey, semanticValue = 3, uint64(0)
		case "capability-admission":
			semanticKey, semanticValue = 19, "unknown-policy"
		case "admission-mutation", "promotion-mutation":
			semanticKey, semanticValue = 3, uint64(1)
		case "promotion-authority":
			semanticKey, semanticValue = 31, uint64(0)
		case "use-lease":
			semanticKey, semanticValue = 2, bytes.Repeat([]byte{1}, 16)
		case "installation-transaction":
			semanticKey, semanticValue = 16, "active"
		case "capability-use-binding":
			semanticKey, semanticValue = 9, d(100)
		case "inventory-snapshot":
			semanticKey, semanticValue = 10, uint64(1)
		case "owner-report":
			semanticKey, semanticValue = 24, "partial"
		case "report-source-coverage":
			semanticKey, semanticValue = 7, "partial"
		case "projection-event":
			semanticKey, semanticValue = 5, uint64(2)
		case "projection-snapshot":
			semanticKey, semanticValue = 4, uint64(0)
		case "owner-bootstrap":
			semanticKey, semanticValue = 13, "completed"
		case "owner-recovery":
			semanticKey, semanticValue = 5, uint64(0)
		case "device-enrollment":
			semanticKey, semanticValue = 10, uint64(0)
		case "device-session":
			semanticKey, semanticValue = 8, uint64(0)
		case "owner-command-lease":
			semanticKey, semanticValue = 11, uint64(0)
		case "owner-command-effect":
			semanticKey, semanticValue = 6, "unknown.command"
		case "owner-command-attempt":
			semanticKey, semanticValue = 2, bytes.Repeat([]byte{1}, 16)
		case "semantic-confirmation":
			semanticKey, semanticValue = 7, "unknown.command"
		case "sourcing-decision":
			semanticKey, semanticValue = 9, "select-without-admission"
		case "evaluation-manifest":
			semanticKey, semanticValue = 19, [][]byte{}
		case "owner-command-resolution":
			semanticKey, semanticValue = 1, "active"
		case "owner-exit-plan":
			semanticKey, semanticValue = 4, "active"
		case "migration":
			semanticKey, semanticValue = 9, "active"
		case "action-outcome-evidence":
			semanticKey, semanticValue = 5, "unsupported-action"
		}
		if semanticKey != 0 {
			semanticFields := map[uint64]any{}
			must(trusted.UnmarshalBody(wireBody(item.CanonicalCBORHex), &semanticFields))
			semanticFields[semanticKey] = semanticValue
			semanticBody, mutationErr := trusted.MarshalBody(semanticFields)
			must(mutationErr)
			semanticWrapper, mutationErr := trusted.DecodeObject(mustHex(item.CanonicalCBORHex))
			must(mutationErr)
			semanticWrapper.Body = semanticBody
			semanticWire, mutationErr := trusted.MarshalBody(semanticWrapper)
			must(mutationErr)
			negativeVectors = append(negativeVectors, negativeVector{"semantic-invalid-" + item.Name, item.ObjectKind, "semantic-invalid", hex.EncodeToString(semanticWire)})
		}
	}
	doc := document{Schema: "tos.trusted-capability-owner-control-conformance.v1", RegistryCanonicalCBORHex: hex.EncodeToString(trusted.RegistryCanonicalBytes()), RegistryDigestHex: hex.EncodeToString(trusted.RegistryDigest()), RegistryObjectKinds: trusted.RegistryObjectKinds(),
		OwnerCommandKinds: trusted.OwnerCommandKindsV1, OwnerCommandProfiles: trusted.OwnerCommandProfilesV1(), BodySchemas: trusted.BodySchemas(), Vectors: vectors,
		NegativeVectors: append(negativeVectors, negativeVector{"trailing-byte", "capability-admission", "non-canonical-wrapper", hex.EncodeToString(append(append([]byte(nil), canonical...), 0))},
			negativeVector{"truncated-wrapper", "capability-admission", "non-canonical-wrapper", hex.EncodeToString(canonical[:len(canonical)-1])},
			negativeVector{"noncanonical-zero", "capability-admission", "non-canonical-wrapper", "1800"})}
	raw, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.WriteFile(os.Args[1], append(raw, '\n'), 0o644))
	if len(os.Args) == 3 {
		writeBodySchemas(os.Args[2])
	}
	if len(os.Args) == 4 {
		writeBodySchemas(os.Args[2])
		registrySchema := map[string]any{
			"$schema":     "https://json-schema.org/draft/2020-12/schema",
			"$id":         "https://tos.network/schemas/trusted-capability-owner-control-v1.json",
			"title":       "TOS Trusted Capability and Owner Control V1 Registry",
			"description": "Released object-kind and owner-command registry. Canonical CBOR shape and semantic validation are frozen by the linked body schemas and conformance vectors.",
			"type":        "object", "additionalProperties": false,
			"required": []string{"profile_uri", "profile_version", "registry_digest_hex", "object_kinds", "owner_command_kinds", "owner_command_profiles"},
			"properties": map[string]any{
				"profile_uri":            map[string]any{"const": trusted.ProfileURI},
				"profile_version":        map[string]any{"const": trusted.ProfileVersion},
				"registry_digest_hex":    map[string]any{"const": hex.EncodeToString(trusted.RegistryDigest()), "pattern": "^[0-9a-f]{64}$"},
				"object_kinds":           map[string]any{"const": trusted.RegistryObjectKinds()},
				"owner_command_kinds":    map[string]any{"const": trusted.OwnerCommandKindsV1},
				"owner_command_profiles": map[string]any{"const": trusted.OwnerCommandProfilesV1()},
			},
		}
		schemaRaw, schemaErr := json.MarshalIndent(registrySchema, "", "  ")
		must(schemaErr)
		must(os.WriteFile(os.Args[3], append(schemaRaw, '\n'), 0o644))
	}
}

func writeBodySchemas(path string) {
	schemaDocument := struct {
		Schema       string                 `json:"schema"`
		ProfileURI   string                 `json:"profile_uri"`
		Version      uint16                 `json:"version"`
		RegistryHash string                 `json:"registry_digest_hex"`
		BodySchemas  []trusted.BodySchemaV1 `json:"body_schemas"`
	}{"tos.trusted-capability-body-schemas.v1", trusted.ProfileURI, trusted.ProfileVersion, hex.EncodeToString(trusted.RegistryDigest()), trusted.BodySchemas()}
	schemaRaw, schemaErr := json.MarshalIndent(schemaDocument, "", "  ")
	must(schemaErr)
	must(os.WriteFile(path, append(schemaRaw, '\n'), 0o644))
}

func mustHex(value string) []byte { raw, err := hex.DecodeString(value); must(err); return raw }
func wireBody(value string) []byte {
	object, err := trusted.DecodeObject(mustHex(value))
	must(err)
	return object.Body
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("fixture generation: %v", err))
	}
}
