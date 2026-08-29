package trustedcapability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func digest(fill byte) []byte { return bytes.Repeat([]byte{fill}, sha256.Size) }

func sampleAdmission() CapabilityAdmissionBodyV1 {
	return CapabilityAdmissionBodyV1{SchemaVersion: 1, AdmissionID: bytes.Repeat([]byte{1}, 16), OwnerID: []byte("owner"), AgentID: []byte("agent"),
		ArtifactVersionDigest: digest(2), PermissionManifestDigest: digest(3), RequirementScopeDigest: digest(4),
		EvaluationManifestDigest: digest(5), SourcingDecisionDigest: digest(6), RuntimeCompatibilityDigest: digest(7),
		PolicyRevision: 4, PolicyDigest: digest(8), AuthoritySubject: []byte("owner-key"), AuthorityProfileDigest: digest(9),
		AdmittedAtUnix: 100, NotBeforeUnix: 100, ExpiresAtUnix: 1000, RevocationGeneration: 1,
		InFlightRevocationPolicy: "kill-and-reconcile", Extensions: [][]byte{}}
}

func TestIntegerKeyCanonicalObjectRoundTrip(t *testing.T) {
	object, err := NewObject(DomainOwnerLocal, []byte("domain"), "capability-admission", sampleAdmission())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeObject(object)
	if err != nil {
		t.Fatal(err)
	}
	// a9 is a nine-pair map; key 1 follows. A string-keyed wrapper would start
	// with a text key and is intentionally wire-incompatible.
	if len(wire) < 2 || wire[0] != 0xa9 || wire[1] != 0x01 {
		t.Fatalf("unexpected integer-key wrapper prefix %x", wire[:2])
	}
	decoded, err := DecodeObject(wire)
	if err != nil {
		t.Fatal(err)
	}
	var body CapabilityAdmissionBodyV1
	if err := DecodeBody(decoded, "capability-admission", &body); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body.AdmissionID, sampleAdmission().AdmissionID) {
		t.Fatal("admission ID changed")
	}
	first, _ := ObjectDigest(object)
	second, _ := ObjectDigest(decoded)
	if !bytes.Equal(first, second) {
		t.Fatal("digest is not stable")
	}
}

func TestRejectsNonCanonicalAndWrongRegistry(t *testing.T) {
	// Indefinite map is forbidden before typed decoding.
	if _, err := DecodeObject([]byte{0xbf, 0xff}); err == nil {
		t.Fatal("accepted indefinite map")
	}
	object, err := NewObject(DomainOwnerLocal, []byte("domain"), "capability-admission", sampleAdmission())
	if err != nil {
		t.Fatal(err)
	}
	object.ProfileRegistryDigest[0] ^= 1
	if _, err := EncodeObject(object); err == nil {
		t.Fatal("accepted registry substitution")
	}
	if _, err := NewObject(DomainOwnerLocal, []byte("domain"), "unknown", sampleAdmission()); err == nil {
		t.Fatal("accepted unknown kind")
	}
}

func TestAuthorizationBindsExactObjectAndEpoch(t *testing.T) {
	object, err := NewObject(DomainOwnerLocal, []byte("domain"), "capability-admission", sampleAdmission())
	if err != nil {
		t.Fatal(err)
	}
	bodyDigest, _ := ObjectDigest(object)
	seed := digest(21)
	key := ed25519.NewKeyFromSeed(seed)
	keyReference := Ed25519KeyReference(key.Public().(ed25519.PublicKey))
	proof := ProfileAuthorizationProofV1{Algorithm: Ed25519ProofProfile, KeyReference: keyReference,
		HistoricalAuthorityProofReference: nil, NotBeforeUnix: 100, ExpiresAtUnix: 1000}
	// A single proof is inherently sorted.
	body := ProfileAuthorizationEnvelopeBodyV1{SchemaVersion: 1, DomainKind: object.DomainKind, DomainID: object.DomainID,
		BodyKind: object.ObjectKind, BodyProfileURI: object.ProfileURI, BodyProfileVersion: object.ProfileVersion,
		BodyDigest: bodyDigest, OwnerID: []byte("owner"), AgentID: ptrBytes([]byte("agent")), AuthorityKind: "capability-admission",
		AuthorityID: bytes.Repeat([]byte{7}, 16), AuthorityRevision: 0, AuthorityEpoch: 3, PolicyRevision: 4,
		PolicyDigest: digest(8), IssuerSubject: TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: Ed25519ProofProfile, Identifier: keyReference},
		ProofProfileURI: Ed25519ProofProfile, ProofProfileVersion: 1, NotBeforeUnix: 100, ExpiresAtUnix: 1000,
		PredecessorEnvelopeDigest: nil, ExtensionsDigest: digest(0)}
	envelope, err := SignAuthorization(body, []ProfileAuthorizationProofV1{proof}, []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(envelope, object, 200, 3); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(envelope, object, 200, 4); err == nil {
		t.Fatal("accepted stale epoch")
	}
	mutated := object
	mutated.DomainID = []byte("other")
	if err := VerifyAuthorization(envelope, mutated, 200, 3); err == nil {
		t.Fatal("accepted domain substitution")
	}
}

func TestUseBindingNullCombination(t *testing.T) {
	binding := CapabilityUseBindingV1{OwnerID: []byte("owner"), AgentID: []byte("agent"), AgreementDigest: digest(1), ObligationID: digest(2), ExecutionID: digest(3), ActionID: digest(4),
		ArtifactVersionDigest: digest(5), InstallationRevision: 1, LoadedObjectDigest: digest(5), PermissionSubsetDigest: digest(6), AdmissionEnvelopeDigest: digest(7),
		AdmissionRevision: 1, AdmissionRevocationGeneration: 1, PromotionRequired: true, AuthorityEpoch: 1, PolicyDigest: digest(8), PolicyRevision: 1,
		ControlScopeGeneration: 1, InventoryRevision: 1, RuntimeAndSandboxDigest: digest(9), EffectiveEnvironmentDigest: digest(10),
		CredentialCapabilityReferenceSetDigest: digest(11), FilesystemHandleSetDigest: digest(12), NetworkBrokerPolicyDigest: digest(13), StartNotAfterUnix: 100,
		InvocationDescriptorDigest: digest(14)}
	if err := ValidateUseBindingShape(binding, false); err == nil {
		t.Fatal("accepted missing promotion")
	}
	binding.PromotionEnvelopeDigest = ptrBytes(digest(1))
	binding.PromotionRevision = ptrU64(1)
	binding.PromotionRevocationGeneration = ptrU64(1)
	if err := ValidateUseBindingShape(binding, false); err != nil {
		t.Fatal(err)
	}
	binding.RemoteSessionHandshakeDigest = ptrBytes(digest(2))
	if err := ValidateUseBindingShape(binding, false); err == nil {
		t.Fatal("accepted remote handshake for local use")
	}
}

func TestLeaseRejectsInvocationDescriptorSubstitution(t *testing.T) {
	binding := CapabilityUseBindingV1{OwnerID: []byte("owner"), AgentID: []byte("agent"), AgreementDigest: digest(1), ObligationID: digest(2), ExecutionID: digest(3), ActionID: digest(4),
		ArtifactVersionDigest: digest(5), InstallationRevision: 1, LoadedObjectDigest: digest(5), PermissionSubsetDigest: digest(6), AdmissionEnvelopeDigest: digest(7),
		AdmissionRevision: 1, AdmissionRevocationGeneration: 1, AuthorityEpoch: 1, PolicyDigest: digest(8), PolicyRevision: 1,
		ControlScopeGeneration: 1, InventoryRevision: 1, RuntimeAndSandboxDigest: digest(9), EffectiveEnvironmentDigest: digest(10),
		CredentialCapabilityReferenceSetDigest: digest(11), FilesystemHandleSetDigest: digest(12), NetworkBrokerPolicyDigest: digest(13),
		StartNotAfterUnix: 200, InvocationDescriptorDigest: digest(14)}
	lease := CapabilityUseLeaseV1{SchemaVersion: 1, LeaseID: digest(15), OwnerID: binding.OwnerID, AgentID: binding.AgentID, SinkID: []byte("sink"),
		ExecutionID: binding.ExecutionID, ActionID: binding.ActionID, ArtifactVersionDigest: binding.ArtifactVersionDigest, PermissionSubsetDigest: binding.PermissionSubsetDigest,
		AdmissionEnvelopeDigest: binding.AdmissionEnvelopeDigest, AdmissionRevocationGeneration: 1, AuthorityEpoch: 1, PolicyDigest: binding.PolicyDigest,
		PolicyRevision: 1, NotBeforeUnix: 100, StartNotAfterUnix: 200, ExpiresAtUnix: 300, InvocationDescriptorDigest: binding.InvocationDescriptorDigest,
		AdmissionRevision: binding.AdmissionRevision, InstallationRevision: binding.InstallationRevision, InventoryRevision: binding.InventoryRevision,
		ControlScopeGeneration: binding.ControlScopeGeneration}
	if err := ValidateLeaseBinding(lease, binding, []byte("sink")); err != nil {
		t.Fatal(err)
	}
	binding.InvocationDescriptorDigest = digest(16)
	if err := ValidateLeaseBinding(lease, binding, []byte("sink")); err == nil {
		t.Fatal("accepted invocation descriptor substitution")
	}
	binding.InvocationDescriptorDigest = lease.InvocationDescriptorDigest
	binding.ControlScopeGeneration++
	if err := ValidateLeaseBinding(lease, binding, []byte("sink")); err == nil {
		t.Fatal("accepted a pre-pause lease with a refreshed unsigned control generation")
	}
}

func ptrBytes(value []byte) *[]byte { copyOf := append([]byte(nil), value...); return &copyOf }
func ptrU64(value uint64) *uint64   { return &value }
