package agentcommerce

import (
	"bytes"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func TestOutcomeEncryptedEvidenceAuthenticatesMetadataAndCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plaintext := []byte("private bounded evidence")
	metadata := OutcomeEncryptedEvidenceMetadataV1{ObjectDigest: outcomeDigest("1"), AudiencePolicyDigest: outcomeDigest("2"),
		RetentionPolicyDigest: outcomeDigest("3"), EvidenceRole: "authoritative_resolution", CanonicalSize: uint64(len(plaintext))}
	first, err := sealOutcomeEncryptedEvidenceV1(bytes.NewReader(bytes.Repeat([]byte{0x11}, 24)), key, outcomeDigest("4"), metadata, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenOutcomeEncryptedEvidenceV1(key, first)
	if err != nil || !bytes.Equal(opened, plaintext) {
		t.Fatalf("open=%q err=%v", opened, err)
	}
	mutated := first
	mutated.Ciphertext = append([]byte(nil), first.Ciphertext...)
	mutated.Ciphertext[0] ^= 1
	if _, err := OpenOutcomeEncryptedEvidenceV1(key, mutated); err == nil {
		t.Fatal("ciphertext mutation authenticated")
	}
	mutated = first
	mutated.AssociatedData.AudiencePolicyDigest = outcomeDigest("5")
	if _, err := OpenOutcomeEncryptedEvidenceV1(key, mutated); err == nil {
		t.Fatal("audience substitution authenticated")
	}
	mutated = first
	mutated.KeyReferenceDigest = outcomeDigest("5")
	if _, err := OpenOutcomeEncryptedEvidenceV1(key, mutated); err == nil {
		t.Fatal("key-reference substitution authenticated")
	}
	mutated.AssociatedDataDigest, err = codec.Digest("tos.outcome.encrypted-evidence-associated-data.v1", outcomeEncryptedEvidenceAADV1{
		SchemaVersion: mutated.SchemaVersion, CipherSuite: mutated.CipherSuite,
		KeyReferenceDigest: mutated.KeyReferenceDigest, Metadata: mutated.AssociatedData})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenOutcomeEncryptedEvidenceV1(key, mutated); err == nil {
		t.Fatal("key-reference substitution with recomputed context digest authenticated")
	}
	second, err := sealOutcomeEncryptedEvidenceV1(bytes.NewReader(bytes.Repeat([]byte{0x12}, 24)), key, outcomeDigest("4"), metadata, plaintext)
	if err != nil || bytes.Equal(first.Nonce, second.Nonce) {
		t.Fatal("evidence envelopes reused a nonce")
	}
}

func TestOutcomeHidingCommitmentSeparatesAudiencesAndRandomness(t *testing.T) {
	value := []byte("enumerable-secret")
	first, err := OutcomeHidingCommitmentV1(outcomeDigest("1"), bytes.Repeat([]byte{1}, 16), value)
	if err != nil {
		t.Fatal(err)
	}
	second, _ := OutcomeHidingCommitmentV1(outcomeDigest("1"), bytes.Repeat([]byte{2}, 16), value)
	third, _ := OutcomeHidingCommitmentV1(outcomeDigest("2"), bytes.Repeat([]byte{1}, 16), value)
	if first == second || first == third {
		t.Fatal("hiding commitment was reusable across randomness or audience context")
	}
}

func TestOutcomeAudiencePolicyEnforcesAudienceSpecificCardinality(t *testing.T) {
	policy := AudiencePolicyV1{SchemaVersion: 1, NetworkID: "tos:test", AudienceKind: "public",
		PermittedPurposeSetDigest: outcomeDigest("1"), OnwardDisclosureRule: "allowed", ExpiresAtUnix: 2_000_000_000, PolicyRevision: 1}
	if err := ValidateAudiencePolicyV1(policy); err != nil {
		t.Fatal(err)
	}
	policy.RecipientPrincipalKeySetDigest = outcomeDigest("2")
	if ValidateAudiencePolicyV1(policy) == nil {
		t.Fatal("public audience carried a recipient correlation set")
	}
	policy.AudienceKind = "named_recipients"
	if err := ValidateAudiencePolicyV1(policy); err != nil {
		t.Fatal(err)
	}
	policy.GroupID, policy.MembershipEpoch, policy.MembershipRootDigest = "group:one", 1, outcomeDigest("3")
	if ValidateAudiencePolicyV1(policy) == nil {
		t.Fatal("named-recipient audience carried group membership fields")
	}
}
