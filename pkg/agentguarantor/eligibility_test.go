package agentguarantor

import (
	"strings"
	"testing"
)

func TestAuthorityAdmissionEligibilityProofSetRejectsSubstitutionAndReordering(t *testing.T) {
	d := func(ch string) string { return "sha256:" + strings.Repeat(ch, 64) }
	profile := ProfileRefV1{ProfileURI: "tos.test.authority.v1", ProfileVersion: 1, ProfileDigest: d("1")}
	entry := func(subject, input string) AuthorityAdmissionEligibilityProofV1 {
		return AuthorityAdmissionEligibilityProofV1{SchemaVersion: 1, InputAuthorizedEnvelopeDigest: input,
			AuthoritySubject: subject, AuthorityKeyOrPrincipalDigest: d("2"), AuthorizedObjectKind: "coverage-acceptance",
			AuthorizedBodyDigest: d("3"), RequiredScopeDigest: d("4"), AuthorityResolverProfile: profile,
			FinalizedAuthorityStateRevision: 9, FinalizedAuthorityStateRoot: d("5"), ResolverFinalityEvidence: []byte("finality"),
			AdmissionDomainID: d("6"), AdmissionSequence: 7, AdmissionTimeUnix: 100, EligibilityState: "eligible"}
	}
	first, second := entry("agent:a", d("7")), entry("agent:b", d("8"))
	set := AuthorityAdmissionEligibilityProofSetV1{SchemaVersion: 1, AdmittedActionDigest: d("9"),
		AdmissionDomainID: d("6"), AdmissionSequence: 7, AdmissionTimeUnix: 100,
		Entries: []AuthorityAdmissionEligibilityProofV1{first, second}}
	firstBytes, _ := Canonical(first)
	secondBytes, _ := Canonical(second)
	if string(firstBytes) > string(secondBytes) {
		set.Entries[0], set.Entries[1] = set.Entries[1], set.Entries[0]
	}
	digest, err := AuthorityAdmissionEligibilityProofSetDigestV1(set)
	if err != nil || digest == "" {
		t.Fatalf("valid proof set failed: digest=%q err=%v", digest, err)
	}
	reordered := set
	reordered.Entries = append([]AuthorityAdmissionEligibilityProofV1(nil), set.Entries...)
	reordered.Entries[0], reordered.Entries[1] = reordered.Entries[1], reordered.Entries[0]
	if ValidateAuthorityAdmissionEligibilityProofSetV1(reordered) == nil {
		t.Fatal("noncanonical proof order was accepted")
	}
	tampered := set
	tampered.Entries = append([]AuthorityAdmissionEligibilityProofV1(nil), set.Entries...)
	tampered.Entries[0].AdmissionSequence++
	if ValidateAuthorityAdmissionEligibilityProofSetV1(tampered) == nil {
		t.Fatal("cross-admission proof substitution was accepted")
	}
}
