package agentcommerce

import (
	"testing"
	"time"
)

func TestPinnedOutcomeAuthorityBindsIssuerSubjectAndHistoricalCut(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	scope, err := OutcomeSubjectScopeDigestV1("execution:one")
	if err != nil {
		t.Fatal(err)
	}
	timeProof := AuthorityTimeProofV1{ProfileURI: "tos.authority.clock.v1", AuthorityOrCheckpointID: "checkpoint:one",
		IntervalStartUnix: uint64(now.Add(-time.Minute).Unix()), IntervalEndUnix: uint64(now.Unix()), FinalizedHighWater: 1,
		FinalizedRootDigest: outcomeDigest("1"), ProofDigest: outcomeDigest("2")}
	qualification := IssuerQualificationProofV1{RootAuthorityID: "authority:root", IssuerAgentID: "agent:executor", IssuerKeyDigest: outcomeDigest("3"),
		OrderedDelegationChainDigest: outcomeDigest("4"), ScopeProfileURI: "tos.execution.resolution.v1", SubjectScopeDigest: scope,
		ValidFromUnix: uint64(now.Add(-time.Hour).Unix()), ValidUntilUnix: uint64(now.Add(time.Hour).Unix()),
		RevocationHandleSetDigest: outcomeDigest("5"), AuthorityTimeProofDigest: outcomeDigest("6"), RevocationHighWater: 1, RevocationRootDigest: outcomeDigest("7")}
	verifier, err := NewPinnedOutcomeEvidenceAuthorityV1([]AuthorityTimeProofV1{timeProof}, []IssuerQualificationProofV1{qualification})
	if err != nil {
		t.Fatal(err)
	}
	item := OutcomeEvidenceItemV1{IssuerDescriptor: "agent:executor", SubjectDescriptor: "execution:one", EvidenceProfileURI: qualification.ScopeProfileURI,
		AuthorityTimeProofDigest: qualification.AuthorityTimeProofDigest}
	if err := verifier.VerifyOutcomeAuthorityTime(timeProof, item, now); err != nil {
		t.Fatal(err)
	}
	if err := verifier.VerifyOutcomeIssuerQualification(qualification, item, timeProof, now); err != nil {
		t.Fatal(err)
	}
	item.SubjectDescriptor = "execution:two"
	if verifier.VerifyOutcomeIssuerQualification(qualification, item, timeProof, now) == nil {
		t.Fatal("qualification escaped its exact subject scope")
	}
}
