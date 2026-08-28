package agentcommerce

import "testing"

func TestOutcomeAssertionSetRootIsOrderedTypedAndDuplicateFree(t *testing.T) {
	left := OutcomeAssertionRefV1{NetworkID: "tos:test", ActorAgentID: "agent:a", OperationID: outcomeDigest("1"), OperationEnvelopeDigest: outcomeDigest("2")}
	right := OutcomeAssertionRefV1{NetworkID: "tos:test", ActorAgentID: "agent:b", OperationID: outcomeDigest("3"), OperationEnvelopeDigest: outcomeDigest("4")}
	forward, err := OutcomeAssertionSetRootV1([]OutcomeAssertionRefV1{left, right})
	if err != nil {
		t.Fatal(err)
	}
	reverse, err := OutcomeAssertionSetRootV1([]OutcomeAssertionRefV1{right, left})
	if err != nil || forward != reverse {
		t.Fatalf("canonical roots differ: %s %s err=%v", forward, reverse, err)
	}
	if _, err := OutcomeAssertionSetRootV1([]OutcomeAssertionRefV1{left, left}); err == nil {
		t.Fatal("duplicate cohort member accepted")
	}
	empty, err := OutcomeAssertionSetRootV1(nil)
	if err != nil || empty == forward {
		t.Fatalf("typed empty root=%s err=%v", empty, err)
	}
}

func TestOutcomeCohortMembershipProofHandlesOddPromotion(t *testing.T) {
	refs := []OutcomeAssertionRefV1{
		{NetworkID: "tos:test", ActorAgentID: "agent:c", OperationID: outcomeDigest("5"), OperationEnvelopeDigest: outcomeDigest("6")},
		{NetworkID: "tos:test", ActorAgentID: "agent:a", OperationID: outcomeDigest("1"), OperationEnvelopeDigest: outcomeDigest("2")},
		{NetworkID: "tos:test", ActorAgentID: "agent:b", OperationID: outcomeDigest("3"), OperationEnvelopeDigest: outcomeDigest("4")},
	}
	proof, root, err := BuildOutcomeCohortMembershipProofV1(refs, refs[0])
	if err != nil || VerifyOutcomeCohortMembershipProofV1(proof, root) != nil {
		t.Fatalf("root=%s proof=%+v err=%v", root, proof, err)
	}
	if expected, err := OutcomeAssertionSetRootV1(refs); err != nil || expected != root {
		t.Fatalf("proof root differs from set root: %s %s %v", root, expected, err)
	}
	proof.Member.OperationEnvelopeDigest = outcomeDigest("7")
	if VerifyOutcomeCohortMembershipProofV1(proof, root) == nil {
		t.Fatal("mutated membership leaf verified")
	}
}
