package agentguarantor

import (
	"strings"
	"testing"
)

func stateDigest(digit string) string { return "sha256:" + strings.Repeat(digit, 64) }

func TestClaimRevisionAdvancesOneOpenLineage(t *testing.T) {
	current := ClaimRecord{ClaimID: stateDigest("1"), ClaimRevision: 1, ClaimStatus: ClaimEvidenceRequired,
		PayoutStatus: PayoutNotMaterialized, ClaimStateRevision: 4,
		CurrentClaimBodyDigest: stateDigest("2"), LastEvidenceDigest: stateDigest("9")}
	updated, err := ReviseAdmittedClaim(current, 2, stateDigest("2"), stateDigest("3"))
	if err != nil || updated.ClaimRevision != 2 || updated.ClaimStatus != ClaimAdmitted ||
		updated.ClaimStateRevision != 5 || updated.LastEvidenceDigest != stateDigest("3") {
		t.Fatalf("claim revision did not advance exactly once: %#v %v", updated, err)
	}
	for name, candidate := range map[string]ClaimRecord{
		"terminal claim":      func() ClaimRecord { value := current; value.ClaimStatus = ClaimFinalDenied; return value }(),
		"materialized payout": func() ClaimRecord { value := current; value.PayoutStatus = PayoutPrepared; return value }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ReviseAdmittedClaim(candidate, 2, stateDigest("2"), stateDigest("3")); err == nil {
				t.Fatal("unsafe claim revision was accepted")
			}
		})
	}
	if _, err := ReviseAdmittedClaim(current, 3, stateDigest("2"), stateDigest("3")); err == nil {
		t.Fatal("claim revision skipped its predecessor")
	}
	if _, err := ReviseAdmittedClaim(current, 2, stateDigest("4"), stateDigest("3")); err == nil {
		t.Fatal("claim revision substituted predecessor evidence")
	}
}
