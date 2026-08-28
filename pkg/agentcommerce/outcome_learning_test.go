package agentcommerce

import "testing"

func TestLearningManifestRetainsNegativeDenominators(t *testing.T) {
	manifest := LearningDatasetManifestV1{ManifestID: outcomeDigest("1"), IncludedAssertionSetRoot: outcomeDigest("2"), IncludedCount: 8,
		ExcludedAssertionSetRoot: outcomeDigest("3"), ExcludedCount: 2, ConflictAssertionSetRoot: outcomeDigest("4"), ConflictCount: 1,
		CensoredAssertionSetRoot: outcomeDigest("5"), CensoredCount: 3, CohortCheckpointRoot: outcomeDigest("6"),
		ClusterPolicyDigest: outcomeDigest("7"), SamplingPolicyDigest: outcomeDigest("8"), WeightPolicyDigest: outcomeDigest("9"),
		ProducerConcentrationDigest: outcomeDigest("a"), SoftwareBuildDigest: outcomeDigest("b"), EvaluationHoldoutSetRoot: outcomeDigest("c"),
		AuthorityCutDigest: outcomeDigest("d")}
	if err := ValidateLearningDatasetManifestV1(manifest); err != nil {
		t.Fatal(err)
	}
	decision := SkillPromotionDecisionV1{DecisionID: outcomeDigest("1"), PriorSkillDigest: outcomeDigest("2"), CandidateSkillDigest: outcomeDigest("3"),
		DatasetManifestDigest: outcomeDigest("4"), EvaluationReportDigest: outcomeDigest("5"), RegressionThresholdDigest: outcomeDigest("6"),
		SafetyThresholdDigest: outcomeDigest("7"), ApproverAuthorityDigest: outcomeDigest("8"), RollbackTargetDigest: outcomeDigest("2"),
		StableActionID: outcomeDigest("9"), ExactRequestDigest: outcomeDigest("a"), Decision: "approved", DecidedAtUnix: 2_000_000_000}
	if err := ValidateSkillPromotionDecisionV1(decision); err != nil {
		t.Fatal(err)
	}
	decision.CandidateSkillDigest = decision.PriorSkillDigest
	if ValidateSkillPromotionDecisionV1(decision) == nil {
		t.Fatal("no-op Skill promotion was accepted")
	}
}
