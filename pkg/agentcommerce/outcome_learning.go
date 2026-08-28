package agentcommerce

import "errors"

// LearningDatasetManifestV1 makes adverse, excluded, conflicted and censored
// rows part of the immutable training cut. It is evidence metadata only and
// carries no Skill-installation authority.
type LearningDatasetManifestV1 struct {
	ManifestID                  string `json:"manifest_id"`
	IncludedAssertionSetRoot    string `json:"included_assertion_set_root"`
	IncludedCount               uint64 `json:"included_count"`
	ExcludedAssertionSetRoot    string `json:"excluded_assertion_set_root"`
	ExcludedCount               uint64 `json:"excluded_count"`
	ConflictAssertionSetRoot    string `json:"conflict_assertion_set_root"`
	ConflictCount               uint64 `json:"conflict_count"`
	CensoredAssertionSetRoot    string `json:"censored_assertion_set_root"`
	CensoredCount               uint64 `json:"censored_count"`
	CohortCheckpointRoot        string `json:"cohort_checkpoint_root"`
	ClusterPolicyDigest         string `json:"cluster_policy_digest"`
	SamplingPolicyDigest        string `json:"sampling_policy_digest"`
	WeightPolicyDigest          string `json:"weight_policy_digest"`
	ProducerConcentrationDigest string `json:"producer_concentration_digest"`
	SoftwareBuildDigest         string `json:"software_build_digest"`
	EvaluationHoldoutSetRoot    string `json:"evaluation_holdout_set_root"`
	AuthorityCutDigest          string `json:"authority_cut_digest"`
}

type SkillPromotionDecisionV1 struct {
	DecisionID                string `json:"decision_id"`
	PriorSkillDigest          string `json:"prior_skill_digest"`
	CandidateSkillDigest      string `json:"candidate_skill_digest"`
	DatasetManifestDigest     string `json:"dataset_manifest_digest"`
	EvaluationReportDigest    string `json:"evaluation_report_digest"`
	RegressionThresholdDigest string `json:"regression_threshold_digest"`
	SafetyThresholdDigest     string `json:"safety_threshold_digest"`
	ApproverAuthorityDigest   string `json:"approver_authority_digest"`
	RollbackTargetDigest      string `json:"rollback_target_digest"`
	StableActionID            string `json:"stable_action_id"`
	ExactRequestDigest        string `json:"exact_request_digest"`
	Decision                  string `json:"decision"`
	DecidedAtUnix             uint64 `json:"decided_at_unix"`
}

func ValidateLearningDatasetManifestV1(value LearningDatasetManifestV1) error {
	if !digest32(value.ManifestID) || !digest32(value.IncludedAssertionSetRoot) || !digest32(value.ExcludedAssertionSetRoot) ||
		!digest32(value.ConflictAssertionSetRoot) || !digest32(value.CensoredAssertionSetRoot) ||
		!digest32(value.CohortCheckpointRoot) || !digest32(value.ClusterPolicyDigest) || !digest32(value.SamplingPolicyDigest) ||
		!digest32(value.WeightPolicyDigest) || !digest32(value.ProducerConcentrationDigest) || !digest32(value.SoftwareBuildDigest) ||
		!digest32(value.EvaluationHoldoutSetRoot) || !digest32(value.AuthorityCutDigest) ||
		value.IncludedCount > uint64(^uint32(0)) || value.ExcludedCount > uint64(^uint32(0)) ||
		value.ConflictCount > uint64(^uint32(0)) || value.CensoredCount > uint64(^uint32(0)) {
		return errors.New("learning dataset manifest is invalid")
	}
	return nil
}

func ValidateSkillPromotionDecisionV1(value SkillPromotionDecisionV1) error {
	if !digest32(value.DecisionID) || !digest32(value.PriorSkillDigest) || !digest32(value.CandidateSkillDigest) ||
		value.PriorSkillDigest == value.CandidateSkillDigest || !digest32(value.DatasetManifestDigest) ||
		!digest32(value.EvaluationReportDigest) || !digest32(value.RegressionThresholdDigest) || !digest32(value.SafetyThresholdDigest) ||
		!digest32(value.ApproverAuthorityDigest) || !digest32(value.RollbackTargetDigest) || !digest32(value.StableActionID) ||
		!digest32(value.ExactRequestDigest) || !oneOf(value.Decision, "approved", "rejected", "rollback") || value.DecidedAtUnix == 0 {
		return errors.New("Skill promotion decision is invalid")
	}
	return nil
}
