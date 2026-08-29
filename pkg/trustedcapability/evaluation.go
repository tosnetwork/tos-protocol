package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sort"
)

// ValidateSourcingDecision validates the portable completeness and
// independence predicates used by V1 consequential promotion. Source-local
// absence remains advisory: this function only proves what was attempted.
func ValidateSourcingDecision(body CapabilitySourcingDecisionV1, candidate, ownerID, agentID, policyDigest []byte, policyRevision, now uint64) error {
	if body.SchemaVersion != SchemaVersion || !bytes.Equal(body.OwnerID, ownerID) || !bytes.Equal(body.AgentID, agentID) ||
		len(body.RequirementDigest) != sha256.Size || !bytes.Equal(body.OwnerSourcePolicyDigest, policyDigest) || body.PolicyRevision != policyRevision ||
		body.CreatedAtUnix == 0 || body.CreatedAtUnix > now || now >= body.ExpiresAtUnix || body.Decision != "request-admission" ||
		body.SelectedArtifactVersionDigest == nil || !bytes.Equal(*body.SelectedArtifactVersionDigest, candidate) || len(body.SourceAttempts) < 2 {
		return errors.New("sourcing decision is incomplete, stale, or does not select the candidate")
	}
	seenSources := map[string]struct{}{}
	admin := map[string]struct{}{}
	failure := map[string]struct{}{}
	var previousAttempt []byte
	for _, attempt := range body.SourceAttempts {
		canonicalAttempt, canonicalErr := MarshalBody(attempt)
		if len(attempt.SourceID) == 0 || attempt.SourceGeneration == 0 || ValidateReference(attempt.SourceSnapshotReference) != nil ||
			len(attempt.QueryCommitment) != sha256.Size || len(attempt.ResultCommitment) != sha256.Size ||
			len(attempt.AdministrativeDomainDigest) != sha256.Size || len(attempt.FailureDomainDigest) != sha256.Size ||
			attempt.StartedAtUnix == 0 || attempt.CompletedAtUnix < attempt.StartedAtUnix || attempt.CompletedAtUnix > now || attempt.Disposition != "complete" ||
			canonicalErr != nil || previousAttempt != nil && bytes.Compare(previousAttempt, canonicalAttempt) >= 0 {
			return errors.New("sourcing attempt is incomplete or not complete")
		}
		previousAttempt = canonicalAttempt
		key := string(attempt.SourceID)
		if _, duplicate := seenSources[key]; duplicate {
			return errors.New("duplicate sourcing source")
		}
		seenSources[key] = struct{}{}
		admin[string(attempt.AdministrativeDomainDigest)] = struct{}{}
		failure[string(attempt.FailureDomainDigest)] = struct{}{}
	}
	if len(admin) < 2 || len(failure) < 2 {
		return errors.New("sourcing sources are not independently administered and failed")
	}
	found := false
	var previousDecision []byte
	for _, decision := range body.CandidateDecisions {
		canonicalDecision, canonicalErr := MarshalBody(decision)
		if len(decision.ArtifactVersionDigest) != sha256.Size || len(decision.EvidenceManifestDigest) != sha256.Size ||
			!sort.StringsAreSorted(decision.StableReasonCodes) || canonicalErr != nil || previousDecision != nil && bytes.Compare(previousDecision, canonicalDecision) >= 0 {
			return errors.New("candidate decision is malformed")
		}
		previousDecision = canonicalDecision
		if bytes.Equal(decision.ArtifactVersionDigest, candidate) && decision.Disposition == "eligible" {
			found = true
		}
	}
	if !found {
		return errors.New("selected candidate is not eligible in sourcing decision")
	}
	return nil
}

func ValidateEvaluationManifest(body CapabilityEvaluationManifestV1, promotion PromotionAuthorityBodyV1, policyDigest []byte, policyRevision, now uint64) error {
	digests := [][]byte{body.CandidateArtifactDigest, body.PermissionManifestDigest, body.RuntimeSandboxDigest, body.PolicyDigest,
		body.CorpusCommitment, body.UnseenTaskCommitment, body.CompleteResultSetDigest, body.PrimaryMetricResultDigest,
		body.HarmMetricResultDigest, body.AllowedRegressionBoundsDigest, body.RetainedControlArtifactDigest,
		body.RetainedControlResultDigest, body.RollbackArtifactDigest, body.RollbackPlanDigest, body.EvaluatorIdentityDigest, body.ReproducibilityDigest}
	for _, digest := range digests {
		if len(digest) != sha256.Size {
			return errors.New("evaluation manifest contains an invalid digest")
		}
	}
	if body.SchemaVersion != SchemaVersion || body.PolicyRevision != policyRevision || !bytes.Equal(body.PolicyDigest, policyDigest) ||
		body.CreatedAtUnix == 0 || body.CreatedAtUnix > now || now >= body.ExpiresAtUnix ||
		!bytes.Equal(body.CandidateArtifactDigest, promotion.CandidateArtifactVersionDigest) ||
		!bytes.Equal(body.PermissionManifestDigest, promotion.CandidatePermissionManifestDigest) ||
		!bytes.Equal(body.UnseenTaskCommitment, promotion.UnseenTaskCommitment) ||
		!bytes.Equal(body.PrimaryMetricResultDigest, promotion.PrimaryMetricResultDigest) ||
		!bytes.Equal(body.HarmMetricResultDigest, promotion.HarmMetricResultDigest) ||
		!bytes.Equal(body.AllowedRegressionBoundsDigest, promotion.AllowedRegressionBoundsDigest) ||
		!bytes.Equal(body.RetainedControlArtifactDigest, promotion.RetainedControlArtifactDigest) ||
		!bytes.Equal(body.RetainedControlResultDigest, promotion.RetainedControlResultDigest) ||
		!bytes.Equal(body.RollbackArtifactDigest, promotion.RollbackArtifactDigest) || !bytes.Equal(body.RollbackPlanDigest, promotion.RollbackPlanDigest) {
		return errors.New("evaluation manifest does not bind the promotion predicate")
	}
	if len(body.EvidenceObjectDigests) < 8 || !canonicalDigestSet(body.EvidenceObjectDigests) {
		return errors.New("evaluation evidence set is incomplete or non-canonical")
	}
	return nil
}

func ValidatePublisherRevocationObservation(body PublisherRevocationObservationV1, publisher TypedAuthoritySubjectV1, artifactDigest, envelopeDigest []byte, now uint64) error {
	if body.SchemaVersion != SchemaVersion || !equalAuthoritySubject(body.PublisherSubject, publisher) ||
		!bytes.Equal(body.ArtifactVersionDigest, artifactDigest) || !bytes.Equal(body.PublisherEnvelopeDigest, envelopeDigest) ||
		body.ObservedGeneration == 0 || len(body.SourceID) == 0 || body.SourceGeneration == 0 || len(body.CheckpointRoot) != sha256.Size ||
		body.ObservedAtUnix == 0 || body.ObservedAtUnix > now || now >= body.ExpiresAtUnix {
		return errors.New("publisher revocation observation is incomplete, stale, or cross-artifact")
	}
	return nil
}

func ValidateEvaluationEvidence(body EvaluationEvidenceV1, kind string, candidate, permission, policy []byte, now uint64) error {
	if body.SchemaVersion != SchemaVersion || body.EvidenceKind != kind || !bytes.Equal(body.CandidateDigest, candidate) ||
		!bytes.Equal(body.PermissionDigest, permission) || !bytes.Equal(body.PolicyDigest, policy) || len(body.ProducerDigest) != sha256.Size ||
		len(body.ContentCommitment) != sha256.Size || body.CreatedAtUnix == 0 || body.CreatedAtUnix > now || now >= body.ExpiresAtUnix {
		return errors.New("evaluation evidence does not bind the current candidate predicate")
	}
	return nil
}

func canonicalDigestSet(values [][]byte) bool {
	var previous []byte
	for _, value := range values {
		if len(value) != sha256.Size || previous != nil && bytes.Compare(previous, value) >= 0 {
			return false
		}
		previous = value
	}
	return true
}
