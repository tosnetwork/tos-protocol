package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"sort"
)

// ValidateConformanceBodyValue is an exhaustive semantic admission gate for
// positive codec fixtures. Adding an object kind without adding a case makes
// fixture generation fail; reflective placeholder values can never silently
// become released positive vectors.
func ValidateConformanceBodyValue(kind string, body any) error {
	digests := func(values ...[]byte) bool {
		for _, value := range values {
			if len(value) != sha256.Size {
				return false
			}
		}
		return true
	}
	validSubject := func(value TypedAuthoritySubjectV1) bool {
		return value.Kind != "" && value.Namespace != "" && len(value.Identifier) > 0
	}
	validWindow := func(start, end uint64) bool { return start > 0 && start < end }
	switch value := body.(type) {
	case *ExecutableCapabilityArtifactBodyV1:
		return ValidateExecutableArtifact(*value)
	case *CapabilityContentManifestV1:
		return ValidateContentManifest(*value)
	case *CapabilityEntrypointDescriptorV1:
		return ValidateEntrypointDescriptor(*value)
	case *CapabilityPermissionManifestV1:
		return ValidatePermissionManifest(*value)
	case *DependencyManifestV1:
		return ValidateDependencyManifest(*value, value.ArtifactPreManifestDigest)
	case *ArtifactPublisherEnvelopeBodyV1:
		if value.SchemaVersion != SchemaVersion || value.ArtifactKind != "skill" || !validSubject(value.PublisherSubject) ||
			!digests(value.ArtifactPreManifestDigest, value.ContentManifestDigest, value.EntrypointDescriptorDigest) || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) || value.RevocationGeneration == 0 {
			return errors.New("publisher envelope conformance semantics are invalid")
		}
	case *PublisherRevocationObservationV1:
		return ValidatePublisherRevocationObservation(*value, value.PublisherSubject, value.ArtifactVersionDigest, value.PublisherEnvelopeDigest, value.ObservedAtUnix)
	case *CapabilityRequirementV1:
		cost, ok := new(big.Int).SetString(value.MaximumDirectCostAtomic, 10)
		if value.SchemaVersion != SchemaVersion || !digests(value.AgreementDigest, value.ObligationID, value.SemanticCapabilityDigest, value.InputSchemaDigest,
			value.OutputSchemaDigest, value.EvidenceRequirementDigest, value.PermissionCeilingDigest, value.CompilerEvidenceDigest) || !ok || cost.Sign() < 0 || cost.String() != value.MaximumDirectCostAtomic ||
			value.MaximumRuntimeMillis == 0 || value.PolicyRevision == 0 || value.InventoryRevision == 0 || !validWindow(value.CreatedAtUnix, value.ExpiresAtUnix) || !sortedUnique(value.AllowedArtifactKinds) {
			return errors.New("capability requirement conformance semantics are invalid")
		}
	case *CapabilitySourcingDecisionV1:
		if value.SelectedArtifactVersionDigest == nil {
			return errors.New("sourcing decision lacks candidate")
		}
		return ValidateSourcingDecision(*value, *value.SelectedArtifactVersionDigest, value.OwnerID, value.AgentID, value.OwnerSourcePolicyDigest, value.PolicyRevision, value.CreatedAtUnix+10)
	case *CapabilityEvaluationManifestV1:
		promotion := PromotionAuthorityBodyV1{CandidateArtifactVersionDigest: value.CandidateArtifactDigest, CandidatePermissionManifestDigest: value.PermissionManifestDigest,
			UnseenTaskCommitment: value.UnseenTaskCommitment, PrimaryMetricResultDigest: value.PrimaryMetricResultDigest, HarmMetricResultDigest: value.HarmMetricResultDigest,
			AllowedRegressionBoundsDigest: value.AllowedRegressionBoundsDigest, RetainedControlArtifactDigest: value.RetainedControlArtifactDigest,
			RetainedControlResultDigest: value.RetainedControlResultDigest, RollbackArtifactDigest: value.RollbackArtifactDigest, RollbackPlanDigest: value.RollbackPlanDigest}
		return ValidateEvaluationManifest(*value, promotion, value.PolicyDigest, value.PolicyRevision, value.CreatedAtUnix)
	case *EvaluationResultV1:
		if value.SchemaVersion != SchemaVersion || !digests(value.CandidateArtifactDigest, value.PermissionManifestDigest, value.RuntimeSandboxDigest, value.CorpusCommitment,
			value.AllocationSeed, value.CompleteResultSetDigest, value.ExclusionSetDigest, value.MetricDefinitionDigest, value.ThresholdDigest,
			value.RetainedControlResultDigest, value.PolicyDigest) || ValidateReference(value.RevealReference) != nil || value.PolicyRevision == 0 || !validWindow(value.ObservedAtUnix, value.ExpiresAtUnix) {
			return errors.New("evaluation result conformance semantics are invalid")
		}
	case *EvaluationEvidenceV1:
		return ValidateEvaluationEvidence(*value, value.EvidenceKind, value.CandidateDigest, value.PermissionDigest, value.PolicyDigest, value.CreatedAtUnix)
	case *ProfileAuthorizationEnvelopeV1:
		if value.Body.SchemaVersion != SchemaVersion || len(value.Proofs) != 1 || !digests(value.Body.BodyDigest, value.Body.PolicyDigest, value.Body.ProofSetDigest, value.Body.ExtensionsDigest) {
			return errors.New("authorization envelope conformance semantics are invalid")
		}
	case *OwnerPolicyBodyV1:
		if len(value.OwnerID) == 0 || len(value.PolicyID) == 0 || value.Revision == 0 || value.AuthorityEpoch == 0 ||
			!digests(value.AuthorityProfileSetDigest, value.CommandProfileSetDigest, value.CapabilityPolicyDigest, value.PromotionSeparationPolicyDigest,
				value.RecoveryQuorumDigest, value.ValidTimeProfileDigest) || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("owner policy conformance semantics are invalid")
		}
	case *CapabilityAdmissionBodyV1:
		return ValidateAdmission(*value, value.NotBeforeUnix)
	case *AuthorityMutationV1:
		if len(value.ObjectID) == 0 || value.TargetRevision != value.PriorRevision+1 || !digests(value.PredecessorEnvelopeDigest, value.EvidenceManifestDigest) ||
			value.MutationKind != "revoke" || value.EffectiveAtUnix == 0 || value.RevocationGeneration == 0 {
			return errors.New("authority mutation conformance semantics are invalid")
		}
	case *PromotionAuthorityBodyV1:
		if value.SchemaVersion != SchemaVersion || len(value.PromotionID) != 16 || len(value.OwnerID) == 0 || len(value.AgentID) == 0 ||
			!digests(value.CandidateArtifactVersionDigest, value.CandidatePermissionManifestDigest, value.CandidateOriginDigest, value.GeneratorIdentityDigest,
				value.SourcingDecisionDigest, value.EvaluationManifestDigest, value.RetainedControlArtifactDigest, value.RetainedControlResultDigest,
				value.UnseenTaskCommitment, value.PrimaryMetricResultDigest, value.HarmMetricResultDigest, value.AllowedRegressionBoundsDigest,
				value.ApproverPolicyDigest, value.ActivationScopeDigest, value.PolicyDigest, value.RollbackArtifactDigest, value.RollbackPlanDigest) ||
			ValidateReference(value.EvaluationResultReference) != nil || ValidateReference(value.VerifierAuthorizationEnvelopeReference) != nil ||
			!validSubject(value.IndependentVerifierSubject) || !validSubject(value.ApproverSubject) || equalAuthoritySubject(value.IndependentVerifierSubject, value.ApproverSubject) ||
			value.PolicyRevision == 0 || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) || value.RevocationGeneration == 0 {
			return errors.New("promotion authority conformance semantics are invalid")
		}
	case *CapabilityUseLeaseV1:
		return ValidateUseLease(*value, value.NotBeforeUnix, value.AuthorityEpoch, value.AdmissionRevocationGeneration, valueOrZero(value.PromotionRevocationGeneration))
	case *CapabilityInstallationTransactionV1:
		if value.SchemaVersion != SchemaVersion || len(value.InstallationID) != 16 || value.State != "prepared" || value.ExpectedInventoryRevision == 0 || value.PolicyRevision == 0 ||
			ValidateReference(value.SourceObjectReference) != nil || !digests(value.ArtifactVersionDigest, value.QuarantineObjectDigest, value.TargetStoreDigest,
			value.DependencyClosureDigest, value.InstallPlanDigest, value.RollbackPlanDigest, value.AdmissionEnvelopeDigest, value.WriterFenceDigest, value.StableActionID, value.ExactRequestDigest) {
			return errors.New("installation transaction conformance semantics are invalid")
		}
	case *CapabilityInventorySnapshotV1:
		return ValidateInventorySnapshot(*value, value.CreatedAtUnix)
	case *CapabilityUseBindingV1:
		return ValidateUseBindingShape(*value, value.RemoteSessionHandshakeDigest != nil)
	case *OwnerReportDescriptorV1:
		if len(value.ReportID) == 0 || len(value.ReportSeriesID) == 0 || len(value.OwnerID) == 0 || value.ReportProfileURI == "" || value.ReportProfileVersion == 0 ||
			value.ReportKind != "finance-daily" || value.PolicyRevision == 0 || !digests(value.ProducerArtifactVersionDigest, value.PolicyDigest, value.AccountingPolicyDigest,
			value.EconomicPerimeterDigest, value.SourceSnapshotDigest, value.SourceCoverageManifestDigest, value.QueryDigest, value.EvidenceManifestDigest,
			value.TypedReportDigest, value.RenderedReportDigest, value.AttachmentSetDigest) || value.PeriodStartUnix >= value.PeriodEndUnix ||
			value.CutoffUnix < value.PeriodEndUnix || value.CreatedAtUnix < value.CutoffUnix || value.Completeness != "complete" || value.CorrectionRevision != 0 || value.PriorReportDigest != nil || value.CorrectionReasonAndDeltaDigest != nil {
			return errors.New("owner report conformance semantics are invalid")
		}
	case *ReportSourceCoverageManifestV1:
		if value.SchemaVersion != SchemaVersion || len(value.ReportID) == 0 || value.CoverageCutoffUnix == 0 || value.Completeness != "complete" || len(value.MissingSourceIDs) != 0 || !digests(value.EvidenceRootDigest) {
			return errors.New("report coverage conformance semantics are invalid")
		}
	case *OwnerProjectionEventV1:
		if value.SchemaVersion != SchemaVersion || len(value.ProjectionSourceID) == 0 || len(value.OwnerID) == 0 || !digests(value.EventID, value.AuthorityReferenceSetDigest,
			value.EvidenceReferenceSetDigest, value.RedactionProfileDigest) || value.SourceSequence != 0 || value.PriorEventDigest != nil || value.ObjectKind == "" || len(value.ObjectID) == 0 ||
			value.ObjectRevision == 0 || value.EventKind == "" || value.OccurredAtUnix > value.EmittedAtUnix || value.FreshnessObservedAtUnix > value.EmittedAtUnix {
			return errors.New("projection event conformance semantics are invalid")
		}
	case *OwnerProjectionSnapshotV1:
		if value.SchemaVersion != SchemaVersion || value.DomainKind == 0 || len(value.DomainID) == 0 || len(value.OwnerID) == 0 || value.SnapshotRevision == 0 ||
			!digests(value.PolicyDigest, value.RedactionProfileDigest, value.EventSetMerkleRoot, value.VerifiedStateRoot, value.AdvisoryStateRoot, value.GapRoot, value.ConflictRoot) ||
			value.MaterializerVersion == "" || value.CreatedAtUnix == 0 || value.SnapshotRevision == 1 && value.PredecessorSnapshotDigest != nil ||
			value.SnapshotRevision > 1 && (value.PredecessorSnapshotDigest == nil || !digests(*value.PredecessorSnapshotDigest)) || !validProjectionSources(value.SourceCheckpoints) {
			return errors.New("projection snapshot conformance semantics are invalid")
		}
	case *OwnerBootstrapCeremonyV1:
		if value.SchemaVersion != SchemaVersion || value.DomainKind == 0 || len(value.DomainID) == 0 || len(value.OwnerID) == 0 || !validSubject(value.RootSubject) ||
			!digests(value.PossessionChallengeDigest, value.GenesisPolicyObjectDigest, value.AuthoritySubjectSetDigest, value.CeremonyNonce, value.OwnerConfirmationDigest) ||
			value.Generation != 0 || value.State != "owner-confirmed" || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("owner bootstrap conformance semantics are invalid")
		}
	case *OwnerAuthorityRecoveryV1:
		if len(value.RecoveryID) == 0 || len(value.OwnerID) == 0 || value.RecoveryEpoch == 0 || !digests(value.LastCommonPolicyDigest, value.ObservedForkRoot,
			value.ReplacementAuthoritySetDigest, value.RecoveryQuorumEvidenceDigest, value.SelectedHeadDigest) || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("owner recovery conformance semantics are invalid")
		}
	case *OwnerDeviceEnrollmentV1:
		if len(value.EnrollmentID) != 16 || len(value.DomainID) == 0 || len(value.OwnerID) == 0 || len(value.DevicePublicKey) != 32 || value.Audience == "" ||
			!digests(value.ChallengeDigest, value.RequestedCommandClassesDigest, value.ChannelBindingDigest, value.PolicyDigest) || value.PolicyRevision == 0 || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("device enrollment conformance semantics are invalid")
		}
	case *OwnerDeviceSessionV1:
		if len(value.SessionID) != 16 || !validSubject(value.IssuerSubject) || len(value.OwnerID) == 0 || len(value.DevicePublicKey) != 32 || value.Audience == "" ||
			!digests(value.AllowedCommandClassesDigest, value.ChannelBindingDigest, value.PolicyDigest) || value.SessionGeneration == 0 || value.SessionRevocationGeneration == 0 ||
			value.AuthorityEpoch == 0 || value.PolicyRevision == 0 || ValidateReference(value.RevocationObjectReference) != nil || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("device session conformance semantics are invalid")
		}
	case *OwnerCommandLeaseV1:
		if value.SchemaVersion != SchemaVersion || !digests(value.LeaseID, value.AllowedCommandClassesDigest, value.PolicyDigest) || value.DomainKind == 0 || len(value.DomainID) == 0 ||
			len(value.OwnerID) == 0 || len(value.DeviceSessionDigest) != 32 || value.Audience == "" || len(value.SinkAuthorityID) == 0 || value.SinkClusterEpoch == 0 ||
			value.ControlScopeGeneration == 0 || value.PolicyRevision == 0 || value.AuthorityEpoch == 0 || !validWindow(value.NotBeforeUnix, value.ExpiresAtUnix) {
			return errors.New("owner command lease conformance semantics are invalid")
		}
	case *OwnerCommandEffectV1:
		return ValidateOwnerCommandEffect(*value)
	case *OwnerCommandAuthorizationAttemptV1:
		if !digests(value.CommandEffectDigest, value.ActionID, value.ExactRequestDigest, value.DeviceSessionDigest, value.CommandLeaseDigest) ||
			value.SessionGeneration == 0 || value.SessionRevocationGeneration == 0 || value.AuthorityEpoch == 0 || !validWindow(value.AttemptedAtUnix, value.ExpiresAtUnix) {
			return errors.New("owner command attempt conformance semantics are invalid")
		}
	case *OwnerCommandResolutionV1:
		return ValidateOwnerCommandResolution(*value)
	case *SemanticConfirmationV1:
		if value.DisplayProfileURI != OwnerCommandConfirmationProfileV1 || value.DisplayProfileVersion != 1 || value.RiskClass != "bounded" ||
			len(value.DomainID) == 0 || len(value.OwnerID) == 0 || len(value.ActionID) != 32 || value.CommandKind != "owner.pause" || value.Target == "" ||
			value.PermissionDelta == nil || value.PolicyDelta == nil || len(value.CriticalParameters) != 3 || value.ExpiresAtUnix == 0 {
			return errors.New("semantic confirmation conformance semantics are invalid")
		}
	case *OwnerExitPlanV1:
		if len(value.ExitID) != 16 || len(value.OwnerID) == 0 || !digests(value.PredecessorPolicyDigest, value.StageEvidenceRoot, value.AmbiguousActionSetRoot,
			value.CustodyDispositionDigest, value.ExportDigest) || value.Stage != "fence-new-work" || value.TombstoneDigest != nil || value.Revision != 1 {
			return errors.New("owner exit conformance semantics are invalid")
		}
	case *CapabilityInventoryMigrationV1:
		if value.SchemaVersion != SchemaVersion || len(value.MigrationID) != 16 || len(value.OwnerID) == 0 || len(value.AgentID) == 0 ||
			len(value.InstallationID) != 16 || value.DeploymentFormatEpoch == 0 || value.CutoverEpoch == 0 || value.SourceStoreGeneration == 0 || value.SourceSnapshotCount == 0 ||
			value.SourceWriterEpoch == 0 || value.TargetWriterEpoch <= value.SourceWriterEpoch || value.MaximumLegacyAuthorityExpiryUnix == 0 || len(value.DurableCursor) == 0 ||
			!digests(value.DeploymentSinkMembershipSnapshotDigest, value.SinkFenceAndHandleAcknowledgementRoot, value.UnreachableSinkDispositionRoot,
				value.SourceStoreIdentityDigest, value.SourceSnapshotRoot, value.TargetInventoryRoot, value.PerRecordClassificationRoot, value.ReconciliationResultDigest) ||
			value.State != "prepared" || value.PredecessorMigrationDigest != nil || value.CreatedAtUnix == 0 {
			return errors.New("migration conformance semantics are invalid")
		}
	case *ActionOutcomeEvidenceV1:
		return ValidateActionOutcomeEvidence(*value, value.ObservedAtUnix)
	default:
		return errors.New("released object kind lacks a conformance semantic validator")
	}
	return nil
}

func validProjectionSources(values []OwnerProjectionSourceCheckpointV1) bool {
	if len(values) == 0 {
		return false
	}
	for index, value := range values {
		if len(value.ProjectionSourceID) == 0 || value.SourceGeneration == 0 || len(value.ChainHeadDigest) != sha256.Size ||
			index > 0 && bytes.Compare(values[index-1].ProjectionSourceID, value.ProjectionSourceID) >= 0 {
			return false
		}
	}
	return true
}

func valueOrZero(value *uint64) uint64 {
	if value == nil {
		return 0
	}
	return *value
}

func sortedUniqueBytes(values [][]byte) bool {
	return sort.SliceIsSorted(values, func(i, j int) bool { return bytes.Compare(values[i], values[j]) < 0 })
}
