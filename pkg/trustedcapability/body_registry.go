package trustedcapability

import (
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// BodyFieldSchemaV1 is one field in the released, recursively generated CBOR
// shape. Nested structs name their Go wire type so independent implementations
// can reject missing, placeholder, and unknown fields at every depth.
type BodyFieldSchemaV1 struct {
	CBORKey  uint64 `json:"cbor_key"`
	JSONName string `json:"json_name"`
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

type BodySchemaV1 struct {
	ObjectKind  string                 `json:"object_kind"`
	GoType      string                 `json:"go_type"`
	Fields      []BodyFieldSchemaV1    `json:"fields"`
	Definitions []BodyTypeDefinitionV1 `json:"definitions"`
}

type BodyTypeDefinitionV1 struct {
	TypeName string              `json:"type_name"`
	Fields   []BodyFieldSchemaV1 `json:"fields"`
}

var bodyTypes = map[string]reflect.Type{
	"artifact": reflect.TypeOf(ExecutableCapabilityArtifactBodyV1{}), "content-manifest": reflect.TypeOf(CapabilityContentManifestV1{}),
	"entrypoint-descriptor": reflect.TypeOf(CapabilityEntrypointDescriptorV1{}), "permission-manifest": reflect.TypeOf(CapabilityPermissionManifestV1{}),
	"dependency-manifest": reflect.TypeOf(DependencyManifestV1{}), "publisher-envelope": reflect.TypeOf(ArtifactPublisherEnvelopeBodyV1{}),
	"publisher-revocation-observation": reflect.TypeOf(PublisherRevocationObservationV1{}), "capability-requirement": reflect.TypeOf(CapabilityRequirementV1{}),
	"sourcing-decision": reflect.TypeOf(CapabilitySourcingDecisionV1{}), "evaluation-manifest": reflect.TypeOf(CapabilityEvaluationManifestV1{}),
	"evaluation-result": reflect.TypeOf(EvaluationResultV1{}), "evaluation-evidence": reflect.TypeOf(EvaluationEvidenceV1{}),
	"authorization-envelope": reflect.TypeOf(ProfileAuthorizationEnvelopeV1{}), "owner-policy": reflect.TypeOf(OwnerPolicyBodyV1{}),
	"capability-admission": reflect.TypeOf(CapabilityAdmissionBodyV1{}), "admission-mutation": reflect.TypeOf(AuthorityMutationV1{}),
	"promotion-authority": reflect.TypeOf(PromotionAuthorityBodyV1{}), "promotion-mutation": reflect.TypeOf(AuthorityMutationV1{}),
	"use-lease": reflect.TypeOf(CapabilityUseLeaseV1{}), "installation-transaction": reflect.TypeOf(CapabilityInstallationTransactionV1{}),
	"inventory-snapshot": reflect.TypeOf(CapabilityInventorySnapshotV1{}), "capability-use-binding": reflect.TypeOf(CapabilityUseBindingV1{}),
	"owner-report": reflect.TypeOf(OwnerReportDescriptorV1{}), "report-source-coverage": reflect.TypeOf(ReportSourceCoverageManifestV1{}),
	"projection-event": reflect.TypeOf(OwnerProjectionEventV1{}), "projection-snapshot": reflect.TypeOf(OwnerProjectionSnapshotV1{}),
	"owner-bootstrap": reflect.TypeOf(OwnerBootstrapCeremonyV1{}), "owner-recovery": reflect.TypeOf(OwnerAuthorityRecoveryV1{}),
	"device-enrollment": reflect.TypeOf(OwnerDeviceEnrollmentV1{}), "device-session": reflect.TypeOf(OwnerDeviceSessionV1{}),
	"owner-command-lease": reflect.TypeOf(OwnerCommandLeaseV1{}), "owner-command-effect": reflect.TypeOf(OwnerCommandEffectV1{}),
	"owner-command-attempt": reflect.TypeOf(OwnerCommandAuthorizationAttemptV1{}), "owner-command-resolution": reflect.TypeOf(OwnerCommandResolutionV1{}),
	"semantic-confirmation": reflect.TypeOf(SemanticConfirmationV1{}), "owner-exit-plan": reflect.TypeOf(OwnerExitPlanV1{}),
	"migration":               reflect.TypeOf(CapabilityInventoryMigrationV1{}),
	"action-outcome-evidence": reflect.TypeOf(ActionOutcomeEvidenceV1{}),
}

func NewBodyValue(objectKind string) (any, error) {
	typ, ok := bodyTypes[objectKind]
	if !ok {
		return nil, errors.New("unknown trusted capability body kind")
	}
	value := reflect.New(typ)
	initializeCollections(value.Elem())
	return value.Interface(), nil
}

// NewConformanceBodyValue returns a deterministic, populated object body for
// cross-implementation positive vectors. It is intentionally separate from
// NewBodyValue: zero values are useful decode targets but are never published
// as positive conformance examples.
func NewConformanceBodyValue(objectKind string, seed byte) (any, error) {
	typ, ok := bodyTypes[objectKind]
	if !ok {
		return nil, errors.New("unknown trusted capability body kind")
	}
	value := reflect.New(typ)
	populateConformanceValue(value.Elem(), "", seed, map[reflect.Type]bool{})
	if err := normalizeConformanceBody(objectKind, value.Interface()); err != nil {
		return nil, err
	}
	if err := ValidateConformanceBodyValue(objectKind, value.Interface()); err != nil {
		return nil, err
	}
	return value.Interface(), nil
}

func normalizeConformanceBody(kind string, body any) error {
	switch value := body.(type) {
	case *ExecutableCapabilityArtifactBodyV1:
		value.ArtifactKind = "skill"
		serviceID := bytesRepeat(2, 32)
		value.OptionalServiceCapabilityID = &serviceID
		return ValidateExecutableArtifact(*value)
	case *CapabilityContentManifestV1:
		value.Entries = []ContentManifestEntryV1{{Path: "SKILL.md", ObjectType: "regular", Mode: 0o444, Size: 7, ContentDigest: bytesRepeat(3, 32)}}
		root, err := ContentClosureRoot(value.Entries)
		value.ClosureRoot = root
		if err != nil {
			return err
		}
		return ValidateContentManifest(*value)
	case *CapabilityEntrypointDescriptorV1:
		return ValidateEntrypointDescriptor(*value)
	case *CapabilityPermissionManifestV1:
		value.ToolCapabilities = []string{}
		value.ProcessCapabilities = []string{}
		value.FilesystemCapabilities = []FilesystemCapabilityV1{}
		value.NetworkCapabilities = []NetworkCapabilityV1{}
		value.CredentialCapabilities = []CredentialCapabilityV1{}
		value.DataClassesRead = []string{}
		value.DataClassesWrite = []string{}
		value.DisclosureCapabilities = []DisclosureCapabilityV1{}
		value.UploadCapabilities = []UploadCapabilityV1{}
		value.DestructiveCapabilities = []string{}
		value.ResourceCeiling = ResourceCeilingV1{CPUMillis: 1, MemoryBytes: 1, StorageBytes: 1, RuntimeMillis: 1}
		value.DirectCostCeiling = "0"
		value.ConcurrencyCeiling = 1
		value.RetentionPolicy = RetentionPolicyV1{MaximumRetentionSeconds: 1, DeleteOnTerminal: true, EvidenceOnlyAfterDelete: true}
		value.LoggingPolicy = LoggingPolicyV1{AllowedDataClasses: []string{}, MaximumBytes: 1, RedactionRequired: true}
		value.Extensions = [][]byte{}
		return ValidatePermissionManifest(*value)
	case *DependencyManifestV1:
		value.Nodes = []DependencyNodeV1{}
		value.Edges = []DependencyEdgeV1{}
		closure, err := MarshalBody(struct {
			Nodes []DependencyNodeV1 `cbor:"1,keyasint"`
			Edges []DependencyEdgeV1 `cbor:"2,keyasint"`
		}{value.Nodes, value.Edges})
		if err != nil {
			return err
		}
		value.ClosureRootDigest = framedDigest("tos.capability-dependency-closure.v1", closure)
		return ValidateDependencyManifest(*value, value.ArtifactPreManifestDigest)
	case *ArtifactPublisherEnvelopeBodyV1:
		value.ArtifactKind = "skill"
		value.CreatedAtUnix, value.NotBeforeUnix, value.ExpiresAtUnix, value.RevocationGeneration = 2_000_000_000, 2_000_000_000, 2_000_003_600, 1
		artifact := ExecutableCapabilityArtifactBodyV1{SchemaVersion: SchemaVersion, ArtifactKind: value.ArtifactKind, ArtifactNamespace: value.ArtifactNamespace,
			ArtifactName: value.ArtifactName, ArtifactVersion: value.ArtifactVersion, PublisherSubject: value.PublisherSubject,
			PublisherAuthorityProfile: bytesRepeat(70, 32), SourceDescriptorDigest: bytesRepeat(71, 32), ContentManifestDigest: value.ContentManifestDigest,
			EntrypointDescriptorDigest: value.EntrypointDescriptorDigest, PermissionManifestDigest: value.PermissionManifestDigest,
			DependencyManifestDigest: value.DependencyManifestDigest, LicenseManifestDigest: bytesRepeat(72, 32), StandardsProfileSetDigest: bytesRepeat(73, 32),
			CompatibilityManifestDigest: bytesRepeat(74, 32), SupplyChainEvidenceDigest: bytesRepeat(75, 32), CreatedAtUnix: value.CreatedAtUnix, Extensions: [][]byte{}}
		pre, err := ArtifactPreManifestDigest(artifact)
		if err != nil {
			return err
		}
		value.ArtifactPreManifestDigest = pre
		return ValidatePublisherEnvelope(*value, artifact, 2_000_000_010)
	case *PublisherRevocationObservationV1:
		value.ObservedAtUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
		return ValidatePublisherRevocationObservation(*value, value.PublisherSubject, value.ArtifactVersionDigest, value.PublisherEnvelopeDigest, 2_000_000_010)
	case *CapabilityRequirementV1:
		value.ObligationID = bytesRepeat(91, 32)
		value.AllowedArtifactKinds = []string{"skill"}
		value.MaximumDirectCostAtomic = "0"
		value.CreatedAtUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *CapabilitySourcingDecisionV1:
		selected := bytesRepeat(31, 32)
		value.SelectedArtifactVersionDigest = &selected
		value.Decision = "request-admission"
		value.CreatedAtUnix = 2_000_000_000
		value.ExpiresAtUnix = 2_000_003_600
		value.SourceAttempts = []SourceAttemptV1{
			{SourceID: []byte("source-a"), SourceSnapshotReference: conformanceReference(32, "projection-snapshot"), AdvisorySourceCursor: "cursor-a", QueryCommitment: bytesRepeat(33, 32), StartedAtUnix: 2_000_000_000, CompletedAtUnix: 2_000_000_001, Disposition: "complete", ResultCommitment: bytesRepeat(34, 32), SourceGeneration: 1, AdministrativeDomainDigest: bytesRepeat(35, 32), FailureDomainDigest: bytesRepeat(36, 32)},
			{SourceID: []byte("source-b"), SourceSnapshotReference: conformanceReference(37, "projection-snapshot"), AdvisorySourceCursor: "cursor-b", QueryCommitment: bytesRepeat(38, 32), StartedAtUnix: 2_000_000_002, CompletedAtUnix: 2_000_000_003, Disposition: "complete", ResultCommitment: bytesRepeat(39, 32), SourceGeneration: 1, AdministrativeDomainDigest: bytesRepeat(40, 32), FailureDomainDigest: bytesRepeat(41, 32)},
		}
		sort.Slice(value.SourceAttempts, func(i, j int) bool {
			left, _ := MarshalBody(value.SourceAttempts[i])
			right, _ := MarshalBody(value.SourceAttempts[j])
			return string(left) < string(right)
		})
		value.CandidateDecisions = []CandidateDecisionV1{{ArtifactVersionDigest: selected, Disposition: "eligible", StableReasonCodes: []string{"policy-match"}, EvidenceManifestDigest: bytesRepeat(42, 32)}}
		return ValidateSourcingDecision(*value, selected, value.OwnerID, value.AgentID, value.OwnerSourcePolicyDigest, value.PolicyRevision, 2_000_000_010)
	case *CapabilityEvaluationManifestV1:
		value.CreatedAtUnix = 2_000_000_000
		value.ExpiresAtUnix = 2_000_003_600
		value.EvidenceObjectDigests = make([][]byte, 8)
		for i := range value.EvidenceObjectDigests {
			value.EvidenceObjectDigests[i] = bytesRepeat(byte(50+i), 32)
		}
		promotion := PromotionAuthorityBodyV1{CandidateArtifactVersionDigest: value.CandidateArtifactDigest, CandidatePermissionManifestDigest: value.PermissionManifestDigest,
			UnseenTaskCommitment: value.UnseenTaskCommitment, PrimaryMetricResultDigest: value.PrimaryMetricResultDigest, HarmMetricResultDigest: value.HarmMetricResultDigest,
			AllowedRegressionBoundsDigest: value.AllowedRegressionBoundsDigest, RetainedControlArtifactDigest: value.RetainedControlArtifactDigest,
			RetainedControlResultDigest: value.RetainedControlResultDigest, RollbackArtifactDigest: value.RollbackArtifactDigest, RollbackPlanDigest: value.RollbackPlanDigest}
		return ValidateEvaluationManifest(*value, promotion, value.PolicyDigest, value.PolicyRevision, 2_000_000_010)
	case *EvaluationResultV1:
		value.RevealReference = conformanceReference(76, "evaluation-evidence")
		value.ObservedAtUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *EvaluationEvidenceV1:
		value.EvidenceKind = "candidate-origin"
		value.CreatedAtUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
		return ValidateEvaluationEvidence(*value, value.EvidenceKind, value.CandidateDigest, value.PermissionDigest, value.PolicyDigest, 2_000_000_010)
	case *OwnerPolicyBodyV1:
		value.PredecessorPolicyDigest = nil
		value.Revision = 1
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *AuthorityMutationV1:
		value.PriorRevision, value.TargetRevision = 1, 2
		value.MutationKind, value.EffectiveAtUnix = "revoke", 2_000_000_000
	case *PromotionAuthorityBodyV1:
		value.AuthorityRevision, value.PredecessorEnvelopeDigest = 0, nil
		value.EvaluationResultReference = conformanceReference(77, "evaluation-result")
		value.VerifierAuthorizationEnvelopeReference = conformanceReference(78, "authorization-envelope")
		value.IndependentVerifierSubject = TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: Ed25519ProofProfile, Identifier: bytesRepeat(79, 32)}
		value.ApproverSubject = TypedAuthoritySubjectV1{Kind: "verification-key", Namespace: Ed25519ProofProfile, Identifier: bytesRepeat(80, 32)}
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *CapabilityInstallationTransactionV1:
		value.SourceObjectReference = conformanceReference(81, "artifact")
		value.StableActionID = bytesRepeat(92, 32)
		value.State = "prepared"
	case *CapabilityAdmissionBodyV1:
		value.InFlightRevocationPolicy = "kill-and-reconcile"
		return ValidateAdmission(*value, 2_000_000_001)
	case *CapabilityUseLeaseV1:
		value.LeaseID = bytesRepeat(11, 32)
		value.ExecutionID = bytesRepeat(12, 32)
		value.ActionID = bytesRepeat(13, 32)
		value.StartNotAfterUnix = 2_000_000_300
		return ValidateUseLease(*value, 2_000_000_001, 1, 1, 1)
	case *CapabilityUseBindingV1:
		value.ObligationID = bytesRepeat(14, 32)
		value.ExecutionID = bytesRepeat(15, 32)
		value.ActionID = bytesRepeat(16, 32)
		value.LoadedObjectDigest = append([]byte(nil), value.ArtifactVersionDigest...)
		return ValidateUseBindingShape(*value, value.RemoteSessionHandshakeDigest != nil)
	case *CapabilityInventorySnapshotV1:
		return ValidateInventorySnapshot(*value, 2_000_000_001)
	case *OwnerReportDescriptorV1:
		value.CorrectionRevision, value.PriorReportDigest, value.CorrectionReasonAndDeltaDigest = 0, nil, nil
		value.ReportKind, value.Completeness = "finance-daily", "complete"
		value.PeriodStartUnix, value.PeriodEndUnix, value.CutoffUnix, value.CreatedAtUnix = 2_000_000_000, 2_000_000_100, 2_000_000_100, 2_000_000_101
	case *ReportSourceCoverageManifestV1:
		value.RequiredSourceIDs, value.ObservedSources, value.MissingSourceIDs = [][]byte{}, []ImmutableObjectReferenceV1{}, [][]byte{}
		value.Completeness, value.CoverageCutoffUnix = "complete", 2_000_000_100
	case *OwnerProjectionEventV1:
		value.EventID, value.SourceSequence, value.PriorEventDigest = bytesRepeat(82, 32), 0, nil
		value.FreshnessObservedAtUnix, value.OccurredAtUnix, value.EmittedAtUnix = 2_000_000_000, 2_000_000_000, 2_000_000_001
		value.Extensions = [][]byte{}
	case *OwnerProjectionSnapshotV1:
		value.DomainKind = uint8(DomainOwnerLocal)
		value.SnapshotRevision = 1
		value.SourceCheckpoints = []OwnerProjectionSourceCheckpointV1{{ProjectionSourceID: []byte("source:fixture"), SourceGeneration: 1, ContiguousCursor: 0, ChainHeadDigest: bytesRepeat(83, 32)}}
		value.MaterializerVersion, value.CreatedAtUnix, value.PredecessorSnapshotDigest = "v1-fixture", 2_000_000_000, nil
	case *OwnerBootstrapCeremonyV1:
		value.Generation, value.State, value.NotBeforeUnix, value.ExpiresAtUnix = 0, "owner-confirmed", 2_000_000_000, 2_000_003_600
		value.RecoverySubjects = []TypedAuthoritySubjectV1{}
	case *OwnerAuthorityRecoveryV1:
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *OwnerDeviceEnrollmentV1:
		value.EnrollmentID, value.DevicePublicKey = bytesRepeat(83, 16), bytesRepeat(84, 32)
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *OwnerDeviceSessionV1:
		value.SessionID, value.DevicePublicKey = bytesRepeat(85, 16), bytesRepeat(86, 32)
		value.RevocationObjectReference = conformanceReference(87, "projection-event")
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *OwnerCommandLeaseV1:
		value.LeaseID = bytesRepeat(88, 32)
		value.NotBeforeUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
	case *OwnerCommandEffectV1:
		value.CommandKind = "owner.pause"
		agent := []byte("agent:fixture")
		value.AgentID = &agent
		value.CommandInstanceID = bytesRepeat(90, 16)
		value.TargetObjectKind = "agent"
		value.TargetObjectID = append([]byte(nil), agent...)
		value.Extensions = [][]byte{}
		return ValidateOwnerCommandEffect(*value)
	case *OwnerCommandResolutionV1:
		value.State = "prepared"
		value.ActionID = bytesRepeat(61, 32)
		value.AcceptedAttemptDigest = nil
		value.TargetResultRevision = nil
		value.AuthorityEvidenceDigest = nil
		value.ErrorCode = nil
		value.EffectReferences = []ImmutableObjectReferenceV1{}
		return ValidateOwnerCommandResolution(*value)
	case *OwnerCommandAuthorizationAttemptV1:
		value.ActionID = bytesRepeat(89, 32)
		value.AttemptedAtUnix, value.ExpiresAtUnix = 2_000_000_000, 2_000_003_600
		value.AuthorizationEnvelopes = []ProfileAuthorizationEnvelopeV1{}
	case *SemanticConfirmationV1:
		value.DisplayProfileURI = OwnerCommandConfirmationProfileV1
		value.DisplayProfileVersion = 1
		value.RiskClass = "bounded"
		value.ActionID = bytesRepeat(21, 32)
		value.CommandKind = "owner.pause"
		value.Target = "owner:" + strings.Repeat("22", 32)
		value.RecipientOrDestination = nil
		value.PermissionDelta = []byte{}
		value.AmountAndAssetOrCostCeiling = nil
		value.PolicyDelta = bytesRepeat(23, 32)
		value.CriticalParameters = [][]byte{bytesRepeat(24, 32), bytesRepeat(25, 32), bytesRepeat(0x22, 32)}
	case *OwnerExitPlanV1:
		value.ExitID, value.Stage, value.TombstoneDigest, value.Revision = bytesRepeat(90, 16), "fence-new-work", nil, 1
	case *CapabilityInventoryMigrationV1:
		value.MigrationID, value.State = bytesRepeat(91, 16), "prepared"
		value.InstallationID = bytesRepeat(92, 16)
		value.DeploymentFormatEpoch, value.CutoverEpoch = 1, 1
		value.MaximumLegacyAuthorityExpiryUnix = 2_000_000_000
		value.SourceStoreGeneration, value.SourceSnapshotCount = 1, 1
		value.SourceWriterEpoch, value.TargetWriterEpoch = 1, 2
		value.DurableCursor = []byte("cursor:fixture")
		value.PredecessorMigrationDigest = nil
	case *ActionOutcomeEvidenceV1:
		value.SchemaVersion = SchemaVersion
		value.EvidenceID = bytesRepeat(92, 16)
		value.ActionKind = "mcp-tool"
		value.ActionID = bytesRepeat(93, 32)
		value.ExecutionID = nil
		value.Disposition = "failed"
		value.SinkAuthorityID = bytesRepeat(94, 32)
		value.SinkEpoch = 1
		value.ObservedAtUnix = 2_000_000_001
		value.NotBeforeUnix = 2_000_000_000
		value.ExpiresAtUnix = 2_000_003_600
		value.Extensions = [][]byte{}
	}
	return ValidateConformanceBodyValue(kind, body)
}

func conformanceReference(seed byte, kind string) ImmutableObjectReferenceV1 {
	return ImmutableObjectReferenceV1{DomainKind: uint8(DomainOwnerLocal), DomainID: []byte("owner-domain:test"), ObjectKind: kind,
		ProfileURI: ProfileURI + "/" + kind + ".v1", ProfileVersion: 1, ObjectDigest: bytesRepeat(seed, 32), CanonicalSize: 128,
		MediaType: "application/cbor", RetrievalPolicyDigest: bytesRepeat(seed+1, 32), RetrievalHints: []string{}}
}

func populateConformanceValue(value reflect.Value, name string, seed byte, stack map[reflect.Type]bool) {
	if !value.CanSet() {
		return
	}
	if value.Kind() == reflect.Pointer {
		// Optional predecessor/terminal references are deliberately absent in a
		// genesis fixture; all other optionals are populated.
		lower := strings.ToLower(name)
		if strings.Contains(lower, "predecessor") || strings.Contains(lower, "error") || strings.Contains(lower, "terminal") {
			return
		}
		value.Set(reflect.New(value.Type().Elem()))
		populateConformanceValue(value.Elem(), name, seed, stack)
		return
	}
	switch value.Kind() {
	case reflect.Struct:
		if stack[value.Type()] {
			return
		}
		stack[value.Type()] = true
		for i := 0; i < value.NumField(); i++ {
			populateConformanceValue(value.Field(i), value.Type().Field(i).Name, seed+byte(i+1), stack)
		}
		delete(stack, value.Type())
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		lower := strings.ToLower(name)
		number := uint64(1)
		switch {
		case strings.Contains(lower, "expires"):
			number = 2_000_003_600
		case strings.Contains(lower, "notbefore") || strings.Contains(lower, "created") || strings.Contains(lower, "issued") || strings.Contains(lower, "attempted") || strings.Contains(lower, "observed") || strings.Contains(lower, "started"):
			number = 2_000_000_000
		}
		value.SetUint(number)
	case reflect.Bool:
		value.SetBool(true)
	case reflect.String:
		value.SetString(conformanceText(name))
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			length := 32
			lower := strings.ToLower(name)
			if strings.HasSuffix(lower, "id") || strings.Contains(lower, "_id") {
				length = 16
			}
			if strings.Contains(lower, "signature") {
				length = 64
			}
			if strings.Contains(lower, "ownerid") || strings.Contains(lower, "agentid") || strings.Contains(lower, "domainid") {
				value.SetBytes([]byte(strings.ToLower(name) + ":fixture"))
				return
			}
			value.SetBytes(bytesRepeat(seed, length))
			return
		}
		if strings.EqualFold(name, "Extensions") {
			value.Set(reflect.MakeSlice(value.Type(), 0, 0))
			return
		}
		item := reflect.New(value.Type().Elem()).Elem()
		populateConformanceValue(item, name+"Item", seed, stack)
		value.Set(reflect.Append(reflect.MakeSlice(value.Type(), 0, 1), item))
	case reflect.Map:
		value.Set(reflect.MakeMap(value.Type()))
	}
}

func conformanceText(name string) string {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "state"):
		return "active"
	case strings.Contains(lower, "algorithm"):
		return Ed25519ProofProfile
	case strings.Contains(lower, "profileuri"):
		return ProfileURI + "/fixture.v1"
	case strings.Contains(lower, "kind"):
		return "fixture"
	case strings.Contains(lower, "audience"):
		return "openfox:fixture"
	case strings.Contains(lower, "uri"):
		return "https://fixture.invalid/profile"
	case strings.Contains(lower, "path"):
		return "bin/fixture"
	case strings.Contains(lower, "version"):
		return "1.0.0"
	default:
		return "fixture-" + strings.ToLower(name)
	}
}

func bytesRepeat(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func initializeCollections(value reflect.Value) {
	for i := 0; i < value.NumField(); i++ {
		field := value.Field(i)
		switch field.Kind() {
		case reflect.Slice:
			field.Set(reflect.MakeSlice(field.Type(), 0, 0))
		case reflect.Map:
			field.Set(reflect.MakeMap(field.Type()))
		case reflect.Struct:
			initializeCollections(field)
		}
	}
}

func BodySchemas() []BodySchemaV1 {
	out := make([]BodySchemaV1, 0, len(objectKinds))
	for _, kind := range objectKinds {
		typ := bodyTypes[kind]
		definitions := map[string][]BodyFieldSchemaV1{}
		collectDefinition(typ, definitions)
		fields := definitions[typ.Name()]
		names := make([]string, 0, len(definitions))
		for name := range definitions {
			if name != typ.Name() {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		nested := make([]BodyTypeDefinitionV1, 0, len(names))
		for _, name := range names {
			nested = append(nested, BodyTypeDefinitionV1{TypeName: name, Fields: definitions[name]})
		}
		out = append(out, BodySchemaV1{ObjectKind: kind, GoType: typ.Name(), Fields: fields, Definitions: nested})
	}
	return out
}

func collectDefinition(typ reflect.Type, definitions map[string][]BodyFieldSchemaV1) {
	for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct || typ.Name() == "" {
		return
	}
	if _, ok := definitions[typ.Name()]; ok {
		return
	}
	definitions[typ.Name()] = nil
	fields := make([]BodyFieldSchemaV1, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		key, _ := strconv.ParseUint(strings.Split(field.Tag.Get("cbor"), ",")[0], 10, 64)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		fields = append(fields, BodyFieldSchemaV1{CBORKey: key, JSONName: jsonName, Type: wireType(field.Type), Required: true})
		collectDefinition(field.Type, definitions)
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].CBORKey < fields[j].CBORKey })
	definitions[typ.Name()] = fields
}

func wireType(t reflect.Type) string {
	if t.Kind() == reflect.Pointer {
		return "nullable:" + wireType(t.Elem())
	}
	switch t.Kind() {
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return "uint"
	case reflect.Bool:
		return "bool"
	case reflect.String:
		return "text"
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return "bytes"
		}
		return "array:" + wireType(t.Elem())
	case reflect.Struct:
		return "object:" + t.Name()
	default:
		return t.Kind().String()
	}
}

func ValidateBodyShape(objectKind string, canonical []byte) error {
	value, err := NewBodyValue(objectKind)
	if err != nil {
		return err
	}
	var raw any
	if err := UnmarshalBody(canonical, &raw); err != nil {
		return err
	}
	if err := validateRawBodyShape(raw, bodyTypes[objectKind], objectKind); err != nil {
		return err
	}
	return UnmarshalBody(canonical, value)
}

func validateRawBodyShape(raw any, typ reflect.Type, path string) error {
	if typ.Kind() == reflect.Pointer {
		if raw == nil {
			return nil
		}
		return validateRawBodyShape(raw, typ.Elem(), path)
	}

	switch typ.Kind() {
	case reflect.Struct:
		object, ok := raw.(map[any]any)
		if !ok {
			// fxamacker decodes integer-keyed maps to map[uint64]any when all
			// keys share that type. Normalize that common representation without
			// weakening the exact-key check below.
			integerObject, integerOK := raw.(map[uint64]any)
			if !integerOK {
				return errors.New(path + ": body value is not an integer-keyed object")
			}
			object = make(map[any]any, len(integerObject))
			for key, item := range integerObject {
				object[key] = item
			}
		}
		if len(object) != typ.NumField() {
			return errors.New(path + ": body has missing or unknown fields")
		}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			key, parseErr := strconv.ParseUint(strings.Split(field.Tag.Get("cbor"), ",")[0], 10, 64)
			if parseErr != nil {
				return errors.New(path + ": invalid registered CBOR field key")
			}
			item, exists := object[key]
			if !exists {
				return errors.New(path + ": body has missing or unknown fields")
			}
			if err := validateRawBodyShape(item, field.Type, path+"."+field.Name); err != nil {
				return err
			}
		}
		return nil
	case reflect.Slice:
		if typ.Elem().Kind() == reflect.Uint8 {
			if _, ok := raw.([]byte); !ok {
				return errors.New(path + ": expected bytes")
			}
			return nil
		}
		items, ok := raw.([]any)
		if !ok {
			return errors.New(path + ": expected array")
		}
		for i, item := range items {
			if err := validateRawBodyShape(item, typ.Elem(), path+"["+strconv.Itoa(i)+"]"); err != nil {
				return err
			}
		}
		return nil
	case reflect.String:
		if _, ok := raw.(string); !ok {
			return errors.New(path + ": expected text")
		}
	case reflect.Bool:
		if _, ok := raw.(bool); !ok {
			return errors.New(path + ": expected bool")
		}
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if _, ok := raw.(uint64); !ok {
			return errors.New(path + ": expected unsigned integer")
		}
	default:
		return errors.New(path + ": unsupported registered wire type")
	}
	return nil
}
