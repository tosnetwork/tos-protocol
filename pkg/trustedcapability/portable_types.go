package trustedcapability

type CapabilityRequirementV1 struct {
	SchemaVersion             uint16   `cbor:"1,keyasint" json:"schema_version"`
	AgreementDigest           []byte   `cbor:"2,keyasint" json:"agreement_digest"`
	ObligationID              []byte   `cbor:"3,keyasint" json:"obligation_id"`
	SemanticCapabilityDigest  []byte   `cbor:"4,keyasint" json:"semantic_capability_digest"`
	InputSchemaDigest         []byte   `cbor:"5,keyasint" json:"input_schema_digest"`
	OutputSchemaDigest        []byte   `cbor:"6,keyasint" json:"output_schema_digest"`
	EvidenceRequirementDigest []byte   `cbor:"7,keyasint" json:"evidence_requirement_digest"`
	PermissionCeilingDigest   []byte   `cbor:"8,keyasint" json:"permission_ceiling_digest"`
	MaximumDirectCostAtomic   string   `cbor:"9,keyasint" json:"maximum_direct_cost_atomic"`
	MaximumRuntimeMillis      uint64   `cbor:"10,keyasint" json:"maximum_runtime_millis"`
	AllowedArtifactKinds      []string `cbor:"11,keyasint" json:"allowed_artifact_kinds"`
	PolicyRevision            uint64   `cbor:"12,keyasint" json:"policy_revision"`
	InventoryRevision         uint64   `cbor:"13,keyasint" json:"inventory_revision"`
	CompilerEvidenceDigest    []byte   `cbor:"14,keyasint" json:"compiler_evidence_digest"`
	CreatedAtUnix             uint64   `cbor:"15,keyasint" json:"created_at_unix"`
	ExpiresAtUnix             uint64   `cbor:"16,keyasint" json:"expires_at_unix"`
}

type SourceAttemptV1 struct {
	SourceID                   []byte                     `cbor:"1,keyasint" json:"source_id"`
	SourceSnapshotReference    ImmutableObjectReferenceV1 `cbor:"2,keyasint" json:"source_snapshot_reference"`
	AdvisorySourceCursor       string                     `cbor:"3,keyasint" json:"advisory_source_cursor"`
	QueryCommitment            []byte                     `cbor:"4,keyasint" json:"query_commitment"`
	StartedAtUnix              uint64                     `cbor:"5,keyasint" json:"started_at_unix"`
	CompletedAtUnix            uint64                     `cbor:"6,keyasint" json:"completed_at_unix"`
	Disposition                string                     `cbor:"7,keyasint" json:"disposition"`
	ResultCommitment           []byte                     `cbor:"8,keyasint" json:"result_commitment"`
	SourceGeneration           uint64                     `cbor:"9,keyasint" json:"source_generation"`
	AdministrativeDomainDigest []byte                     `cbor:"10,keyasint" json:"administrative_domain_digest"`
	FailureDomainDigest        []byte                     `cbor:"11,keyasint" json:"failure_domain_digest"`
}

type CandidateDecisionV1 struct {
	ArtifactVersionDigest  []byte   `cbor:"1,keyasint" json:"artifact_version_digest"`
	Disposition            string   `cbor:"2,keyasint" json:"disposition"`
	StableReasonCodes      []string `cbor:"3,keyasint" json:"stable_reason_codes"`
	EvidenceManifestDigest []byte   `cbor:"4,keyasint" json:"evidence_manifest_digest"`
}

type CapabilitySourcingDecisionV1 struct {
	SchemaVersion                 uint16                `cbor:"1,keyasint" json:"schema_version"`
	OwnerID                       []byte                `cbor:"2,keyasint" json:"owner_id"`
	AgentID                       []byte                `cbor:"3,keyasint" json:"agent_id"`
	RequirementDigest             []byte                `cbor:"4,keyasint" json:"requirement_digest"`
	OwnerSourcePolicyDigest       []byte                `cbor:"5,keyasint" json:"owner_source_policy_digest"`
	SourceAttempts                []SourceAttemptV1     `cbor:"6,keyasint" json:"source_attempts"`
	CandidateDecisions            []CandidateDecisionV1 `cbor:"7,keyasint" json:"candidate_decisions"`
	SelectedArtifactVersionDigest *[]byte               `cbor:"8,keyasint" json:"selected_artifact_version_digest"`
	Decision                      string                `cbor:"9,keyasint" json:"decision"`
	PolicyRevision                uint64                `cbor:"10,keyasint" json:"policy_revision"`
	CreatedAtUnix                 uint64                `cbor:"11,keyasint" json:"created_at_unix"`
	ExpiresAtUnix                 uint64                `cbor:"12,keyasint" json:"expires_at_unix"`
}

type EvaluationResultV1 struct {
	SchemaVersion               uint16                     `cbor:"1,keyasint" json:"schema_version"`
	CandidateArtifactDigest     []byte                     `cbor:"2,keyasint" json:"candidate_artifact_digest"`
	BaselineArtifactDigest      *[]byte                    `cbor:"3,keyasint" json:"baseline_artifact_digest"`
	PermissionManifestDigest    []byte                     `cbor:"4,keyasint" json:"permission_manifest_digest"`
	RuntimeSandboxDigest        []byte                     `cbor:"5,keyasint" json:"runtime_sandbox_digest"`
	CorpusCommitment            []byte                     `cbor:"6,keyasint" json:"corpus_commitment"`
	AllocationSeed              []byte                     `cbor:"7,keyasint" json:"allocation_seed"`
	RevealReference             ImmutableObjectReferenceV1 `cbor:"8,keyasint" json:"reveal_reference"`
	CompleteResultSetDigest     []byte                     `cbor:"9,keyasint" json:"complete_result_set_digest"`
	ExclusionSetDigest          []byte                     `cbor:"10,keyasint" json:"exclusion_set_digest"`
	MetricDefinitionDigest      []byte                     `cbor:"11,keyasint" json:"metric_definition_digest"`
	ThresholdDigest             []byte                     `cbor:"12,keyasint" json:"threshold_digest"`
	RetainedControlResultDigest []byte                     `cbor:"13,keyasint" json:"retained_control_result_digest"`
	PolicyDigest                []byte                     `cbor:"14,keyasint" json:"policy_digest"`
	PolicyRevision              uint64                     `cbor:"15,keyasint" json:"policy_revision"`
	ObservedAtUnix              uint64                     `cbor:"16,keyasint" json:"observed_at_unix"`
	ExpiresAtUnix               uint64                     `cbor:"17,keyasint" json:"expires_at_unix"`
}

// CapabilityEvaluationManifestV1 freezes the complete evaluation predicate.
// Individual metric/result objects are immutable objects whose digests are
// committed here and in the Promotion Authority body; a summary digest is not
// accepted as a substitute for any member.
type CapabilityEvaluationManifestV1 struct {
	SchemaVersion                 uint16   `cbor:"1,keyasint" json:"schema_version"`
	CandidateArtifactDigest       []byte   `cbor:"2,keyasint" json:"candidate_artifact_digest"`
	PermissionManifestDigest      []byte   `cbor:"3,keyasint" json:"permission_manifest_digest"`
	RuntimeSandboxDigest          []byte   `cbor:"4,keyasint" json:"runtime_sandbox_digest"`
	PolicyDigest                  []byte   `cbor:"5,keyasint" json:"policy_digest"`
	PolicyRevision                uint64   `cbor:"6,keyasint" json:"policy_revision"`
	CorpusCommitment              []byte   `cbor:"7,keyasint" json:"corpus_commitment"`
	UnseenTaskCommitment          []byte   `cbor:"8,keyasint" json:"unseen_task_commitment"`
	CompleteResultSetDigest       []byte   `cbor:"9,keyasint" json:"complete_result_set_digest"`
	PrimaryMetricResultDigest     []byte   `cbor:"10,keyasint" json:"primary_metric_result_digest"`
	HarmMetricResultDigest        []byte   `cbor:"11,keyasint" json:"harm_metric_result_digest"`
	AllowedRegressionBoundsDigest []byte   `cbor:"12,keyasint" json:"allowed_regression_bounds_digest"`
	RetainedControlArtifactDigest []byte   `cbor:"13,keyasint" json:"retained_control_artifact_digest"`
	RetainedControlResultDigest   []byte   `cbor:"14,keyasint" json:"retained_control_result_digest"`
	RollbackArtifactDigest        []byte   `cbor:"15,keyasint" json:"rollback_artifact_digest"`
	RollbackPlanDigest            []byte   `cbor:"16,keyasint" json:"rollback_plan_digest"`
	EvaluatorIdentityDigest       []byte   `cbor:"17,keyasint" json:"evaluator_identity_digest"`
	ReproducibilityDigest         []byte   `cbor:"18,keyasint" json:"reproducibility_digest"`
	EvidenceObjectDigests         [][]byte `cbor:"19,keyasint" json:"evidence_object_digests"`
	CreatedAtUnix                 uint64   `cbor:"20,keyasint" json:"created_at_unix"`
	ExpiresAtUnix                 uint64   `cbor:"21,keyasint" json:"expires_at_unix"`
}

// PublisherRevocationObservationV1 is a signed, source-local checkpoint.  It
// does not claim global revocation truth; owner policy chooses the required
// observation sources and freshness bound.
type PublisherRevocationObservationV1 struct {
	SchemaVersion           uint16                  `cbor:"1,keyasint" json:"schema_version"`
	PublisherSubject        TypedAuthoritySubjectV1 `cbor:"2,keyasint" json:"publisher_subject"`
	ArtifactVersionDigest   []byte                  `cbor:"3,keyasint" json:"artifact_version_digest"`
	PublisherEnvelopeDigest []byte                  `cbor:"4,keyasint" json:"publisher_envelope_digest"`
	ObservedGeneration      uint64                  `cbor:"5,keyasint" json:"observed_generation"`
	Revoked                 bool                    `cbor:"6,keyasint" json:"revoked"`
	SourceID                []byte                  `cbor:"7,keyasint" json:"source_id"`
	SourceGeneration        uint64                  `cbor:"8,keyasint" json:"source_generation"`
	CheckpointRoot          []byte                  `cbor:"9,keyasint" json:"checkpoint_root"`
	ObservedAtUnix          uint64                  `cbor:"10,keyasint" json:"observed_at_unix"`
	ExpiresAtUnix           uint64                  `cbor:"11,keyasint" json:"expires_at_unix"`
}

type EvaluationEvidenceV1 struct {
	SchemaVersion     uint16 `cbor:"1,keyasint" json:"schema_version"`
	EvidenceKind      string `cbor:"2,keyasint" json:"evidence_kind"`
	CandidateDigest   []byte `cbor:"3,keyasint" json:"candidate_digest"`
	PermissionDigest  []byte `cbor:"4,keyasint" json:"permission_digest"`
	PolicyDigest      []byte `cbor:"5,keyasint" json:"policy_digest"`
	ProducerDigest    []byte `cbor:"6,keyasint" json:"producer_digest"`
	ContentCommitment []byte `cbor:"7,keyasint" json:"content_commitment"`
	CreatedAtUnix     uint64 `cbor:"8,keyasint" json:"created_at_unix"`
	ExpiresAtUnix     uint64 `cbor:"9,keyasint" json:"expires_at_unix"`
}

type PromotionAuthorityBodyV1 struct {
	SchemaVersion                          uint16                     `cbor:"1,keyasint" json:"schema_version"`
	PromotionID                            []byte                     `cbor:"2,keyasint" json:"promotion_id"`
	AuthorityRevision                      uint64                     `cbor:"3,keyasint" json:"authority_revision"`
	PredecessorEnvelopeDigest              *[]byte                    `cbor:"4,keyasint" json:"predecessor_envelope_digest"`
	OwnerID                                []byte                     `cbor:"5,keyasint" json:"owner_id"`
	AgentID                                []byte                     `cbor:"6,keyasint" json:"agent_id"`
	CandidateArtifactVersionDigest         []byte                     `cbor:"7,keyasint" json:"candidate_artifact_version_digest"`
	CandidatePermissionManifestDigest      []byte                     `cbor:"8,keyasint" json:"candidate_permission_manifest_digest"`
	CandidateOriginDigest                  []byte                     `cbor:"9,keyasint" json:"candidate_origin_digest"`
	GeneratorIdentityDigest                []byte                     `cbor:"10,keyasint" json:"generator_identity_digest"`
	SourcingDecisionDigest                 []byte                     `cbor:"11,keyasint" json:"sourcing_decision_digest"`
	EvaluationManifestDigest               []byte                     `cbor:"12,keyasint" json:"evaluation_manifest_digest"`
	EvaluationResultReference              ImmutableObjectReferenceV1 `cbor:"13,keyasint" json:"evaluation_result_reference"`
	VerifierAuthorizationEnvelopeReference ImmutableObjectReferenceV1 `cbor:"14,keyasint" json:"verifier_authorization_envelope_reference"`
	RetainedControlArtifactDigest          []byte                     `cbor:"15,keyasint" json:"retained_control_artifact_digest"`
	RetainedControlResultDigest            []byte                     `cbor:"16,keyasint" json:"retained_control_result_digest"`
	UnseenTaskCommitment                   []byte                     `cbor:"17,keyasint" json:"unseen_task_commitment"`
	PrimaryMetricResultDigest              []byte                     `cbor:"18,keyasint" json:"primary_metric_result_digest"`
	HarmMetricResultDigest                 []byte                     `cbor:"19,keyasint" json:"harm_metric_result_digest"`
	AllowedRegressionBoundsDigest          []byte                     `cbor:"20,keyasint" json:"allowed_regression_bounds_digest"`
	IndependentVerifierSubject             TypedAuthoritySubjectV1    `cbor:"21,keyasint" json:"independent_verifier_subject"`
	ApproverSubject                        TypedAuthoritySubjectV1    `cbor:"22,keyasint" json:"approver_subject"`
	ApproverPolicyDigest                   []byte                     `cbor:"23,keyasint" json:"approver_policy_digest"`
	ActivationScopeDigest                  []byte                     `cbor:"24,keyasint" json:"activation_scope_digest"`
	PolicyRevision                         uint64                     `cbor:"25,keyasint" json:"policy_revision"`
	PolicyDigest                           []byte                     `cbor:"26,keyasint" json:"policy_digest"`
	NotBeforeUnix                          uint64                     `cbor:"27,keyasint" json:"not_before_unix"`
	ExpiresAtUnix                          uint64                     `cbor:"28,keyasint" json:"expires_at_unix"`
	RollbackArtifactDigest                 []byte                     `cbor:"29,keyasint" json:"rollback_artifact_digest"`
	RollbackPlanDigest                     []byte                     `cbor:"30,keyasint" json:"rollback_plan_digest"`
	RevocationGeneration                   uint64                     `cbor:"31,keyasint" json:"revocation_generation"`
	Extensions                             [][]byte                   `cbor:"32,keyasint" json:"extensions"`
}

type CapabilityInstallationTransactionV1 struct {
	SchemaVersion             uint16                     `cbor:"1,keyasint" json:"schema_version"`
	InstallationID            []byte                     `cbor:"2,keyasint" json:"installation_id"`
	ArtifactVersionDigest     []byte                     `cbor:"3,keyasint" json:"artifact_version_digest"`
	SourceObjectReference     ImmutableObjectReferenceV1 `cbor:"4,keyasint" json:"source_object_reference"`
	QuarantineObjectDigest    []byte                     `cbor:"5,keyasint" json:"quarantine_object_digest"`
	TargetStoreDigest         []byte                     `cbor:"6,keyasint" json:"target_store_digest"`
	ExpectedInventoryRevision uint64                     `cbor:"7,keyasint" json:"expected_inventory_revision"`
	DependencyClosureDigest   []byte                     `cbor:"8,keyasint" json:"dependency_closure_digest"`
	InstallPlanDigest         []byte                     `cbor:"9,keyasint" json:"install_plan_digest"`
	RollbackPlanDigest        []byte                     `cbor:"10,keyasint" json:"rollback_plan_digest"`
	AdmissionEnvelopeDigest   []byte                     `cbor:"11,keyasint" json:"admission_envelope_digest"`
	WriterFenceDigest         []byte                     `cbor:"12,keyasint" json:"writer_fence_digest"`
	StableActionID            []byte                     `cbor:"13,keyasint" json:"stable_action_id"`
	ExactRequestDigest        []byte                     `cbor:"14,keyasint" json:"exact_request_digest"`
	PolicyRevision            uint64                     `cbor:"15,keyasint" json:"policy_revision"`
	State                     string                     `cbor:"16,keyasint" json:"state"`
}

type OwnerReportDescriptorV1 struct {
	ReportID                       []byte  `cbor:"1,keyasint" json:"report_id"`
	ReportSeriesID                 []byte  `cbor:"2,keyasint" json:"report_series_id"`
	CorrectionRevision             uint64  `cbor:"3,keyasint" json:"correction_revision"`
	OwnerID                        []byte  `cbor:"4,keyasint" json:"owner_id"`
	ReportProfileURI               string  `cbor:"5,keyasint" json:"report_profile_uri"`
	ReportProfileVersion           uint16  `cbor:"6,keyasint" json:"report_profile_version"`
	ReportKind                     string  `cbor:"7,keyasint" json:"report_kind"`
	ProducerArtifactVersionDigest  []byte  `cbor:"8,keyasint" json:"producer_artifact_version_digest"`
	PolicyRevision                 uint64  `cbor:"9,keyasint" json:"policy_revision"`
	PolicyDigest                   []byte  `cbor:"10,keyasint" json:"policy_digest"`
	PeriodStartUnix                uint64  `cbor:"11,keyasint" json:"period_start_unix"`
	PeriodEndUnix                  uint64  `cbor:"12,keyasint" json:"period_end_unix"`
	CutoffUnix                     uint64  `cbor:"13,keyasint" json:"cutoff_unix"`
	TimezoneID                     string  `cbor:"14,keyasint" json:"timezone_id"`
	AccountingPolicyDigest         []byte  `cbor:"15,keyasint" json:"accounting_policy_digest"`
	EconomicPerimeterDigest        []byte  `cbor:"16,keyasint" json:"economic_perimeter_digest"`
	SourceSnapshotDigest           []byte  `cbor:"17,keyasint" json:"source_snapshot_digest"`
	SourceCoverageManifestDigest   []byte  `cbor:"18,keyasint" json:"source_coverage_manifest_digest"`
	QueryDigest                    []byte  `cbor:"19,keyasint" json:"query_digest"`
	EvidenceManifestDigest         []byte  `cbor:"20,keyasint" json:"evidence_manifest_digest"`
	TypedReportDigest              []byte  `cbor:"21,keyasint" json:"typed_report_digest"`
	RenderedReportDigest           []byte  `cbor:"22,keyasint" json:"rendered_report_digest"`
	AttachmentSetDigest            []byte  `cbor:"23,keyasint" json:"attachment_set_digest"`
	Completeness                   string  `cbor:"24,keyasint" json:"completeness"`
	PriorReportDigest              *[]byte `cbor:"25,keyasint" json:"prior_report_digest"`
	CorrectionReasonAndDeltaDigest *[]byte `cbor:"26,keyasint" json:"correction_reason_and_delta_digest"`
	ConfidentialityClass           string  `cbor:"27,keyasint" json:"confidentiality_class"`
	CreatedAtUnix                  uint64  `cbor:"28,keyasint" json:"created_at_unix"`
}

// ReportSourceCoverageManifestV1 makes report completeness independently
// checkable instead of leaving source coverage in rendered prose.
type ReportSourceCoverageManifestV1 struct {
	SchemaVersion      uint16                       `cbor:"1,keyasint" json:"schema_version"`
	ReportID           []byte                       `cbor:"2,keyasint" json:"report_id"`
	RequiredSourceIDs  [][]byte                     `cbor:"3,keyasint" json:"required_source_ids"`
	ObservedSources    []ImmutableObjectReferenceV1 `cbor:"4,keyasint" json:"observed_sources"`
	MissingSourceIDs   [][]byte                     `cbor:"5,keyasint" json:"missing_source_ids"`
	CoverageCutoffUnix uint64                       `cbor:"6,keyasint" json:"coverage_cutoff_unix"`
	Completeness       string                       `cbor:"7,keyasint" json:"completeness"`
	EvidenceRootDigest []byte                       `cbor:"8,keyasint" json:"evidence_root_digest"`
}

type OwnerProjectionEventV1 struct {
	SchemaVersion               uint16   `cbor:"1,keyasint" json:"schema_version"`
	ProjectionSourceID          []byte   `cbor:"2,keyasint" json:"projection_source_id"`
	OwnerID                     []byte   `cbor:"3,keyasint" json:"owner_id"`
	EventID                     []byte   `cbor:"4,keyasint" json:"event_id"`
	SourceSequence              uint64   `cbor:"5,keyasint" json:"source_sequence"`
	ObjectKind                  string   `cbor:"6,keyasint" json:"object_kind"`
	ObjectID                    []byte   `cbor:"7,keyasint" json:"object_id"`
	ObjectRevision              uint64   `cbor:"8,keyasint" json:"object_revision"`
	EventKind                   string   `cbor:"9,keyasint" json:"event_kind"`
	VerifiedState               []byte   `cbor:"10,keyasint" json:"verified_state"`
	AdvisoryState               []byte   `cbor:"11,keyasint" json:"advisory_state"`
	AuthorityReferenceSetDigest []byte   `cbor:"12,keyasint" json:"authority_reference_set_digest"`
	EvidenceReferenceSetDigest  []byte   `cbor:"13,keyasint" json:"evidence_reference_set_digest"`
	RedactionProfileDigest      []byte   `cbor:"14,keyasint" json:"redaction_profile_digest"`
	FreshnessObservedAtUnix     uint64   `cbor:"15,keyasint" json:"freshness_observed_at_unix"`
	OccurredAtUnix              uint64   `cbor:"16,keyasint" json:"occurred_at_unix"`
	EmittedAtUnix               uint64   `cbor:"17,keyasint" json:"emitted_at_unix"`
	PriorEventDigest            *[]byte  `cbor:"18,keyasint" json:"prior_event_digest"`
	Extensions                  [][]byte `cbor:"19,keyasint" json:"extensions"`
}

type OwnerProjectionSourceCheckpointV1 struct {
	ProjectionSourceID []byte `cbor:"1,keyasint" json:"projection_source_id"`
	SourceGeneration   uint64 `cbor:"2,keyasint" json:"source_generation"`
	ContiguousCursor   uint64 `cbor:"3,keyasint" json:"contiguous_cursor"`
	ChainHeadDigest    []byte `cbor:"4,keyasint" json:"chain_head_digest"`
	Removed            bool   `cbor:"5,keyasint" json:"removed"`
}

// OwnerProjectionSnapshotV1 is a bounded, predecessor-linked checkpoint of
// all source-local owner projections. It does not create a global event head.
type OwnerProjectionSnapshotV1 struct {
	SchemaVersion             uint16                              `cbor:"1,keyasint" json:"schema_version"`
	DomainKind                uint8                               `cbor:"2,keyasint" json:"domain_kind"`
	DomainID                  []byte                              `cbor:"3,keyasint" json:"domain_id"`
	OwnerID                   []byte                              `cbor:"4,keyasint" json:"owner_id"`
	SnapshotRevision          uint64                              `cbor:"5,keyasint" json:"snapshot_revision"`
	PolicyDigest              []byte                              `cbor:"6,keyasint" json:"policy_digest"`
	RedactionProfileDigest    []byte                              `cbor:"7,keyasint" json:"redaction_profile_digest"`
	SourceCheckpoints         []OwnerProjectionSourceCheckpointV1 `cbor:"8,keyasint" json:"source_checkpoints"`
	EventSetMerkleRoot        []byte                              `cbor:"9,keyasint" json:"event_set_merkle_root"`
	MaterializerVersion       string                              `cbor:"10,keyasint" json:"materializer_version"`
	VerifiedStateRoot         []byte                              `cbor:"11,keyasint" json:"verified_state_root"`
	AdvisoryStateRoot         []byte                              `cbor:"12,keyasint" json:"advisory_state_root"`
	GapRoot                   []byte                              `cbor:"13,keyasint" json:"gap_root"`
	ConflictRoot              []byte                              `cbor:"14,keyasint" json:"conflict_root"`
	CreatedAtUnix             uint64                              `cbor:"15,keyasint" json:"created_at_unix"`
	PredecessorSnapshotDigest *[]byte                             `cbor:"16,keyasint" json:"predecessor_snapshot_digest"`
}

type OwnerDeviceSessionV1 struct {
	SessionID                   []byte                     `cbor:"1,keyasint" json:"session_id"`
	IssuerSubject               TypedAuthoritySubjectV1    `cbor:"2,keyasint" json:"issuer_subject"`
	OwnerID                     []byte                     `cbor:"3,keyasint" json:"owner_id"`
	DevicePublicKey             []byte                     `cbor:"4,keyasint" json:"device_public_key"`
	AllowedCommandClassesDigest []byte                     `cbor:"5,keyasint" json:"allowed_command_classes_digest"`
	Audience                    string                     `cbor:"6,keyasint" json:"audience"`
	ChannelBindingDigest        []byte                     `cbor:"7,keyasint" json:"channel_binding_digest"`
	SessionGeneration           uint64                     `cbor:"8,keyasint" json:"session_generation"`
	SessionRevocationGeneration uint64                     `cbor:"9,keyasint" json:"session_revocation_generation"`
	AuthorityRevision           uint64                     `cbor:"10,keyasint" json:"authority_revision"`
	PredecessorEnvelopeDigest   *[]byte                    `cbor:"11,keyasint" json:"predecessor_envelope_digest"`
	AuthorityEpoch              uint64                     `cbor:"12,keyasint" json:"authority_epoch"`
	PolicyDigest                []byte                     `cbor:"13,keyasint" json:"policy_digest"`
	PolicyRevision              uint64                     `cbor:"14,keyasint" json:"policy_revision"`
	NotBeforeUnix               uint64                     `cbor:"15,keyasint" json:"not_before_unix"`
	ExpiresAtUnix               uint64                     `cbor:"16,keyasint" json:"expires_at_unix"`
	RevocationObjectReference   ImmutableObjectReferenceV1 `cbor:"17,keyasint" json:"revocation_object_reference"`
}

type OwnerDeviceEnrollmentV1 struct {
	EnrollmentID                  []byte `cbor:"1,keyasint" json:"enrollment_id"`
	DomainID                      []byte `cbor:"2,keyasint" json:"domain_id"`
	OwnerID                       []byte `cbor:"3,keyasint" json:"owner_id"`
	DevicePublicKey               []byte `cbor:"4,keyasint" json:"device_public_key"`
	ChallengeDigest               []byte `cbor:"5,keyasint" json:"challenge_digest"`
	RequestedCommandClassesDigest []byte `cbor:"6,keyasint" json:"requested_command_classes_digest"`
	Audience                      string `cbor:"7,keyasint" json:"audience"`
	ChannelBindingDigest          []byte `cbor:"8,keyasint" json:"channel_binding_digest"`
	PolicyDigest                  []byte `cbor:"9,keyasint" json:"policy_digest"`
	PolicyRevision                uint64 `cbor:"10,keyasint" json:"policy_revision"`
	NotBeforeUnix                 uint64 `cbor:"11,keyasint" json:"not_before_unix"`
	ExpiresAtUnix                 uint64 `cbor:"12,keyasint" json:"expires_at_unix"`
}

type OwnerAuthorityRecoveryV1 struct {
	RecoveryID                    []byte `cbor:"1,keyasint" json:"recovery_id"`
	OwnerID                       []byte `cbor:"2,keyasint" json:"owner_id"`
	LastCommonPolicyDigest        []byte `cbor:"3,keyasint" json:"last_common_policy_digest"`
	ObservedForkRoot              []byte `cbor:"4,keyasint" json:"observed_fork_root"`
	RecoveryEpoch                 uint64 `cbor:"5,keyasint" json:"recovery_epoch"`
	ReplacementAuthoritySetDigest []byte `cbor:"6,keyasint" json:"replacement_authority_set_digest"`
	RecoveryQuorumEvidenceDigest  []byte `cbor:"7,keyasint" json:"recovery_quorum_evidence_digest"`
	SelectedHeadDigest            []byte `cbor:"8,keyasint" json:"selected_head_digest"`
	NotBeforeUnix                 uint64 `cbor:"9,keyasint" json:"not_before_unix"`
	ExpiresAtUnix                 uint64 `cbor:"10,keyasint" json:"expires_at_unix"`
}

type OwnerExitPlanV1 struct {
	ExitID                   []byte  `cbor:"1,keyasint" json:"exit_id"`
	OwnerID                  []byte  `cbor:"2,keyasint" json:"owner_id"`
	PredecessorPolicyDigest  []byte  `cbor:"3,keyasint" json:"predecessor_policy_digest"`
	Stage                    string  `cbor:"4,keyasint" json:"stage"`
	StageEvidenceRoot        []byte  `cbor:"5,keyasint" json:"stage_evidence_root"`
	AmbiguousActionSetRoot   []byte  `cbor:"6,keyasint" json:"ambiguous_action_set_root"`
	CustodyDispositionDigest []byte  `cbor:"7,keyasint" json:"custody_disposition_digest"`
	ExportDigest             []byte  `cbor:"8,keyasint" json:"export_digest"`
	TombstoneDigest          *[]byte `cbor:"9,keyasint" json:"tombstone_digest"`
	Revision                 uint64  `cbor:"10,keyasint" json:"revision"`
}

type OwnerBootstrapCeremonyV1 struct {
	SchemaVersion             uint16                    `cbor:"1,keyasint" json:"schema_version"`
	DomainKind                uint8                     `cbor:"2,keyasint" json:"domain_kind"`
	DomainID                  []byte                    `cbor:"3,keyasint" json:"domain_id"`
	OwnerID                   []byte                    `cbor:"4,keyasint" json:"owner_id"`
	RootSubject               TypedAuthoritySubjectV1   `cbor:"5,keyasint" json:"root_subject"`
	RecoverySubjects          []TypedAuthoritySubjectV1 `cbor:"6,keyasint" json:"recovery_subjects"`
	PossessionChallengeDigest []byte                    `cbor:"7,keyasint" json:"possession_challenge_digest"`
	GenesisPolicyObjectDigest []byte                    `cbor:"8,keyasint" json:"genesis_policy_object_digest"`
	AuthoritySubjectSetDigest []byte                    `cbor:"9,keyasint" json:"authority_subject_set_digest"`
	CeremonyNonce             []byte                    `cbor:"10,keyasint" json:"ceremony_nonce"`
	OwnerConfirmationDigest   []byte                    `cbor:"11,keyasint" json:"owner_confirmation_digest"`
	Generation                uint64                    `cbor:"12,keyasint" json:"generation"`
	State                     string                    `cbor:"13,keyasint" json:"state"`
	NotBeforeUnix             uint64                    `cbor:"14,keyasint" json:"not_before_unix"`
	ExpiresAtUnix             uint64                    `cbor:"15,keyasint" json:"expires_at_unix"`
}

// CapabilityInventoryMigrationV1 fences legacy writers before a V1
// projection is admitted. It never promotes imported legacy capabilities.
type CapabilityInventoryMigrationV1 struct {
	SchemaVersion                          uint16  `cbor:"1,keyasint" json:"schema_version"`
	MigrationID                            []byte  `cbor:"2,keyasint" json:"migration_id"`
	OwnerID                                []byte  `cbor:"3,keyasint" json:"owner_id"`
	AgentID                                []byte  `cbor:"4,keyasint" json:"agent_id"`
	InstallationID                         []byte  `cbor:"5,keyasint" json:"installation_id"`
	DeploymentFormatEpoch                  uint64  `cbor:"6,keyasint" json:"deployment_format_epoch"`
	CutoverEpoch                           uint64  `cbor:"7,keyasint" json:"cutover_epoch"`
	DeploymentSinkMembershipSnapshotDigest []byte  `cbor:"8,keyasint" json:"deployment_sink_membership_snapshot_digest"`
	SinkFenceAndHandleAcknowledgementRoot  []byte  `cbor:"9,keyasint" json:"sink_fence_and_handle_acknowledgement_root"`
	MaximumLegacyAuthorityExpiryUnix       uint64  `cbor:"10,keyasint" json:"maximum_legacy_authority_expiry_unix"`
	UnreachableSinkDispositionRoot         []byte  `cbor:"11,keyasint" json:"unreachable_sink_disposition_root"`
	SourceStoreIdentityDigest              []byte  `cbor:"12,keyasint" json:"source_store_identity_digest"`
	SourceStoreGeneration                  uint64  `cbor:"13,keyasint" json:"source_store_generation"`
	SourceSnapshotCount                    uint64  `cbor:"14,keyasint" json:"source_snapshot_count"`
	SourceSnapshotRoot                     []byte  `cbor:"15,keyasint" json:"source_snapshot_root"`
	TargetInventoryRoot                    []byte  `cbor:"16,keyasint" json:"target_inventory_root"`
	SourceWriterEpoch                      uint64  `cbor:"17,keyasint" json:"source_writer_epoch"`
	TargetWriterEpoch                      uint64  `cbor:"18,keyasint" json:"target_writer_epoch"`
	PerRecordClassificationRoot            []byte  `cbor:"19,keyasint" json:"per_record_classification_root"`
	DurableCursor                          []byte  `cbor:"20,keyasint" json:"durable_cursor"`
	ReconciliationResultDigest             []byte  `cbor:"21,keyasint" json:"reconciliation_result_digest"`
	PredecessorMigrationDigest             *[]byte `cbor:"22,keyasint" json:"predecessor_migration_digest"`
	State                                  string  `cbor:"23,keyasint" json:"state"`
	CreatedAtUnix                          uint64  `cbor:"24,keyasint" json:"created_at_unix"`
}
