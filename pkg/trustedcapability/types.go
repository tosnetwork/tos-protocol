package trustedcapability

// Optional scalar fields are pointers so their canonical wire value is null,
// not an omitted/default field. Every struct field has a released integer key.
type ImmutableObjectReferenceV1 struct {
	DomainKind            uint8    `cbor:"1,keyasint" json:"domain_kind"`
	DomainID              []byte   `cbor:"2,keyasint" json:"domain_id"`
	ObjectKind            string   `cbor:"3,keyasint" json:"object_kind"`
	ProfileURI            string   `cbor:"4,keyasint" json:"profile_uri"`
	ProfileVersion        uint16   `cbor:"5,keyasint" json:"profile_version"`
	ObjectDigest          []byte   `cbor:"6,keyasint" json:"object_digest"`
	CanonicalSize         uint32   `cbor:"7,keyasint" json:"canonical_size"`
	MediaType             string   `cbor:"8,keyasint" json:"media_type"`
	RetrievalPolicyDigest []byte   `cbor:"9,keyasint" json:"retrieval_policy_digest"`
	RetrievalHints        []string `cbor:"10,keyasint" json:"retrieval_hints"`
}

type ExecutableCapabilityArtifactBodyV1 struct {
	SchemaVersion               uint16                  `cbor:"1,keyasint" json:"schema_version"`
	ArtifactKind                string                  `cbor:"2,keyasint" json:"artifact_kind"`
	ArtifactNamespace           string                  `cbor:"3,keyasint" json:"artifact_namespace"`
	ArtifactName                string                  `cbor:"4,keyasint" json:"artifact_name"`
	ArtifactVersion             string                  `cbor:"5,keyasint" json:"artifact_version"`
	PublisherSubject            TypedAuthoritySubjectV1 `cbor:"6,keyasint" json:"publisher_subject"`
	PublisherAuthorityProfile   []byte                  `cbor:"7,keyasint" json:"publisher_authority_profile"`
	SourceDescriptorDigest      []byte                  `cbor:"8,keyasint" json:"source_descriptor_digest"`
	ContentManifestDigest       []byte                  `cbor:"9,keyasint" json:"content_manifest_digest"`
	EntrypointDescriptorDigest  []byte                  `cbor:"10,keyasint" json:"entrypoint_descriptor_digest"`
	PermissionManifestDigest    *[]byte                 `cbor:"11,keyasint" json:"permission_manifest_digest"`
	DependencyManifestDigest    *[]byte                 `cbor:"12,keyasint" json:"dependency_manifest_digest"`
	LicenseManifestDigest       []byte                  `cbor:"13,keyasint" json:"license_manifest_digest"`
	StandardsProfileSetDigest   []byte                  `cbor:"14,keyasint" json:"standards_profile_set_digest"`
	CompatibilityManifestDigest []byte                  `cbor:"15,keyasint" json:"compatibility_manifest_digest"`
	SupplyChainEvidenceDigest   []byte                  `cbor:"16,keyasint" json:"supply_chain_evidence_digest"`
	OptionalServiceCapabilityID *[]byte                 `cbor:"17,keyasint" json:"optional_service_capability_id"`
	CreatedAtUnix               uint64                  `cbor:"18,keyasint" json:"created_at_unix"`
	Extensions                  [][]byte                `cbor:"19,keyasint" json:"extensions"`
}

type ContentManifestEntryV1 struct {
	Path          string `cbor:"1,keyasint" json:"path"`
	ObjectType    string `cbor:"2,keyasint" json:"object_type"`
	Mode          uint32 `cbor:"3,keyasint" json:"mode"`
	Size          uint64 `cbor:"4,keyasint" json:"size"`
	ContentDigest []byte `cbor:"5,keyasint" json:"content_digest"`
}

type CapabilityContentManifestV1 struct {
	SchemaVersion uint16                   `cbor:"1,keyasint" json:"schema_version"`
	Entries       []ContentManifestEntryV1 `cbor:"2,keyasint" json:"entries"`
	ClosureRoot   []byte                   `cbor:"3,keyasint" json:"closure_root"`
}

type CapabilityEntrypointDescriptorV1 struct {
	SchemaVersion                 uint16   `cbor:"1,keyasint" json:"schema_version"`
	ExecutableObjectDigest        []byte   `cbor:"2,keyasint" json:"executable_object_digest"`
	Arguments                     []string `cbor:"3,keyasint" json:"arguments"`
	WorkingDirectoryPolicyDigest  []byte   `cbor:"4,keyasint" json:"working_directory_policy_digest"`
	RuntimeSubjectDigest          []byte   `cbor:"5,keyasint" json:"runtime_subject_digest"`
	EnvironmentNameSetDigest      []byte   `cbor:"6,keyasint" json:"environment_name_set_digest"`
	EnvironmentValueSourceDigest  []byte   `cbor:"7,keyasint" json:"environment_value_source_digest"`
	FilesystemRootSetDigest       []byte   `cbor:"8,keyasint" json:"filesystem_root_set_digest"`
	ProcessModelDigest            []byte   `cbor:"9,keyasint" json:"process_model_digest"`
	SandboxProfileDigest          []byte   `cbor:"10,keyasint" json:"sandbox_profile_digest"`
	RemoteServiceDescriptorDigest *[]byte  `cbor:"11,keyasint" json:"remote_service_descriptor_digest"`
}

type ArtifactPublisherEnvelopeBodyV1 struct {
	SchemaVersion              uint16                  `cbor:"1,keyasint" json:"schema_version"`
	ArtifactPreManifestDigest  []byte                  `cbor:"2,keyasint" json:"artifact_pre_manifest_digest"`
	ArtifactKind               string                  `cbor:"3,keyasint" json:"artifact_kind"`
	ArtifactNamespace          string                  `cbor:"4,keyasint" json:"artifact_namespace"`
	ArtifactName               string                  `cbor:"5,keyasint" json:"artifact_name"`
	ArtifactVersion            string                  `cbor:"6,keyasint" json:"artifact_version"`
	PublisherSubject           TypedAuthoritySubjectV1 `cbor:"7,keyasint" json:"publisher_subject"`
	PermissionManifestDigest   *[]byte                 `cbor:"8,keyasint" json:"permission_manifest_digest"`
	DependencyManifestDigest   *[]byte                 `cbor:"9,keyasint" json:"dependency_manifest_digest"`
	ContentManifestDigest      []byte                  `cbor:"10,keyasint" json:"content_manifest_digest"`
	EntrypointDescriptorDigest []byte                  `cbor:"11,keyasint" json:"entrypoint_descriptor_digest"`
	CreatedAtUnix              uint64                  `cbor:"12,keyasint" json:"created_at_unix"`
	NotBeforeUnix              uint64                  `cbor:"13,keyasint" json:"not_before_unix"`
	ExpiresAtUnix              uint64                  `cbor:"14,keyasint" json:"expires_at_unix"`
	PredecessorVersionDigest   *[]byte                 `cbor:"15,keyasint" json:"predecessor_version_digest"`
	RevocationGeneration       uint64                  `cbor:"16,keyasint" json:"revocation_generation"`
	Extensions                 [][]byte                `cbor:"17,keyasint" json:"extensions"`
}

type DependencyNodeV1 struct {
	NodeID                                []byte                     `cbor:"1,keyasint" json:"node_id"`
	ImmutableArtifactReference            ImmutableObjectReferenceV1 `cbor:"2,keyasint" json:"immutable_artifact_reference"`
	PublisherEnvelopeReference            ImmutableObjectReferenceV1 `cbor:"3,keyasint" json:"publisher_envelope_reference"`
	SourceSnapshotReference               ImmutableObjectReferenceV1 `cbor:"4,keyasint" json:"source_snapshot_reference"`
	BuildInputDigest                      []byte                     `cbor:"5,keyasint" json:"build_input_digest"`
	BuildOutputDigest                     []byte                     `cbor:"6,keyasint" json:"build_output_digest"`
	InstallAndBuildHookDigest             []byte                     `cbor:"7,keyasint" json:"install_and_build_hook_digest"`
	EffectivePermissionContributionDigest []byte                     `cbor:"8,keyasint" json:"effective_permission_contribution_digest"`
}

type DependencyEdgeV1 struct {
	FromNodeID     []byte `cbor:"1,keyasint" json:"from_node_id"`
	ToNodeID       []byte `cbor:"2,keyasint" json:"to_node_id"`
	DependencyKind string `cbor:"3,keyasint" json:"dependency_kind"`
}

type DependencyManifestV1 struct {
	SchemaVersion                     uint16             `cbor:"1,keyasint" json:"schema_version"`
	ArtifactPreManifestDigest         []byte             `cbor:"2,keyasint" json:"artifact_pre_manifest_digest"`
	ResolverArtifactDigest            []byte             `cbor:"3,keyasint" json:"resolver_artifact_digest"`
	BuildToolchainDigest              []byte             `cbor:"4,keyasint" json:"build_toolchain_digest"`
	PlatformAndFeaturePredicateDigest []byte             `cbor:"5,keyasint" json:"platform_and_feature_predicate_digest"`
	Nodes                             []DependencyNodeV1 `cbor:"6,keyasint" json:"nodes"`
	Edges                             []DependencyEdgeV1 `cbor:"7,keyasint" json:"edges"`
	ClosureRootDigest                 []byte             `cbor:"8,keyasint" json:"closure_root_digest"`
}

type NetworkCapabilityV1 struct {
	Scheme                   string   `cbor:"1,keyasint" json:"scheme"`
	Host                     string   `cbor:"2,keyasint" json:"host"`
	Port                     uint16   `cbor:"3,keyasint" json:"port"`
	ResolverProfileDigest    []byte   `cbor:"4,keyasint" json:"resolver_profile_digest"`
	ProhibitedAddressClasses []string `cbor:"5,keyasint" json:"prohibited_address_classes"`
	MaximumDNSAnswers        uint16   `cbor:"6,keyasint" json:"maximum_dns_answers"`
	MaximumDNSTTL            uint32   `cbor:"7,keyasint" json:"maximum_dns_ttl"`
	RedirectCount            uint8    `cbor:"8,keyasint" json:"redirect_count"`
	SameOriginRedirects      bool     `cbor:"9,keyasint" json:"same_origin_redirects"`
	ProxyIdentity            *[]byte  `cbor:"10,keyasint" json:"proxy_identity"`
	ProxyConnectDestinations []string `cbor:"17,keyasint" json:"proxy_connect_destinations"`
	TLSProfileDigest         []byte   `cbor:"11,keyasint" json:"tls_profile_digest"`
	MaximumRequestBytes      uint32   `cbor:"12,keyasint" json:"maximum_request_bytes"`
	MaximumResponseBytes     uint32   `cbor:"13,keyasint" json:"maximum_response_bytes"`
	TimeoutMillis            uint32   `cbor:"14,keyasint" json:"timeout_millis"`
	ConnectionCeiling        uint16   `cbor:"15,keyasint" json:"connection_ceiling"`
	RetryCeiling             uint8    `cbor:"16,keyasint" json:"retry_ceiling"`
}

// FilesystemCapabilityV1 names an immutable broker root, never an ambient
// pathname.  The broker resolves RootHandleDigest to a pinned directory
// descriptor and applies the relative-path and operation restrictions with
// no-follow/beneath semantics.
type FilesystemCapabilityV1 struct {
	RootHandleDigest []byte   `cbor:"1,keyasint" json:"root_handle_digest"`
	RelativePrefix   string   `cbor:"2,keyasint" json:"relative_prefix"`
	Operations       []string `cbor:"3,keyasint" json:"operations"`
	NoFollow         bool     `cbor:"4,keyasint" json:"no_follow"`
	ReadOnly         bool     `cbor:"5,keyasint" json:"read_only"`
	MaximumBytes     uint64   `cbor:"6,keyasint" json:"maximum_bytes"`
}

type DisclosureCapabilityV1 struct {
	DataClass      string `cbor:"1,keyasint" json:"data_class"`
	AudienceDigest []byte `cbor:"2,keyasint" json:"audience_digest"`
	PurposeDigest  []byte `cbor:"3,keyasint" json:"purpose_digest"`
	MaximumBytes   uint64 `cbor:"4,keyasint" json:"maximum_bytes"`
	ExpiresAtUnix  uint64 `cbor:"5,keyasint" json:"expires_at_unix"`
}

type UploadCapabilityV1 struct {
	DestinationOrigin string `cbor:"1,keyasint" json:"destination_origin"`
	DataClass         string `cbor:"2,keyasint" json:"data_class"`
	ObjectDigest      []byte `cbor:"3,keyasint" json:"object_digest"`
	MaximumBytes      uint64 `cbor:"4,keyasint" json:"maximum_bytes"`
	CredentialHandle  []byte `cbor:"5,keyasint" json:"credential_handle"`
}

type RetentionPolicyV1 struct {
	MaximumRetentionSeconds uint64 `cbor:"1,keyasint" json:"maximum_retention_seconds"`
	DeleteOnTerminal        bool   `cbor:"2,keyasint" json:"delete_on_terminal"`
	EvidenceOnlyAfterDelete bool   `cbor:"3,keyasint" json:"evidence_only_after_delete"`
}

type LoggingPolicyV1 struct {
	AllowedDataClasses []string `cbor:"1,keyasint" json:"allowed_data_classes"`
	MaximumBytes       uint64   `cbor:"2,keyasint" json:"maximum_bytes"`
	RedactionRequired  bool     `cbor:"3,keyasint" json:"redaction_required"`
}

type CredentialCapabilityV1 struct {
	BrokerHandle  []byte   `cbor:"1,keyasint" json:"broker_handle"`
	Issuer        string   `cbor:"2,keyasint" json:"issuer"`
	Audience      string   `cbor:"3,keyasint" json:"audience"`
	Scopes        []string `cbor:"4,keyasint" json:"scopes"`
	Origin        string   `cbor:"5,keyasint" json:"origin"`
	Destination   string   `cbor:"6,keyasint" json:"destination"`
	Action        string   `cbor:"7,keyasint" json:"action"`
	ExpiresAtUnix uint64   `cbor:"8,keyasint" json:"expires_at_unix"`
	UseCount      uint32   `cbor:"9,keyasint" json:"use_count"`
	NonDelegable  bool     `cbor:"10,keyasint" json:"non_delegable"`
}

type ResourceCeilingV1 struct {
	CPUMillis     uint64 `cbor:"1,keyasint" json:"cpu_millis"`
	MemoryBytes   uint64 `cbor:"2,keyasint" json:"memory_bytes"`
	StorageBytes  uint64 `cbor:"3,keyasint" json:"storage_bytes"`
	RuntimeMillis uint64 `cbor:"4,keyasint" json:"runtime_millis"`
}

type CapabilityPermissionManifestV1 struct {
	SchemaVersion             uint16                   `cbor:"1,keyasint" json:"schema_version"`
	ArtifactPreManifestDigest []byte                   `cbor:"2,keyasint" json:"artifact_pre_manifest_digest"`
	ToolCapabilities          []string                 `cbor:"3,keyasint" json:"tool_capabilities"`
	ProcessCapabilities       []string                 `cbor:"4,keyasint" json:"process_capabilities"`
	FilesystemCapabilities    []FilesystemCapabilityV1 `cbor:"5,keyasint" json:"filesystem_capabilities"`
	NetworkCapabilities       []NetworkCapabilityV1    `cbor:"6,keyasint" json:"network_capabilities"`
	CredentialCapabilities    []CredentialCapabilityV1 `cbor:"7,keyasint" json:"credential_capabilities"`
	DataClassesRead           []string                 `cbor:"8,keyasint" json:"data_classes_read"`
	DataClassesWrite          []string                 `cbor:"9,keyasint" json:"data_classes_write"`
	DisclosureCapabilities    []DisclosureCapabilityV1 `cbor:"10,keyasint" json:"disclosure_capabilities"`
	UploadCapabilities        []UploadCapabilityV1     `cbor:"11,keyasint" json:"upload_capabilities"`
	DestructiveCapabilities   []string                 `cbor:"12,keyasint" json:"destructive_capabilities"`
	ResourceCeiling           ResourceCeilingV1        `cbor:"13,keyasint" json:"resource_ceiling"`
	DirectCostCeiling         string                   `cbor:"14,keyasint" json:"direct_cost_ceiling"`
	ConcurrencyCeiling        uint16                   `cbor:"15,keyasint" json:"concurrency_ceiling"`
	RetentionPolicy           RetentionPolicyV1        `cbor:"16,keyasint" json:"retention_policy"`
	LoggingPolicy             LoggingPolicyV1          `cbor:"17,keyasint" json:"logging_policy"`
	Extensions                [][]byte                 `cbor:"18,keyasint" json:"extensions"`
}

type CapabilityAdmissionBodyV1 struct {
	SchemaVersion              uint16   `cbor:"1,keyasint" json:"schema_version"`
	AdmissionID                []byte   `cbor:"2,keyasint" json:"admission_id"`
	OwnerID                    []byte   `cbor:"3,keyasint" json:"owner_id"`
	AgentID                    []byte   `cbor:"4,keyasint" json:"agent_id"`
	ArtifactVersionDigest      []byte   `cbor:"5,keyasint" json:"artifact_version_digest"`
	PermissionManifestDigest   []byte   `cbor:"6,keyasint" json:"permission_manifest_digest"`
	RequirementScopeDigest     []byte   `cbor:"7,keyasint" json:"requirement_scope_digest"`
	EvaluationManifestDigest   []byte   `cbor:"8,keyasint" json:"evaluation_manifest_digest"`
	SourcingDecisionDigest     []byte   `cbor:"9,keyasint" json:"sourcing_decision_digest"`
	RuntimeCompatibilityDigest []byte   `cbor:"10,keyasint" json:"runtime_compatibility_digest"`
	PolicyRevision             uint64   `cbor:"11,keyasint" json:"policy_revision"`
	PolicyDigest               []byte   `cbor:"12,keyasint" json:"policy_digest"`
	AuthoritySubject           []byte   `cbor:"13,keyasint" json:"authority_subject"`
	AuthorityProfileDigest     []byte   `cbor:"14,keyasint" json:"authority_profile_digest"`
	AdmittedAtUnix             uint64   `cbor:"15,keyasint" json:"admitted_at_unix"`
	NotBeforeUnix              uint64   `cbor:"16,keyasint" json:"not_before_unix"`
	ExpiresAtUnix              uint64   `cbor:"17,keyasint" json:"expires_at_unix"`
	RevocationGeneration       uint64   `cbor:"18,keyasint" json:"revocation_generation"`
	InFlightRevocationPolicy   string   `cbor:"19,keyasint" json:"in_flight_revocation_policy"`
	Extensions                 [][]byte `cbor:"20,keyasint" json:"extensions"`
}

type AuthorityMutationV1 struct {
	ObjectID                  []byte `cbor:"1,keyasint" json:"object_id"`
	PriorRevision             uint64 `cbor:"2,keyasint" json:"prior_revision"`
	TargetRevision            uint64 `cbor:"3,keyasint" json:"target_revision"`
	PredecessorEnvelopeDigest []byte `cbor:"4,keyasint" json:"predecessor_envelope_digest"`
	MutationKind              string `cbor:"5,keyasint" json:"mutation_kind"`
	ReasonCode                string `cbor:"6,keyasint" json:"reason_code"`
	EffectiveAtUnix           uint64 `cbor:"7,keyasint" json:"effective_at_unix"`
	EvidenceManifestDigest    []byte `cbor:"8,keyasint" json:"evidence_manifest_digest"`
	RevocationGeneration      uint64 `cbor:"9,keyasint" json:"revocation_generation"`
}

type CapabilityUseLeaseV1 struct {
	SchemaVersion                 uint16  `cbor:"1,keyasint" json:"schema_version"`
	LeaseID                       []byte  `cbor:"2,keyasint" json:"lease_id"`
	OwnerID                       []byte  `cbor:"3,keyasint" json:"owner_id"`
	AgentID                       []byte  `cbor:"4,keyasint" json:"agent_id"`
	SinkID                        []byte  `cbor:"5,keyasint" json:"sink_id"`
	ExecutionID                   []byte  `cbor:"6,keyasint" json:"execution_id"`
	ActionID                      []byte  `cbor:"7,keyasint" json:"action_id"`
	ArtifactVersionDigest         []byte  `cbor:"8,keyasint" json:"artifact_version_digest"`
	PermissionSubsetDigest        []byte  `cbor:"9,keyasint" json:"permission_subset_digest"`
	AdmissionEnvelopeDigest       []byte  `cbor:"10,keyasint" json:"admission_envelope_digest"`
	AdmissionRevocationGeneration uint64  `cbor:"11,keyasint" json:"admission_revocation_generation"`
	PromotionEnvelopeDigest       *[]byte `cbor:"12,keyasint" json:"promotion_envelope_digest"`
	PromotionRevocationGeneration *uint64 `cbor:"13,keyasint" json:"promotion_revocation_generation"`
	AuthorityEpoch                uint64  `cbor:"14,keyasint" json:"authority_epoch"`
	PolicyDigest                  []byte  `cbor:"15,keyasint" json:"policy_digest"`
	PolicyRevision                uint64  `cbor:"16,keyasint" json:"policy_revision"`
	NotBeforeUnix                 uint64  `cbor:"17,keyasint" json:"not_before_unix"`
	StartNotAfterUnix             uint64  `cbor:"18,keyasint" json:"start_not_after_unix"`
	ExpiresAtUnix                 uint64  `cbor:"19,keyasint" json:"expires_at_unix"`
	// InvocationDescriptorDigest commits the exact executable/service
	// descriptor, selected tool surface and caller-side argument ceilings. A
	// transport sidecar is never authority unless its canonical digest matches
	// this value.
	InvocationDescriptorDigest []byte  `cbor:"20,keyasint" json:"invocation_descriptor_digest"`
	AdmissionRevision          uint64  `cbor:"21,keyasint" json:"admission_revision"`
	PromotionRevision          *uint64 `cbor:"22,keyasint" json:"promotion_revision"`
	InstallationRevision       uint64  `cbor:"23,keyasint" json:"installation_revision"`
	InventoryRevision          uint64  `cbor:"24,keyasint" json:"inventory_revision"`
	ControlScopeGeneration     uint64  `cbor:"25,keyasint" json:"control_scope_generation"`
}

type InventoryEntryV1 struct {
	ArtifactVersionDigest    []byte                       `cbor:"1,keyasint" json:"artifact_version_digest"`
	AdmissionID              []byte                       `cbor:"2,keyasint" json:"admission_id"`
	AdmissionRevision        uint64                       `cbor:"3,keyasint" json:"admission_revision"`
	PromotionID              *[]byte                      `cbor:"4,keyasint" json:"promotion_id"`
	PermissionManifestDigest []byte                       `cbor:"5,keyasint" json:"permission_manifest_digest"`
	RevocationGeneration     uint64                       `cbor:"6,keyasint" json:"revocation_generation"`
	ProjectedState           string                       `cbor:"7,keyasint" json:"projected_state"`
	EvidenceRefs             []ImmutableObjectReferenceV1 `cbor:"8,keyasint" json:"evidence_refs"`
}

type CapabilityInventorySnapshotV1 struct {
	OwnerID           []byte             `cbor:"1,keyasint" json:"owner_id"`
	AgentID           []byte             `cbor:"2,keyasint" json:"agent_id"`
	SnapshotRevision  uint64             `cbor:"3,keyasint" json:"snapshot_revision"`
	SourceGeneration  uint64             `cbor:"4,keyasint" json:"source_generation"`
	PolicyRevision    uint64             `cbor:"5,keyasint" json:"policy_revision"`
	PolicyDigest      []byte             `cbor:"6,keyasint" json:"policy_digest"`
	PortfolioRevision uint64             `cbor:"7,keyasint" json:"portfolio_revision"`
	ConsistencyToken  []byte             `cbor:"8,keyasint" json:"consistency_token"`
	CreatedAtUnix     uint64             `cbor:"9,keyasint" json:"created_at_unix"`
	ExpiresAtUnix     uint64             `cbor:"10,keyasint" json:"expires_at_unix"`
	Entries           []InventoryEntryV1 `cbor:"11,keyasint" json:"entries"`
}

// CapabilityAcquisitionTransitionV1 is the exact rollback-resistant closure
// admitted by the separately administered Owner/Agent acquisition authority.
// It is an operational CAS record, not capability or execution authority.
type CapabilityAcquisitionTransitionV1 struct {
	SchemaVersion    uint16 `cbor:"1,keyasint" json:"schema_version"`
	OwnerID          []byte `cbor:"2,keyasint" json:"owner_id"`
	AgentID          []byte `cbor:"3,keyasint" json:"agent_id"`
	LedgerID         []byte `cbor:"4,keyasint" json:"ledger_id"`
	AcquisitionID    string `cbor:"5,keyasint" json:"acquisition_id"`
	Phase            string `cbor:"6,keyasint" json:"phase"`
	Principal        string `cbor:"7,keyasint" json:"principal"`
	SourceID         string `cbor:"8,keyasint" json:"source_id"`
	SourceGeneration uint64 `cbor:"9,keyasint" json:"source_generation"`
	ReservedBytes    uint64 `cbor:"10,keyasint" json:"reserved_bytes"`
	ReservedFiles    uint32 `cbor:"11,keyasint" json:"reserved_files"`
	ExpiresAtUnix    uint64 `cbor:"12,keyasint" json:"expires_at_unix"`
	ContentDigest    []byte `cbor:"13,keyasint" json:"content_digest"`
	ContentBytes     uint64 `cbor:"14,keyasint" json:"content_bytes"`
	ContentFiles     uint32 `cbor:"15,keyasint" json:"content_files"`
	PriorRevision    uint64 `cbor:"16,keyasint" json:"prior_revision"`
	NextRevision     uint64 `cbor:"17,keyasint" json:"next_revision"`
}

type CapabilityUseBindingV1 struct {
	OwnerID                                []byte  `cbor:"1,keyasint" json:"owner_id"`
	AgentID                                []byte  `cbor:"2,keyasint" json:"agent_id"`
	AgreementDigest                        []byte  `cbor:"3,keyasint" json:"agreement_digest"`
	ObligationID                           []byte  `cbor:"4,keyasint" json:"obligation_id"`
	ExecutionID                            []byte  `cbor:"5,keyasint" json:"execution_id"`
	ActionID                               []byte  `cbor:"6,keyasint" json:"action_id"`
	ArtifactVersionDigest                  []byte  `cbor:"7,keyasint" json:"artifact_version_digest"`
	InstallationRevision                   uint64  `cbor:"8,keyasint" json:"installation_revision"`
	LoadedObjectDigest                     []byte  `cbor:"9,keyasint" json:"loaded_object_digest"`
	PermissionSubsetDigest                 []byte  `cbor:"10,keyasint" json:"permission_subset_digest"`
	AdmissionEnvelopeDigest                []byte  `cbor:"11,keyasint" json:"admission_envelope_digest"`
	AdmissionRevision                      uint64  `cbor:"12,keyasint" json:"admission_revision"`
	AdmissionRevocationGeneration          uint64  `cbor:"13,keyasint" json:"admission_revocation_generation"`
	PromotionRequired                      bool    `cbor:"14,keyasint" json:"promotion_required"`
	PromotionEnvelopeDigest                *[]byte `cbor:"15,keyasint" json:"promotion_envelope_digest"`
	PromotionRevision                      *uint64 `cbor:"16,keyasint" json:"promotion_revision"`
	PromotionRevocationGeneration          *uint64 `cbor:"17,keyasint" json:"promotion_revocation_generation"`
	AuthorityEpoch                         uint64  `cbor:"18,keyasint" json:"authority_epoch"`
	PolicyDigest                           []byte  `cbor:"19,keyasint" json:"policy_digest"`
	PolicyRevision                         uint64  `cbor:"20,keyasint" json:"policy_revision"`
	UseLeaseDigest                         []byte  `cbor:"21,keyasint" json:"use_lease_digest"`
	ControlScopeGeneration                 uint64  `cbor:"22,keyasint" json:"control_scope_generation"`
	InventoryRevision                      uint64  `cbor:"23,keyasint" json:"inventory_revision"`
	RuntimeAndSandboxDigest                []byte  `cbor:"24,keyasint" json:"runtime_and_sandbox_digest"`
	EffectiveEnvironmentDigest             []byte  `cbor:"25,keyasint" json:"effective_environment_digest"`
	CredentialCapabilityReferenceSetDigest []byte  `cbor:"26,keyasint" json:"credential_capability_reference_set_digest"`
	FilesystemHandleSetDigest              []byte  `cbor:"27,keyasint" json:"filesystem_handle_set_digest"`
	NetworkBrokerPolicyDigest              []byte  `cbor:"28,keyasint" json:"network_broker_policy_digest"`
	RemoteSessionHandshakeDigest           *[]byte `cbor:"29,keyasint" json:"remote_session_handshake_digest"`
	StartNotAfterUnix                      uint64  `cbor:"30,keyasint" json:"start_not_after_unix"`
	InvocationDescriptorDigest             []byte  `cbor:"31,keyasint" json:"invocation_descriptor_digest"`
}
