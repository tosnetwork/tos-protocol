// Package agentrelay defines the business-neutral service profile used by an
// Agent that sponsors gas, relays an exact client-signed transaction, or does
// both. It deliberately does not define a market, a chain opcode, or a new
// semantic identity for the underlying economic action.
package agentrelay

import (
	"context"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

const (
	ProfileURI                         = "tos.agent-service.transaction-relay.v1"
	ServiceProfileContentType          = "application/vnd.tos.agent-relay-service-profile.v1+cbor"
	QuoteRequestContentType            = "application/vnd.tos.agent-relay-quote-request.v1+cbor"
	ProviderQuoteContentType           = "application/vnd.tos.agent-relay-provider-quote.v1+cbor"
	ExecutionRequestContentType        = "application/vnd.tos.agent-relay-execution-request.v1+cbor"
	ResolutionContentType              = "application/vnd.tos.agent-relay-resolution.v1+cbor"
	FinalityEvidenceContentType        = "application/vnd.tos.agent-relay-finality-evidence.v1+cbor"
	SponsorshipEvidenceContentType     = "application/vnd.tos.agent-relay-sponsorship-transaction-evidence.v1+cbor"
	SponsorshipObservationContentType  = "application/vnd.tos.agent-relay-sponsorship-credit-observation.v1+cbor"
	AgreementBindingContentType        = "application/vnd.tos.agent-relay-agreement-binding.v1+cbor"
	QuoteCallContentType               = "application/vnd.tos.agent-relay-quote-call.v1+cbor"
	QuoteResultContentType             = "application/vnd.tos.agent-relay-quote-result.v1+cbor"
	SubmitCallContentType              = "application/vnd.tos.agent-relay-submit-call.v1+cbor"
	SubmitResultContentType            = "application/vnd.tos.agent-relay-submit-result.v1+cbor"
	ResolveCallContentType             = "application/vnd.tos.agent-relay-resolve-call.v1+cbor"
	ResolveResultContentType           = "application/vnd.tos.agent-relay-resolve-result.v1+cbor"
	EvidenceCallContentType            = "application/vnd.tos.agent-relay-evidence-call.v1+cbor"
	EvidenceResultContentType          = "application/vnd.tos.agent-relay-evidence-result.v1+cbor"
	DirectPaymentAdapterURI            = "tos.payment.direct.v1"
	RPCCorroborationEvidenceProfileURI = "agreement-payment-rpc-corroboration.v1"
	// ClientCorroboratedTerminalProfileURI names an explicit lower-assurance
	// terminal predicate. The complete FinalityProfile and its canonical digest
	// are signed before either party authorizes an Agreement, so an older
	// observed-only Agreement cannot be upgraded after a transfer is observed.
	ClientCorroboratedTerminalProfileURI = "tos.sponsorship.client-corroborated-terminal.v1"
	// ProviderCorroboratedTerminalProfileURI is the one released URI for a
	// lower-assurance relay predicate.  A terminal evidence class is not enough
	// to identify its rules: accepting an arbitrary URI would let two
	// implementations assign different semantics to the same class.
	ProviderCorroboratedTerminalProfileURI = "tos.relay.provider-corroborated-terminal.v1"

	ObligationRelayDelivery   = "transaction_relay"
	ObligationSponsorDelivery = "gas_sponsorship"
	ObligationRelayFee        = "transaction_relay_fee"
	ObligationSponsorshipFee  = "gas_sponsorship_fee"

	MaxSignedTransactionBytes = 64 << 10
	// Relay embeds []byte through the protocol JSON model, where base64 is a
	// canonical text string capped at 256 KiB. 192 KiB is therefore the exact
	// largest raw request that every conforming codec can represent.
	MaxRelayActionRequestBytes = 192 << 10
	MaxRelayRequestLifetime    = 15 * 60
	MaxRelayProfileLifetime    = 90 * 24 * 60 * 60
	MaxRelayEndpoints          = 4
	MaxRelayFeeLines           = 2
	MaxRelayEvidenceRefs       = 64
	// MaxRelayProofBundleBytes bounds an in-band, canonical proof attachment.
	// The value stays below codec.MaxStringBytes after JSON base64 expansion.
	MaxRelayProofBundleBytes    = 128 << 10
	MaxRelayAdmissionStartDelay = 60
	// MinimumRelayInclusionMarginSeconds is deliberately in addition to the
	// selected finality profile's complete resolution budget. It prevents a
	// provider from starting an irreversible side effect at the edge of an
	// otherwise technically unexpired authorization window.
	MinimumRelayInclusionMarginSeconds = 30
)

type Mode string

const (
	ModeRelayExact      Mode = "relay_exact"
	ModeSponsorOnly     Mode = "sponsor_only"
	ModeSponsorAndRelay Mode = "sponsor_and_relay"
)

// AssuranceLevel is orthogonal to Mode: Mode says which service side effects
// are requested, while AssuranceLevel says which operational trust and
// recovery profile the parties selected. It is signed by both parties and
// carried into Agreement and admission evidence so a coordinator cannot
// silently upgrade or downgrade the route after pricing.
type AssuranceLevel string

const (
	AssuranceTrustedLocal             AssuranceLevel = "trusted-local"
	AssuranceAuthorizedSingleProvider AssuranceLevel = "authorized-single-provider"
	AssuranceAutonomousDecentralized  AssuranceLevel = "autonomous-decentralized"
)

// SponsorshipReleaseEvidenceClass freezes the evidence threshold that may
// release a Provider-funded top-up into the relay stage. It is orthogonal to
// AssuranceLevel: the assurance level selects the operating trust model,
// while this value prevents either party from changing the exact sponsorship
// release threshold after quote authorization.
type SponsorshipReleaseEvidenceClass string

const (
	SponsorshipReleaseValidatorFinality SponsorshipReleaseEvidenceClass = "validator_finality"
	SponsorshipReleaseObservedUnproven  SponsorshipReleaseEvidenceClass = "observed_unproven"
)

// SponsorshipReleaseProfile is the exact selected capability descriptor.
// Discovery/readiness code compares this value, rather than a boolean such as
// "supports sponsorship", before it constructs a signed quote request.
type SponsorshipReleaseProfile struct {
	EvidenceClass SponsorshipReleaseEvidenceClass `json:"evidence_class"`
	ProfileURI    string                          `json:"profile_uri"`
	ProfileDigest string                          `json:"profile_digest"`
}

// RelayEvidenceCapability is the exact, currently selected readiness tuple.
// It is a local capability query rather than a wire certificate: callers must
// build it from the signed request/profile pair and must not reuse its answer
// for another mode, assurance level, or predicate digest.
type RelayEvidenceCapability struct {
	Mode                             Mode
	AssuranceLevel                   AssuranceLevel
	Network                          NetworkDomain
	TransactionProfileURI            string
	TransactionProfileDigest         string
	UnderlyingActionKind             string
	RelayTerminalEvidenceClass       RelayTerminalEvidenceClass
	SponsorshipTerminalEvidenceClass SponsorshipTerminalEvidenceClass
	RelayFinalityProfile             *FinalityProfile
	SponsorshipReleaseProfile        SponsorshipReleaseProfile
	SponsorshipTerminalProfile       *FinalityProfile
	AbsenceProofProfileURI           string
	AbsenceProofProfileDigest        string
}

func (body RelayQuoteRequestBody) SelectedSponsorshipReleaseProfile() SponsorshipReleaseProfile {
	return SponsorshipReleaseProfile{EvidenceClass: body.SponsorshipReleaseEvidenceClass,
		ProfileURI: body.SponsorshipReleaseProfileURI, ProfileDigest: body.SponsorshipReleaseProfileDigest}
}

func (body ProviderRelayQuoteBody) SelectedSponsorshipReleaseProfile() SponsorshipReleaseProfile {
	return SponsorshipReleaseProfile{EvidenceClass: body.SponsorshipReleaseEvidenceClass,
		ProfileURI: body.SponsorshipReleaseProfileURI, ProfileDigest: body.SponsorshipReleaseProfileDigest}
}

// SideEffectStage identifies the irreversible boundary whose remaining
// signed-validity budget is being checked.
type SideEffectStage string

const (
	SideEffectSponsorship SideEffectStage = "sponsorship"
	SideEffectBroadcast   SideEffectStage = "broadcast"
)

// NetworkDomain prevents a display network name from being confused with a
// different chain. Both zero-state hashes are required because either hash by
// itself is an incomplete TOS network identity.
type NetworkDomain struct {
	NetworkID         string `json:"network_id"`
	GlobalID          int32  `json:"global_id"`
	ZeroStateRootHash string `json:"zero_state_root_hash"`
	ZeroStateFileHash string `json:"zero_state_file_hash"`
	WorkchainID       int32  `json:"workchain_id"`
}

type AssetIdentity struct {
	AssetNamespace  string `json:"asset_namespace"`
	AssetIdentifier string `json:"asset_identifier"`
	Unit            string `json:"unit"`
}

type AssetAmount struct {
	Asset        AssetIdentity `json:"asset"`
	AmountAtomic string        `json:"amount_atomic"`
}

type TransactionProfile struct {
	ProfileURI                   string `json:"profile_uri"`
	ProfileDigest                string `json:"profile_digest"`
	MaximumSignedBytes           uint32 `json:"maximum_signed_bytes"`
	InspectableSourceSequence    bool   `json:"inspectable_source_sequence"`
	InspectableTransactionExpiry bool   `json:"inspectable_transaction_expiry"`
}

// FinalityProfile names the exact evidence rules. A signed provider statement
// is never sufficient by itself; the client independently verifies the
// referenced chain evidence under this descriptor.
type FinalityProfile struct {
	ProfileURI               string                `json:"profile_uri"`
	ProfileDigest            string                `json:"profile_digest"`
	TerminalEvidenceClass    TerminalEvidenceClass `json:"terminal_evidence_class"`
	MinimumConfirmationDepth uint32                `json:"minimum_confirmation_depth"`
	MinimumObservers         uint16                `json:"minimum_observers"`
	MinimumOperatorDomains   uint16                `json:"minimum_operator_domains"`
	ReorgWindowSeconds       uint32                `json:"reorg_window_seconds"`
	MaximumResolutionSeconds uint32                `json:"maximum_resolution_seconds"`
}

type ExposureLimit struct {
	Asset                    AssetIdentity `json:"asset"`
	MaximumPerRequestAtomic  string        `json:"maximum_per_request_atomic"`
	MaximumOutstandingAtomic string        `json:"maximum_outstanding_atomic"`
}

// AdmissionLimits are provider-wide, signed availability ceilings. They are
// enforced atomically with quote reservation and execution admission. A
// provider may refuse work for a stricter local reason, but it may not admit
// more work than these published bounds under one profile revision.
type AdmissionLimits struct {
	MaximumQuoteReservations               uint32 `json:"maximum_quote_reservations"`
	MaximumActiveExecutions                uint32 `json:"maximum_active_executions"`
	MaximumActivePerRequester              uint32 `json:"maximum_active_per_requester"`
	MaximumQuoteRequestsPerWindow          uint32 `json:"maximum_quote_requests_per_window"`
	MaximumQuoteRequestsPerRequesterWindow uint32 `json:"maximum_quote_requests_per_requester_window"`
	QuoteRequestWindowSeconds              uint32 `json:"quote_request_window_seconds"`
}

type ServiceEndpoints struct {
	QuoteURL    string `json:"quote_url"`
	SubmitURL   string `json:"submit_url"`
	ResolveURL  string `json:"resolve_url"`
	EvidenceURL string `json:"evidence_url"`
}

// RelayServiceProfile is placed in the detail of an ordinary signed OFFER
// Intent. The Intent signature authenticates these bytes; this object is not a
// second publication or a globally authoritative market record.
type RelayServiceProfile struct {
	SchemaVersion            uint16               `json:"schema_version"`
	ProfileID                string               `json:"profile_id"`
	Revision                 uint64               `json:"revision"`
	ProviderAgentID          string               `json:"provider_agent_id"`
	NetworkDomains           []NetworkDomain      `json:"network_domains"`
	SupportedModes           []Mode               `json:"supported_modes"`
	SupportedAssuranceLevels []AssuranceLevel     `json:"supported_assurance_levels"`
	TransactionProfiles      []TransactionProfile `json:"transaction_profiles"`
	FinalityProfiles         []FinalityProfile    `json:"finality_profiles"`
	FeeAssets                []AssetIdentity      `json:"fee_assets"`
	ExposureLimits           []ExposureLimit      `json:"exposure_limits"`
	AdmissionLimits          AdmissionLimits      `json:"admission_limits"`
	MaximumRequestBytes      uint32               `json:"maximum_request_bytes"`
	Endpoints                ServiceEndpoints     `json:"endpoints"`
	PolicyRevision           uint64               `json:"policy_revision"`
	CreatedAtUnix            uint64               `json:"created_at_unix"`
	ExpiresAtUnix            uint64               `json:"expires_at_unix"`
}

type RelayQuoteRequestBody struct {
	SchemaVersion                    uint16                           `json:"schema_version"`
	RequestID                        string                           `json:"request_id"`
	RequesterAgentID                 string                           `json:"requester_agent_id"`
	ProviderAgentID                  string                           `json:"provider_agent_id"`
	Network                          NetworkDomain                    `json:"network"`
	Mode                             Mode                             `json:"mode"`
	AssuranceLevel                   AssuranceLevel                   `json:"assurance_level"`
	SponsorshipReleaseEvidenceClass  SponsorshipReleaseEvidenceClass  `json:"sponsorship_release_evidence_class,omitempty"`
	SponsorshipReleaseProfileURI     string                           `json:"sponsorship_release_profile_uri,omitempty"`
	SponsorshipReleaseProfileDigest  string                           `json:"sponsorship_release_profile_digest,omitempty"`
	RelayTerminalEvidenceClass       RelayTerminalEvidenceClass       `json:"relay_terminal_evidence_class,omitempty"`
	SponsorshipTerminalEvidenceClass SponsorshipTerminalEvidenceClass `json:"sponsorship_terminal_evidence_class,omitempty"`
	SourceAccount                    string                           `json:"source_account"`
	SourceAccountAuthorityDigest     string                           `json:"source_account_authority_digest"`
	TransactionProfileURI            string                           `json:"transaction_profile_uri"`
	TransactionProfileDigest         string                           `json:"transaction_profile_digest"`
	UnderlyingActionKind             string                           `json:"underlying_action_kind"`
	StableActionID                   string                           `json:"stable_action_id"`
	ExactRequestDigest               string                           `json:"exact_request_digest"`
	SignedTransactionDigest          string                           `json:"signed_transaction_digest"`
	SignedTransactionCellHash        string                           `json:"signed_transaction_cell_hash"`
	SignedTransactionSize            uint32                           `json:"signed_transaction_size"`
	TransactionIntentDigest          string                           `json:"transaction_intent_digest"`
	SourceSequence                   uint64                           `json:"source_sequence"`
	TransactionValidUntilUnix        uint64                           `json:"transaction_valid_until_unix"`
	RequestedSponsorship             *AssetAmount                     `json:"requested_sponsorship,omitempty"`
	MaximumServiceFee                AssetAmount                      `json:"maximum_service_fee"`
	MaximumNetworkFeeAtomic          string                           `json:"maximum_network_fee_atomic"`
	MaximumTransactionValueAtomic    string                           `json:"maximum_transaction_value_atomic"`
	RelayFinalityProfileURI          string                           `json:"relay_finality_profile_uri,omitempty"`
	RelayFinalityProfileDigest       string                           `json:"relay_finality_profile_digest,omitempty"`
	SponsorshipTerminalProfileURI    string                           `json:"sponsorship_terminal_profile_uri,omitempty"`
	SponsorshipTerminalProfileDigest string                           `json:"sponsorship_terminal_profile_digest,omitempty"`
	CreatedAtUnix                    uint64                           `json:"created_at_unix"`
	ExpiresAtUnix                    uint64                           `json:"expires_at_unix"`
}

// SignedRelayQuoteRequest carries only an authenticated transaction
// descriptor. The exact bearer-executable transaction is deliberately
// withheld from candidate providers until one provider has been selected and
// a complete Agreement has been authorized.
type SignedRelayQuoteRequest struct {
	Body      RelayQuoteRequestBody `json:"body"`
	PublicKey string                `json:"public_key"`
	Signature string                `json:"signature"`
}

type FeeLine struct {
	Kind   string      `json:"kind"`
	Amount AssetAmount `json:"amount"`
}

type ProviderRelayQuoteBody struct {
	SchemaVersion                    uint16                           `json:"schema_version"`
	QuoteID                          string                           `json:"quote_id"`
	QuoteRequestDigest               string                           `json:"quote_request_digest"`
	ServiceProfileDigest             string                           `json:"service_profile_digest"`
	ProviderAgentID                  string                           `json:"provider_agent_id"`
	Mode                             Mode                             `json:"mode"`
	AssuranceLevel                   AssuranceLevel                   `json:"assurance_level"`
	SponsorshipReleaseEvidenceClass  SponsorshipReleaseEvidenceClass  `json:"sponsorship_release_evidence_class,omitempty"`
	SponsorshipReleaseProfileURI     string                           `json:"sponsorship_release_profile_uri,omitempty"`
	SponsorshipReleaseProfileDigest  string                           `json:"sponsorship_release_profile_digest,omitempty"`
	RelayTerminalEvidenceClass       RelayTerminalEvidenceClass       `json:"relay_terminal_evidence_class,omitempty"`
	SponsorshipTerminalEvidenceClass SponsorshipTerminalEvidenceClass `json:"sponsorship_terminal_evidence_class,omitempty"`
	FeeLines                         []FeeLine                        `json:"fee_lines"`
	ReservedSponsorship              *AssetAmount                     `json:"reserved_sponsorship,omitempty"`
	MaximumNetworkFeeAtomic          string                           `json:"maximum_network_fee_atomic"`
	MaximumTransactionValueAtomic    string                           `json:"maximum_transaction_value_atomic"`
	MaximumRequestBytes              uint32                           `json:"maximum_request_bytes"`
	RelayFinalityProfile             *FinalityProfile                 `json:"relay_finality_profile,omitempty"`
	SponsorshipTerminalProfile       *FinalityProfile                 `json:"sponsorship_terminal_profile,omitempty"`
	StatusEndpoint                   string                           `json:"status_endpoint"`
	ProviderPolicyRevision           uint64                           `json:"provider_policy_revision"`
	OfferIntentDigest                string                           `json:"offer_intent_digest,omitempty"`
	ValidFromUnix                    uint64                           `json:"valid_from_unix"`
	ExpiresAtUnix                    uint64                           `json:"expires_at_unix"`
}

type SignedProviderRelayQuote struct {
	Body      ProviderRelayQuoteBody `json:"body"`
	PublicKey string                 `json:"public_key"`
	Signature string                 `json:"signature"`
}

// RelayAgreementBinding is embedded byte-for-byte in every Agreement
// obligation belonging to this service. It keeps the generic Agreement model
// while preventing an obligation from being reused with another quote,
// transaction, or underlying economic action.
type RelayAgreementBinding struct {
	SchemaVersion                    uint16                           `json:"schema_version"`
	QuoteRequestDigest               string                           `json:"quote_request_digest"`
	ProviderQuoteDigest              string                           `json:"provider_quote_digest"`
	ServiceProfileDigest             string                           `json:"service_profile_digest"`
	Mode                             Mode                             `json:"mode"`
	AssuranceLevel                   AssuranceLevel                   `json:"assurance_level"`
	SponsorshipReleaseEvidenceClass  SponsorshipReleaseEvidenceClass  `json:"sponsorship_release_evidence_class,omitempty"`
	SponsorshipReleaseProfileURI     string                           `json:"sponsorship_release_profile_uri,omitempty"`
	SponsorshipReleaseProfileDigest  string                           `json:"sponsorship_release_profile_digest,omitempty"`
	RelayTerminalEvidenceClass       RelayTerminalEvidenceClass       `json:"relay_terminal_evidence_class,omitempty"`
	SponsorshipTerminalEvidenceClass SponsorshipTerminalEvidenceClass `json:"sponsorship_terminal_evidence_class,omitempty"`
	RelayFinalityProfileURI          string                           `json:"relay_finality_profile_uri,omitempty"`
	RelayFinalityProfileDigest       string                           `json:"relay_finality_profile_digest,omitempty"`
	SponsorshipTerminalProfileURI    string                           `json:"sponsorship_terminal_profile_uri,omitempty"`
	SponsorshipTerminalProfileDigest string                           `json:"sponsorship_terminal_profile_digest,omitempty"`
	RequesterAgentID                 string                           `json:"requester_agent_id"`
	ProviderAgentID                  string                           `json:"provider_agent_id"`
	StableActionID                   string                           `json:"stable_action_id"`
	ExactRequestDigest               string                           `json:"exact_request_digest"`
	SignedTransactionDigest          string                           `json:"signed_transaction_digest"`
}

// RelayExecutionRequest is the exact service envelope. AuthorizedAction and
// ExactRequestDigest continue to identify the underlying economic action; the
// provider route and quote are intentionally excluded from that stable ID.
type RelayExecutionRequest struct {
	SchemaVersion           uint16                                `json:"schema_version"`
	QuoteRequest            SignedRelayQuoteRequest               `json:"quote_request"`
	ProviderQuote           SignedProviderRelayQuote              `json:"provider_quote"`
	SignedTransactionBytes  []byte                                `json:"signed_transaction_bytes"`
	AgreementBodyDigest     string                                `json:"agreement_body_digest"`
	AgreementExpiresAtUnix  uint64                                `json:"agreement_expires_at_unix"`
	RelayObligationID       string                                `json:"relay_obligation_id,omitempty"`
	SponsorshipObligationID string                                `json:"sponsorship_obligation_id,omitempty"`
	FeeObligationIDs        []string                              `json:"fee_obligation_ids"`
	UnderlyingActionRequest []byte                                `json:"underlying_action_request"`
	SemanticFields          []agentcommerce.SemanticFieldValue    `json:"semantic_fields"`
	AuthorizedAction        agentcommerce.AuthorizedAction        `json:"authorized_action"`
	WriterFence             agentcommerce.WriterFence             `json:"writer_fence"`
	AdmissionReceipt        SignedRelaySideEffectAdmissionReceipt `json:"admission_receipt"`
	CreatedAtUnix           uint64                                `json:"created_at_unix"`
	ExpiresAtUnix           uint64                                `json:"expires_at_unix"`
}

type TerminalOutcome string

const (
	OutcomeFinalizedSuccess TerminalOutcome = "finalized_success"
	// OutcomeCorroboratedSuccess means every requested side effect succeeded
	// under the exact signed lower-assurance predicates, while at least one
	// component lacks validator-authenticated portable proof. It is never valid
	// for autonomous-decentralized assurance.
	OutcomeCorroboratedSuccess      TerminalOutcome = "corroborated_success"
	OutcomeFinalizedExpired         TerminalOutcome = "finalized_expired"
	OutcomeFinalizedAbsent          TerminalOutcome = "finalized_absent"
	OutcomeFinalizedInvalidated     TerminalOutcome = "finalized_invalidated"
	OutcomeCorroboratedExpired      TerminalOutcome = "corroborated_expired"
	OutcomeCorroboratedAbsent       TerminalOutcome = "corroborated_absent"
	OutcomeCorroboratedInvalidated  TerminalOutcome = "corroborated_invalidated"
	OutcomeFinalizedSponsorshipOnly TerminalOutcome = "finalized_sponsorship_only"
	// OutcomeCorroboratedSponsorshipOnly closes a lower-assurance sponsorship
	// obligation under an owner-selected, independently re-queried
	// corroboration predicate. It is deliberately distinct from validator
	// finality and is never valid for autonomous-decentralized assurance.
	OutcomeCorroboratedSponsorshipOnly TerminalOutcome = "corroborated_sponsorship_only"
	// OutcomeFinalizedRelayOnly closes a combined sponsorship-and-relay
	// execution when the exact client transaction succeeded but the exact
	// sponsorship effect was proven absent under validator-authenticated
	// predicates. It is never a success for the sponsorship obligation.
	OutcomeFinalizedRelayOnly TerminalOutcome = "finalized_relay_only"
	// OutcomeCorroboratedRelayOnly is the lower-assurance counterpart of
	// OutcomeFinalizedRelayOnly. At least one selected component predicate is
	// independently corroborated rather than validator authenticated.
	OutcomeCorroboratedRelayOnly TerminalOutcome = "corroborated_relay_only"
)

// RelayTerminalEvidenceClass states who authenticates the relay terminal
// predicate. Provider corroboration is deliberately available only to the two
// lower assurance levels; autonomous operation requires validator-authenticated
// portable evidence and an independent client verifier.
type TerminalEvidenceClass string

type RelayTerminalEvidenceClass = TerminalEvidenceClass

const (
	RelayTerminalValidatorFinality    TerminalEvidenceClass = "validator_finality"
	RelayTerminalProviderCorroborated TerminalEvidenceClass = "provider_corroborated"
)

type SponsorshipTerminalEvidenceClass = TerminalEvidenceClass

const (
	SponsorshipTerminalValidatorFinality  TerminalEvidenceClass = "validator_finality"
	SponsorshipTerminalClientCorroborated TerminalEvidenceClass = "client_corroborated"
)

type RelayResolutionBody struct {
	SchemaVersion                 uint16                              `json:"schema_version"`
	ProviderAgentID               string                              `json:"provider_agent_id"`
	Network                       NetworkDomain                       `json:"network"`
	AssuranceLevel                AssuranceLevel                      `json:"assurance_level"`
	StableActionID                string                              `json:"stable_action_id"`
	ExactRequestDigest            string                              `json:"exact_request_digest"`
	RelayExecutionDigest          string                              `json:"relay_execution_request_digest"`
	State                         agentcommerce.ActionResolutionState `json:"state"`
	StateRevision                 uint64                              `json:"state_revision"`
	TerminalOutcome               TerminalOutcome                     `json:"terminal_outcome,omitempty"`
	TransactionReference          string                              `json:"transaction_reference,omitempty"`
	SponsorshipStableActionID     string                              `json:"sponsorship_stable_action_id,omitempty"`
	SponsorshipExactRequestDigest string                              `json:"sponsorship_exact_request_digest,omitempty"`
	SponsorshipValidUntilUnix     uint64                              `json:"sponsorship_valid_until_unix,omitempty"`
	SponsorshipTransferReference  string                              `json:"sponsorship_transfer_reference,omitempty"`
	SponsorshipStatus             SponsorshipResolutionStatus         `json:"sponsorship_status,omitempty"`
	SponsorshipObservationDigest  string                              `json:"sponsorship_observation_digest,omitempty"`
	EvidenceSetDigest             string                              `json:"evidence_set_digest,omitempty"`
	ObservedAtUnix                uint64                              `json:"observed_at_unix"`
	ExpiresAtUnix                 uint64                              `json:"expires_at_unix"`
}

// RelaySponsorshipCreditObservation is explicit nonterminal RPC
// corroboration. It proves that a bounded query succeeded and binds the exact
// top-up transaction identity, but it is not validator-authenticated finality
// and can never recognize revenue, release exposure, or authorize another
// top-up.
type RelaySponsorshipCreditObservation struct {
	SchemaVersion                  uint16                                `json:"schema_version"`
	NetworkDigest                  string                                `json:"network_digest"`
	AgreementPaymentRequest        agentcommerce.AgreementPaymentRequest `json:"agreement_payment_request"`
	AgreementPaymentRequestDigest  string                                `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID      string                                `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest  string                                `json:"sponsorship_exact_request_digest"`
	ProviderSponsorSourceAccount   string                                `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence  uint64                                `json:"provider_sponsor_source_sequence"`
	ProviderSponsorValidUntilUnix  uint64                                `json:"provider_sponsor_valid_until_unix"`
	SignedTopUpTransactionDigest   string                                `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash string                                `json:"signed_top_up_transaction_cell_hash"`
	// SponsorshipPaymentCommitmentCellHash is the hash of the exact
	// domain-separated task body committed by the Provider's signed top-up.
	// A chain Adapter must independently reconstruct this body from the
	// AgreementPaymentRequest digest and stable action ID.  This prevents an
	// old same-account/same-amount transfer from being reused for another
	// Agreement.
	SponsorshipPaymentCommitmentCellHash string      `json:"sponsorship_payment_commitment_cell_hash"`
	DestinationSourceAccount             string      `json:"destination_source_account"`
	Amount                               AssetAmount `json:"amount"`
	SubmittedTransactionHash             string      `json:"submitted_transaction_hash"`
	SourceExecutionReference             string      `json:"source_execution_reference"`
	DestinationCreditReferences          []string    `json:"destination_credit_references"`
	EvidenceProfileURI                   string      `json:"evidence_profile_uri"`
	EvidenceProfileDigest                string      `json:"evidence_profile_digest"`
	ObservedCheckpointID                 string      `json:"observed_checkpoint_id"`
	ObservedCheckpointSequence           uint64      `json:"observed_checkpoint_sequence"`
	ObservedCheckpointUnix               uint64      `json:"observed_checkpoint_unix"`
	ObservationDigests                   []string    `json:"observation_digests"`
	ObservedAtUnix                       uint64      `json:"observed_at_unix"`
}

type SignedRelayResolution struct {
	Body      RelayResolutionBody `json:"body"`
	PublicKey string              `json:"public_key"`
	Signature string              `json:"signature"`
}

// RelaySponsorshipTransactionEvidence is the exact transaction-level proof
// projection for the Provider-funded top-up. A legacy transfer reference can
// identify a journal entry, but it cannot by itself prove which Provider
// account spent which sequence, which signed BOC was executed, or which source
// Agent Account received the exact credit. The parent finality-evidence
// signature authenticates this nested canonical object.
type RelaySponsorshipTransactionEvidence struct {
	SchemaVersion                        uint16                                `json:"schema_version"`
	TerminalEvidenceClass                SponsorshipTerminalEvidenceClass      `json:"terminal_evidence_class"`
	ValidatorAuthenticatedPortableProof  bool                                  `json:"validator_authenticated_portable_proof"`
	NetworkDigest                        string                                `json:"network_digest"`
	AgreementPaymentRequest              agentcommerce.AgreementPaymentRequest `json:"agreement_payment_request"`
	AgreementPaymentRequestDigest        string                                `json:"agreement_payment_request_digest"`
	SponsorshipStableActionID            string                                `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest        string                                `json:"sponsorship_exact_request_digest"`
	ProviderSponsorSourceAccount         string                                `json:"provider_sponsor_source_account"`
	ProviderSponsorSourceSequence        uint64                                `json:"provider_sponsor_source_sequence"`
	ProviderSponsorValidUntilUnix        uint64                                `json:"provider_sponsor_valid_until_unix"`
	SignedTopUpTransactionDigest         string                                `json:"signed_top_up_transaction_digest"`
	SignedTopUpTransactionCellHash       string                                `json:"signed_top_up_transaction_cell_hash"`
	SponsorshipPaymentCommitmentCellHash string                                `json:"sponsorship_payment_commitment_cell_hash"`
	DestinationSourceAccount             string                                `json:"destination_source_account"`
	Amount                               AssetAmount                           `json:"amount"`
	SubmittedTransactionHash             string                                `json:"submitted_transaction_hash"`
	SourceExecutionReference             string                                `json:"source_execution_reference"`
	DestinationCreditReferences          []string                              `json:"destination_credit_references"`
	FinalizedCheckpointID                string                                `json:"finalized_checkpoint_id"`
	FinalizedCheckpointSequence          uint64                                `json:"finalized_checkpoint_sequence"`
	FinalizedCheckpointUnix              uint64                                `json:"finalized_checkpoint_unix"`
	ConfirmationDepth                    uint32                                `json:"confirmation_depth"`
	SponsorshipTerminalProfileDigest     string                                `json:"sponsorship_terminal_profile_digest"`
	ObservationDigests                   []string                              `json:"observation_digests"`
	ProofBundleDigest                    string                                `json:"proof_bundle_digest"`
	// ProofBundle carries the exact deterministic-CBOR proof attachment for
	// lower-assurance remote verification. Autonomous evidence may instead (or
	// additionally) use PortableProofLocator, which remains mandatory there.
	ProofBundle          []byte `json:"proof_bundle,omitempty"`
	PortableProofLocator string `json:"portable_proof_locator,omitempty"`
	ObservedAtUnix       uint64 `json:"observed_at_unix"`
}

type RelayFinalityEvidenceBody struct {
	SchemaVersion                  uint16                               `json:"schema_version"`
	ProviderAgentID                string                               `json:"provider_agent_id"`
	Network                        NetworkDomain                        `json:"network"`
	AssuranceLevel                 AssuranceLevel                       `json:"assurance_level"`
	StableActionID                 string                               `json:"stable_action_id"`
	ExactRequestDigest             string                               `json:"exact_request_digest"`
	RelayExecutionDigest           string                               `json:"relay_execution_request_digest"`
	SignedTransactionDigest        string                               `json:"signed_transaction_digest"`
	SignedTransactionCellHash      string                               `json:"signed_transaction_cell_hash"`
	TransactionValidUntilUnix      uint64                               `json:"transaction_valid_until_unix"`
	SourceAccount                  string                               `json:"source_account"`
	SourceSequence                 uint64                               `json:"source_sequence"`
	SponsorshipStableActionID      string                               `json:"sponsorship_stable_action_id,omitempty"`
	SponsorshipExactRequestDigest  string                               `json:"sponsorship_exact_request_digest,omitempty"`
	SponsorshipValidUntilUnix      uint64                               `json:"sponsorship_valid_until_unix,omitempty"`
	SponsorshipTransferReference   string                               `json:"sponsorship_transfer_reference,omitempty"`
	SponsorshipTransactionEvidence *RelaySponsorshipTransactionEvidence `json:"sponsorship_transaction_evidence,omitempty"`
	SponsorshipAbsenceObservations []RelayAbsenceObservationReference   `json:"sponsorship_absence_observations,omitempty"`
	TransactionAbsenceObservations []RelayAbsenceObservationReference   `json:"transaction_absence_observations,omitempty"`
	AbsenceProofBundleDigest       string                               `json:"absence_proof_bundle_digest,omitempty"`
	// AbsenceProofBundle is a bounded, exact Core Deterministic CBOR V1
	// manifest. It is mandatory for every absence result, including portable
	// validator profiles, so an independent verifier can bind the observation
	// references to the exact signed effects before it performs fresh queries.
	AbsenceProofBundle          []byte                     `json:"absence_proof_bundle,omitempty"`
	SponsorshipTerminalProfile  *FinalityProfile           `json:"sponsorship_terminal_profile,omitempty"`
	SubmittedTransactionHash    string                     `json:"submitted_transaction_hash,omitempty"`
	SourceExecutionReference    string                     `json:"source_execution_reference,omitempty"`
	DestinationCreditReferences []string                   `json:"destination_credit_references,omitempty"`
	RelayTerminalEvidenceClass  RelayTerminalEvidenceClass `json:"relay_terminal_evidence_class,omitempty"`
	// RelayValidatorAuthenticatedPortableProof is presence-sensitive. Relay
	// terminal evidence must explicitly commit true for validator-authenticated
	// proof and false for the selected provider-corroborated predicate. It is
	// omitted only when no relay terminal component is present.
	RelayValidatorAuthenticatedPortableProof *bool            `json:"relay_validator_authenticated_portable_proof,omitempty"`
	RelayFinalizedCheckpointID               string           `json:"relay_finalized_checkpoint_id,omitempty"`
	RelayFinalizedCheckpointSequence         uint64           `json:"relay_finalized_checkpoint_sequence,omitempty"`
	RelayFinalizedCheckpointUnix             uint64           `json:"relay_finalized_checkpoint_unix,omitempty"`
	RelayConfirmationDepth                   uint32           `json:"relay_confirmation_depth,omitempty"`
	RelayFinalityProfile                     *FinalityProfile `json:"relay_finality_profile,omitempty"`
	RelayObservationDigests                  []string         `json:"relay_observation_digests,omitempty"`
	Outcome                                  TerminalOutcome  `json:"outcome"`
	ObservedAtUnix                           uint64           `json:"observed_at_unix"`
	// SigningAuthorityAtUnix selects the Provider key-authorization epoch.
	// It is distinct from ObservedAtUnix, which is chain evidence time and may
	// predate a Provider key rotation by an arbitrary interval.
	SigningAuthorityAtUnix uint64 `json:"signing_authority_at_unix"`
}

type SignedRelayFinalityEvidence struct {
	Body      RelayFinalityEvidenceBody `json:"body"`
	PublicKey string                    `json:"public_key"`
	Signature string                    `json:"signature"`
}

// The HTTP/Connect transport is intentionally thin. These bounded messages
// freeze Quote/Submit/Resolve/Evidence without making any gateway or endpoint
// authoritative for discovery, Agreement state, or chain outcome.
type QuoteCall struct {
	Request SignedRelayQuoteRequest `json:"request"`
}

type QuoteResult struct {
	Quote SignedProviderRelayQuote `json:"quote"`
}

type SubmitCall struct {
	Request   RelayExecutionRequest        `json:"request"`
	Agreement agentcommerce.AgentAgreement `json:"agreement"`
}

type SubmitResult struct {
	Resolution SignedRelayResolution `json:"resolution"`
}

type ResolveCall struct {
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
}

type ResolveResult struct {
	Resolution SignedRelayResolution `json:"resolution"`
}

type EvidenceCall struct {
	StableActionID     string `json:"stable_action_id"`
	ExactRequestDigest string `json:"exact_request_digest"`
}

type EvidenceResult struct {
	Evidence SignedRelayFinalityEvidence `json:"evidence"`
}

// InspectedTransaction is produced by a chain-specific parser. The parser is
// mandatory: trusting caller-supplied source, sequence, expiry, gas, value, or
// cell hash would turn the service into a blind broadcaster.
type InspectedTransaction struct {
	NetworkDigest                 string
	SourceAccount                 string
	SourceAccountAuthorityDigest  string
	AuthorizedAgentID             string
	ControllerEpoch               uint64
	SourceSequence                uint64
	ValidUntilUnix                uint64
	Destination                   string
	ValueAtomic                   string
	TransactionIntentDigest       string
	SignedTransactionCellHash     string
	MaximumNetworkFeeAtomic       string
	MaximumTransactionValueAtomic string
}

// TransactionInspectionPhase makes the balance rule explicit. Admission may
// account for only the exact sponsorship amount already committed by the
// signed request and Provider quote. Broadcast readiness must freshly read
// on-chain balance and source sequence under the selected release profile and
// may not count that pending credit a second time. A lower-assurance RPC read
// is never relabelled as validator finality.
type TransactionInspectionPhase string

const (
	InspectionAdmission        TransactionInspectionPhase = "admission"
	InspectionReadyToBroadcast TransactionInspectionPhase = "ready_to_broadcast"
)

type TransactionInspector interface {
	InspectTransaction(context.Context, RelayQuoteRequestBody, TransactionProfile, []byte,
		TransactionInspectionPhase) (InspectedTransaction, error)
}

// ActionTransactionBinder proves that the parsed immutable transaction is the
// chain realization of the original canonical economic action request. This
// prevents a correctly signed but unrelated transaction from borrowing an
// AuthorizedAction and relay quote.
type ActionTransactionBinder interface {
	VerifyActionTransaction(RelayExecutionRequest, InspectedTransaction) error
}
