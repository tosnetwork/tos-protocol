package agentrelay

import (
	"errors"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	RelayAbsenceProofBundleSchemaV1  = "tos.agent-relay-absence-proof-bundle.v1"
	RelayAbsenceProofBundleDomainV1  = "tos.agent-relay-absence-proof-bundle.v1"
	RelayAbsenceProofPayloadDomainV1 = "tos.agent-relay-absence-proof-payload.v1"
)

type RelayAbsenceProofScope string

const (
	RelayAbsenceProofSponsorshipOnly RelayAbsenceProofScope = "sponsorship_only"
	RelayAbsenceProofTransactionOnly RelayAbsenceProofScope = "transaction_only"
	RelayAbsenceProofDual            RelayAbsenceProofScope = "dual"
)

type RelayAbsenceObservationKind string

const (
	AbsenceObservationSponsorshipAction RelayAbsenceObservationKind = "sponsorship_action"
	AbsenceObservationClientTransaction RelayAbsenceObservationKind = "client_transaction"
)

type RelayAbsenceConclusion string

const (
	AbsenceConclusionAbsent                  RelayAbsenceConclusion = "absent"
	AbsenceConclusionExpiredWithoutInclusion RelayAbsenceConclusion = "expired_without_inclusion"
	AbsenceConclusionInvalidated             RelayAbsenceConclusion = "invalidated_without_inclusion"
)

// RelayAbsenceObservationReference is the canonical, content-addressed
// interpretation of a profile-qualified observer proof. ObservationDigest
// addresses the underlying signed proof; this wrapper prevents the same bytes
// from being relabelled as proof about a different side effect, action,
// profile, or finalized checkpoint.
type RelayAbsenceObservationReference struct {
	SchemaVersion                    uint16                      `json:"schema_version"`
	ObservationKind                  RelayAbsenceObservationKind `json:"observation_kind"`
	Conclusion                       RelayAbsenceConclusion      `json:"conclusion"`
	ProviderAgentID                  string                      `json:"provider_agent_id"`
	NetworkDigest                    string                      `json:"network_digest"`
	RelayStableActionID              string                      `json:"relay_stable_action_id"`
	RelayExactRequestDigest          string                      `json:"relay_exact_request_digest"`
	RelayExecutionDigest             string                      `json:"relay_execution_request_digest"`
	SponsorshipStableActionID        string                      `json:"sponsorship_stable_action_id"`
	SponsorshipExactRequestDigest    string                      `json:"sponsorship_exact_request_digest"`
	SponsorshipValidUntilUnix        uint64                      `json:"sponsorship_valid_until_unix"`
	SignedTransactionDigest          string                      `json:"signed_transaction_digest"`
	SignedTransactionCellHash        string                      `json:"signed_transaction_cell_hash"`
	TerminalProfileURI               string                      `json:"terminal_profile_uri"`
	TerminalProfileDigest            string                      `json:"terminal_profile_digest"`
	TerminalEvidenceClass            TerminalEvidenceClass       `json:"terminal_evidence_class"`
	FinalizedCheckpointID            string                      `json:"finalized_checkpoint_id"`
	FinalizedCheckpointSequence      uint64                      `json:"finalized_checkpoint_sequence"`
	FinalizedCheckpointUnix          uint64                      `json:"finalized_checkpoint_unix"`
	ObserverID                       string                      `json:"observer_id"`
	OperatorDomainID                 string                      `json:"operator_domain_id"`
	ObservationEvidenceProfileURI    string                      `json:"observation_evidence_profile_uri"`
	ObservationEvidenceProfileDigest string                      `json:"observation_evidence_profile_digest"`
	ObservationDigest                string                      `json:"observation_digest"`
	ObservedAtUnix                   uint64                      `json:"observed_at_unix"`
}

// RelayAbsenceProofBundleV1 is the generic, bounded wrapper around the stock
// tosctl adapter's exact canonical payload. ProofScope binds which typed
// reference arrays the payload is allowed to prove.
type RelayAbsenceProofBundleV1 struct {
	SchemaVersion                  uint16                             `json:"schema_version"`
	ProofScope                     RelayAbsenceProofScope             `json:"proof_scope"`
	ProofProfileURI                string                             `json:"proof_profile_uri"`
	ProofProfileDigest             string                             `json:"proof_profile_digest"`
	ProofPayloadDigest             string                             `json:"proof_payload_digest"`
	ProofPayload                   []byte                             `json:"proof_payload"`
	SponsorshipAbsenceObservations []RelayAbsenceObservationReference `json:"sponsorship_absence_observations,omitempty"`
	TransactionAbsenceObservations []RelayAbsenceObservationReference `json:"transaction_absence_observations,omitempty"`
}

func RelayAbsenceObservationReferenceDigest(reference RelayAbsenceObservationReference) (string, error) {
	if err := validateRelayAbsenceObservationReferenceShape(reference); err != nil {
		return "", err
	}
	return codec.Digest("tos.agent-relay-absence-observation-reference.v1", reference)
}

const RelayAbsenceTOSRPCProofProfileURI = "tos.relay-absence.tosctl-rpc-snapshot.v1"

type relayAbsenceTOSRPCProofProfileV1 struct {
	SchemaVersion            uint16 `json:"schema_version"`
	ProfileURI               string `json:"profile_uri"`
	IndependentSnapshotQuery bool   `json:"independent_snapshot_query"`
	MaximumBundleBytes       uint32 `json:"maximum_bundle_bytes"`
	ChainSideEffect          bool   `json:"chain_side_effect"`
}

func RelayAbsenceTOSRPCProofProfileDigest() (string, error) {
	return codec.Digest("tos.agent-relay-absence-proof-profile.v1", relayAbsenceTOSRPCProofProfileV1{
		SchemaVersion: 1, ProfileURI: RelayAbsenceTOSRPCProofProfileURI,
		IndependentSnapshotQuery: true, MaximumBundleBytes: MaxRelayProofBundleBytes,
		ChainSideEffect: false,
	})
}

func validateRelayAbsenceProofBundle(bundle RelayAbsenceProofBundleV1) error {
	profileDigest, profileErr := RelayAbsenceTOSRPCProofProfileDigest()
	if bundle.SchemaVersion != 1 || bundle.ProofProfileURI != RelayAbsenceTOSRPCProofProfileURI ||
		profileErr != nil || bundle.ProofProfileDigest != profileDigest ||
		!digestPattern.MatchString(bundle.ProofPayloadDigest) || len(bundle.ProofPayload) == 0 ||
		len(bundle.ProofPayload) > MaxRelayProofBundleBytes {
		return errors.New("relay absence proof bundle shape is invalid")
	}
	payloadDigest, err := codec.DigestCanonical(RelayAbsenceProofPayloadDomainV1, bundle.ProofPayload)
	if err != nil || payloadDigest != bundle.ProofPayloadDigest {
		return errors.New("relay absence proof payload digest is invalid")
	}
	hasSponsorship := len(bundle.SponsorshipAbsenceObservations) != 0
	hasTransaction := len(bundle.TransactionAbsenceObservations) != 0
	// A non-nil empty slice would encode an explicitly present empty array.
	// Inapplicable arrays must be nil so omitempty removes them entirely.
	if bundle.SponsorshipAbsenceObservations != nil && !hasSponsorship ||
		bundle.TransactionAbsenceObservations != nil && !hasTransaction {
		return errors.New("relay absence proof bundle has an empty component array")
	}
	switch bundle.ProofScope {
	case RelayAbsenceProofSponsorshipOnly:
		if !hasSponsorship || hasTransaction {
			return errors.New("sponsorship-only proof bundle has the wrong component arrays")
		}
	case RelayAbsenceProofTransactionOnly:
		if hasSponsorship || !hasTransaction {
			return errors.New("transaction-only proof bundle has the wrong component arrays")
		}
	case RelayAbsenceProofDual:
		if !hasSponsorship || !hasTransaction {
			return errors.New("dual proof bundle lacks one component array")
		}
	default:
		return errors.New("relay absence proof bundle scope is unknown")
	}
	if hasSponsorship && !sortedRequiredDigests(relayAbsenceObservationReferenceDigests(bundle.SponsorshipAbsenceObservations), 1) ||
		hasTransaction && !sortedRequiredDigests(relayAbsenceObservationReferenceDigests(bundle.TransactionAbsenceObservations), 1) {
		return errors.New("relay absence proof bundle reference arrays are invalid")
	}
	return nil
}

type relayAbsenceContext struct {
	providerAgentID                  string
	networkDigest                    string
	relayStableActionID              string
	relayExactRequestDigest          string
	relayExecutionDigest             string
	sponsorshipStableActionID        string
	sponsorshipExactRequestDigest    string
	sponsorshipValidUntilUnix        uint64
	transactionValidUntilUnix        uint64
	signedTransactionDigest          string
	signedTransactionCellHash        string
	observationEvidenceProfileURI    string
	observationEvidenceProfileDigest string
	sponsorshipTerminalProfile       FinalityProfile
	relayFinalityProfile             *FinalityProfile
	maximumObservedAtUnix            uint64
	outcome                          TerminalOutcome
}

func relayAbsenceContextForRequest(request RelayExecutionRequest, recovery SponsorshipRecoveryHandle,
	outcome TerminalOutcome, at time.Time) (relayAbsenceContext, error) {
	if !validSponsorshipIdentity(recovery.StableActionID, recovery.ExactRequestDigest) || recovery.ValidUntilUnix == 0 ||
		request.QuoteRequest.Body.TransactionValidUntilUnix == 0 {
		return relayAbsenceContext{}, errors.New("relay sponsorship absence identity is invalid")
	}
	networkDigest, err := NetworkDomainDigest(request.QuoteRequest.Body.Network)
	if err != nil {
		return relayAbsenceContext{}, err
	}
	executionDigest, err := RelayExecutionRequestDigest(request)
	if err != nil {
		return relayAbsenceContext{}, err
	}
	nowSeconds := at.UTC().Unix()
	if nowSeconds < 0 || uint64(nowSeconds) > ^uint64(0)-5*60 {
		return relayAbsenceContext{}, errors.New("relay absence observation time is invalid")
	}
	if request.ProviderQuote.Body.SponsorshipTerminalProfile == nil {
		return relayAbsenceContext{}, errors.New("relay sponsorship absence terminal profile is missing")
	}
	releaseProfile := request.QuoteRequest.Body.SelectedSponsorshipReleaseProfile()
	if releaseProfile.ProfileURI == "" || !digestPattern.MatchString(releaseProfile.ProfileDigest) {
		return relayAbsenceContext{}, errors.New("relay sponsorship absence observation profile is missing")
	}
	return relayAbsenceContext{
		providerAgentID:                  request.ProviderQuote.Body.ProviderAgentID,
		networkDigest:                    networkDigest,
		relayStableActionID:              request.AuthorizedAction.StableActionID,
		relayExactRequestDigest:          request.AuthorizedAction.ExactRequestDigest,
		relayExecutionDigest:             executionDigest,
		sponsorshipStableActionID:        recovery.StableActionID,
		sponsorshipExactRequestDigest:    recovery.ExactRequestDigest,
		sponsorshipValidUntilUnix:        recovery.ValidUntilUnix,
		transactionValidUntilUnix:        request.QuoteRequest.Body.TransactionValidUntilUnix,
		signedTransactionDigest:          request.QuoteRequest.Body.SignedTransactionDigest,
		signedTransactionCellHash:        request.QuoteRequest.Body.SignedTransactionCellHash,
		observationEvidenceProfileURI:    releaseProfile.ProfileURI,
		observationEvidenceProfileDigest: releaseProfile.ProfileDigest,
		sponsorshipTerminalProfile:       *request.ProviderQuote.Body.SponsorshipTerminalProfile,
		relayFinalityProfile:             request.ProviderQuote.Body.RelayFinalityProfile,
		maximumObservedAtUnix:            uint64(nowSeconds) + 5*60,
		outcome:                          outcome,
	}, nil
}

func validateRelayAbsenceObservationSets(sponsorship, transaction []RelayAbsenceObservationReference,
	context relayAbsenceContext) ([]string, error) {
	if err := validateRelayAbsenceOutcomeClass(context.outcome, context.sponsorshipTerminalProfile,
		context.relayFinalityProfile); err != nil {
		return nil, err
	}
	sponsorshipNotBefore, ok := relayAbsenceNotBefore(context.sponsorshipValidUntilUnix,
		context.sponsorshipTerminalProfile.ReorgWindowSeconds)
	if !ok {
		return nil, errors.New("relay sponsorship absence deadline overflows")
	}
	sponsorshipDigests, sponsorshipProofDigests, _, _, err :=
		validateRelayAbsenceObservationSet(sponsorship, AbsenceObservationSponsorshipAction,
			AbsenceConclusionExpiredWithoutInclusion, context, context.sponsorshipTerminalProfile,
			sponsorshipNotBefore)
	if err != nil {
		return nil, err
	}
	transactionProfile := context.sponsorshipTerminalProfile
	if context.relayFinalityProfile != nil {
		transactionProfile = *context.relayFinalityProfile
	}
	transactionNotBefore := uint64(0)
	if transactionConclusion(context.outcome) != AbsenceConclusionInvalidated {
		var ok bool
		transactionNotBefore, ok = relayAbsenceNotBefore(context.transactionValidUntilUnix,
			transactionProfile.ReorgWindowSeconds)
		if !ok {
			return nil, errors.New("relay client-transaction absence deadline overflows")
		}
	}
	transactionDigests, transactionProofDigests, _, _, err :=
		validateRelayAbsenceObservationSet(transaction, AbsenceObservationClientTransaction,
			transactionConclusion(context.outcome), context, transactionProfile, transactionNotBefore)
	if err != nil {
		return nil, err
	}
	for proofDigest := range sponsorshipProofDigests {
		if _, reused := transactionProofDigests[proofDigest]; reused {
			return nil, errors.New("one observer proof was relabelled for both absent side effects")
		}
	}
	merged := mergeSortedDigestSets(sponsorshipDigests, transactionDigests)
	if !sortedOptionalDigests(merged) {
		return nil, errors.New("relay absence observation set is too large")
	}
	return merged, nil
}

func validateRelaySponsorshipAbsenceObservationSet(sponsorship []RelayAbsenceObservationReference,
	context relayAbsenceContext) ([]string, error) {
	sponsorshipNotBefore, ok := relayAbsenceNotBefore(context.sponsorshipValidUntilUnix,
		context.sponsorshipTerminalProfile.ReorgWindowSeconds)
	if !ok {
		return nil, errors.New("relay sponsorship absence deadline overflows")
	}
	digests, _, _, _, err := validateRelayAbsenceObservationSet(sponsorship,
		AbsenceObservationSponsorshipAction, AbsenceConclusionExpiredWithoutInclusion,
		context, context.sponsorshipTerminalProfile, sponsorshipNotBefore)
	return digests, err
}

func validateRelayTransactionAbsenceObservationSet(transaction []RelayAbsenceObservationReference,
	context relayAbsenceContext) ([]string, error) {
	if len(transaction) == 0 {
		return nil, errors.New("relay client-transaction absence threshold is incomplete")
	}
	conclusion := transaction[0].Conclusion
	if conclusion != AbsenceConclusionAbsent && conclusion != AbsenceConclusionExpiredWithoutInclusion &&
		conclusion != AbsenceConclusionInvalidated {
		return nil, errors.New("relay client-transaction absence conclusion is invalid")
	}
	profile := context.sponsorshipTerminalProfile
	if context.relayFinalityProfile != nil {
		profile = *context.relayFinalityProfile
	}
	notBefore := uint64(0)
	if conclusion != AbsenceConclusionInvalidated {
		var ok bool
		notBefore, ok = relayAbsenceNotBefore(context.transactionValidUntilUnix, profile.ReorgWindowSeconds)
		if !ok {
			return nil, errors.New("relay client-transaction absence deadline overflows")
		}
	}
	digests, _, _, _, err := validateRelayAbsenceObservationSet(transaction,
		AbsenceObservationClientTransaction, conclusion, context, profile, notBefore)
	return digests, err
}

// validateRelayAbsenceObservationComponents validates exactly the component
// sets present in a proof. Sponsor-only service has no client transaction, and
// combined service has two legitimate partial terminal quadrants, so requiring
// both arrays here would collapse distinct economic facts into one false
// whole-negative claim.
func validateRelayAbsenceObservationComponents(sponsorship, transaction []RelayAbsenceObservationReference,
	context relayAbsenceContext) ([]string, error) {
	switch {
	case len(sponsorship) != 0 && len(transaction) != 0:
		if !safeTerminalAbsenceOutcome(context.outcome) {
			return nil, errors.New("dual relay absence requires a whole-negative outcome")
		}
		return validateRelayAbsenceObservationSets(sponsorship, transaction, context)
	case len(sponsorship) != 0:
		return validateRelaySponsorshipAbsenceObservationSet(sponsorship, context)
	case len(transaction) != 0:
		return validateRelayTransactionAbsenceObservationSet(transaction, context)
	default:
		return nil, errors.New("relay absence proof has no component observations")
	}
}

func validateRelayAbsenceProofBundleForBody(body RelayFinalityEvidenceBody) error {
	hasSponsorship := len(body.SponsorshipAbsenceObservations) != 0
	hasTransaction := len(body.TransactionAbsenceObservations) != 0
	if !hasSponsorship && !hasTransaction {
		if body.AbsenceProofBundleDigest != "" || len(body.AbsenceProofBundle) != 0 {
			return errors.New("non-absence finality evidence carries an absence proof bundle")
		}
		return nil
	}
	if !digestPattern.MatchString(body.AbsenceProofBundleDigest) || len(body.AbsenceProofBundle) == 0 {
		return errors.New("absence finality evidence lacks its exact proof bundle")
	}
	digest, err := RelayAbsenceProofBundleDigest(body.AbsenceProofBundle)
	if err != nil || digest != body.AbsenceProofBundleDigest {
		return errors.New("absence proof bundle digest is invalid")
	}
	var bundle RelayAbsenceProofBundleV1
	if err := codec.Unmarshal(body.AbsenceProofBundle, &bundle); err != nil {
		return err
	}
	expectedScope := RelayAbsenceProofDual
	if hasSponsorship && !hasTransaction {
		expectedScope = RelayAbsenceProofSponsorshipOnly
	} else if !hasSponsorship && hasTransaction {
		expectedScope = RelayAbsenceProofTransactionOnly
	}
	if bundle.ProofScope != expectedScope ||
		!equalStrings(relayAbsenceObservationReferenceDigests(bundle.SponsorshipAbsenceObservations),
			relayAbsenceObservationReferenceDigests(body.SponsorshipAbsenceObservations)) ||
		!equalStrings(relayAbsenceObservationReferenceDigests(bundle.TransactionAbsenceObservations),
			relayAbsenceObservationReferenceDigests(body.TransactionAbsenceObservations)) {
		return errors.New("absence proof bundle conflicts with its signed finality body")
	}
	return nil
}

// validateRelayAbsenceOutcomeClass prevents a lower-assurance observation set
// from being persisted or signed under a validator-finality outcome label.
// The terminal label is finalized only when every selected predicate is
// validator authenticated; if either selected predicate is corroborated, the
// whole absence result is explicitly corroborated.
func validateRelayAbsenceOutcomeClass(outcome TerminalOutcome, sponsorshipProfile FinalityProfile,
	relayProfile *FinalityProfile) error {
	allValidator := sponsorshipProfile.TerminalEvidenceClass == SponsorshipTerminalValidatorFinality
	if relayProfile != nil {
		allValidator = allValidator &&
			relayProfile.TerminalEvidenceClass == RelayTerminalValidatorFinality
	}
	finalized := outcome == OutcomeFinalizedExpired || outcome == OutcomeFinalizedAbsent ||
		outcome == OutcomeFinalizedInvalidated
	corroborated := outcome == OutcomeCorroboratedExpired || outcome == OutcomeCorroboratedAbsent ||
		outcome == OutcomeCorroboratedInvalidated
	if allValidator && !finalized {
		return errors.New("validator-authenticated absence requires a finalized outcome")
	}
	if !allValidator && !corroborated {
		return errors.New("corroborated absence requires a corroborated outcome")
	}
	return nil
}

func validateRelayAbsenceObservationSet(references []RelayAbsenceObservationReference,
	kind RelayAbsenceObservationKind, conclusion RelayAbsenceConclusion, context relayAbsenceContext,
	profile FinalityProfile, notBeforeUnix uint64) ([]string, map[string]struct{}, string, uint64, error) {
	minimumObservers := int(profile.MinimumObservers)
	minimumDomains := int(profile.MinimumOperatorDomains)
	if conclusion == "" || len(references) < minimumObservers || len(references) > MaxRelayEvidenceRefs {
		return nil, nil, "", 0, errors.New("relay absence observation threshold is incomplete")
	}
	observerIDs := make(map[string]struct{}, len(references))
	operatorDomains := make(map[string]struct{}, len(references))
	proofDigests := make(map[string]struct{}, len(references))
	digests := make([]string, len(references))
	checkpointID := references[0].FinalizedCheckpointID
	checkpointSequence := references[0].FinalizedCheckpointSequence
	checkpointUnix := references[0].FinalizedCheckpointUnix
	for index, reference := range references {
		if err := validateRelayAbsenceObservationReferenceShape(reference); err != nil ||
			reference.ObservationKind != kind || reference.Conclusion != conclusion ||
			reference.ProviderAgentID != context.providerAgentID || reference.NetworkDigest != context.networkDigest ||
			reference.RelayStableActionID != context.relayStableActionID ||
			reference.RelayExactRequestDigest != context.relayExactRequestDigest ||
			reference.RelayExecutionDigest != context.relayExecutionDigest ||
			reference.SponsorshipStableActionID != context.sponsorshipStableActionID ||
			reference.SponsorshipExactRequestDigest != context.sponsorshipExactRequestDigest ||
			reference.SponsorshipValidUntilUnix != context.sponsorshipValidUntilUnix ||
			reference.SignedTransactionDigest != context.signedTransactionDigest ||
			reference.SignedTransactionCellHash != context.signedTransactionCellHash ||
			reference.TerminalProfileURI != profile.ProfileURI ||
			reference.TerminalProfileDigest != profile.ProfileDigest ||
			reference.TerminalEvidenceClass != profile.TerminalEvidenceClass ||
			reference.ObservationEvidenceProfileURI != context.observationEvidenceProfileURI ||
			reference.ObservationEvidenceProfileDigest != context.observationEvidenceProfileDigest ||
			reference.FinalizedCheckpointID != checkpointID ||
			reference.FinalizedCheckpointSequence != checkpointSequence ||
			reference.FinalizedCheckpointUnix != checkpointUnix ||
			context.maximumObservedAtUnix != 0 && reference.ObservedAtUnix > context.maximumObservedAtUnix {
			return nil, nil, "", 0, errors.New("relay absence observation conflicts with the exact action context")
		}
		if _, duplicate := observerIDs[reference.ObserverID]; duplicate {
			return nil, nil, "", 0, errors.New("relay absence observation repeats an observer")
		}
		if _, duplicate := proofDigests[reference.ObservationDigest]; duplicate {
			return nil, nil, "", 0, errors.New("relay absence observation repeats a proof")
		}
		digest, digestErr := RelayAbsenceObservationReferenceDigest(reference)
		if digestErr != nil || index > 0 && digests[index-1] >= digest {
			return nil, nil, "", 0, errors.New("relay absence observations are not in canonical digest order")
		}
		digests[index] = digest
		observerIDs[reference.ObserverID] = struct{}{}
		operatorDomains[reference.OperatorDomainID] = struct{}{}
		proofDigests[reference.ObservationDigest] = struct{}{}
	}
	if checkpointUnix < notBeforeUnix {
		return nil, nil, "", 0, errors.New("relay absence checkpoint predates its side-effect terminal window")
	}
	if len(observerIDs) < minimumObservers || len(operatorDomains) < minimumDomains {
		return nil, nil, "", 0, errors.New("relay absence observation profile threshold is not met")
	}
	return digests, proofDigests, checkpointID, checkpointSequence, nil
}

func relayAbsenceNotBefore(validUntil uint64, reorgWindowSeconds uint32) (uint64, bool) {
	if validUntil == 0 || validUntil > ^uint64(0)-uint64(reorgWindowSeconds) {
		return 0, false
	}
	return validUntil + uint64(reorgWindowSeconds), true
}

func validateRelayAbsenceObservationReferenceShape(reference RelayAbsenceObservationReference) error {
	if reference.SchemaVersion != 1 ||
		(reference.ObservationKind != AbsenceObservationSponsorshipAction &&
			reference.ObservationKind != AbsenceObservationClientTransaction) ||
		(reference.Conclusion != AbsenceConclusionAbsent &&
			reference.Conclusion != AbsenceConclusionExpiredWithoutInclusion &&
			reference.Conclusion != AbsenceConclusionInvalidated) ||
		!identifier(reference.ProviderAgentID, 256) || !digestPattern.MatchString(reference.NetworkDigest) ||
		!digestPattern.MatchString(reference.RelayStableActionID) ||
		!digestPattern.MatchString(reference.RelayExactRequestDigest) ||
		!digestPattern.MatchString(reference.RelayExecutionDigest) ||
		!digestPattern.MatchString(reference.SponsorshipStableActionID) ||
		!digestPattern.MatchString(reference.SponsorshipExactRequestDigest) ||
		reference.SponsorshipValidUntilUnix == 0 ||
		!digestPattern.MatchString(reference.SignedTransactionDigest) ||
		!cellHashPattern.MatchString(reference.SignedTransactionCellHash) ||
		!identifier(reference.TerminalProfileURI, 256) || !digestPattern.MatchString(reference.TerminalProfileDigest) ||
		(reference.TerminalEvidenceClass != RelayTerminalValidatorFinality &&
			reference.TerminalEvidenceClass != RelayTerminalProviderCorroborated &&
			reference.TerminalEvidenceClass != SponsorshipTerminalClientCorroborated) ||
		!identifier(reference.FinalizedCheckpointID, 1024) || reference.FinalizedCheckpointSequence == 0 ||
		reference.FinalizedCheckpointUnix == 0 || reference.ObservedAtUnix > ^uint64(0)-5*60 ||
		reference.FinalizedCheckpointUnix > reference.ObservedAtUnix+5*60 ||
		!identifier(reference.ObserverID, 256) || !identifier(reference.OperatorDomainID, 256) ||
		!identifier(reference.ObservationEvidenceProfileURI, 256) ||
		!digestPattern.MatchString(reference.ObservationEvidenceProfileDigest) ||
		!digestPattern.MatchString(reference.ObservationDigest) || reference.ObservedAtUnix == 0 {
		return errors.New("relay absence observation reference is invalid")
	}
	return nil
}

func transactionConclusion(outcome TerminalOutcome) RelayAbsenceConclusion {
	switch outcome {
	case OutcomeFinalizedAbsent, OutcomeCorroboratedAbsent:
		return AbsenceConclusionAbsent
	case OutcomeFinalizedExpired, OutcomeCorroboratedExpired:
		return AbsenceConclusionExpiredWithoutInclusion
	case OutcomeFinalizedInvalidated, OutcomeCorroboratedInvalidated:
		return AbsenceConclusionInvalidated
	default:
		return ""
	}
}

func relayAbsenceObservationReferenceDigests(references []RelayAbsenceObservationReference) []string {
	digests := make([]string, len(references))
	for index, reference := range references {
		digests[index], _ = RelayAbsenceObservationReferenceDigest(reference)
	}
	return digests
}

func sortRelayAbsenceObservationReferences(references []RelayAbsenceObservationReference) {
	sort.Slice(references, func(left, right int) bool {
		leftDigest, _ := RelayAbsenceObservationReferenceDigest(references[left])
		rightDigest, _ := RelayAbsenceObservationReferenceDigest(references[right])
		return leftDigest < rightDigest
	})
}
