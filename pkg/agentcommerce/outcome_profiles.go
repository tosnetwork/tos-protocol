package agentcommerce

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const (
	OutcomeProfileStateTransition           = "tos.outcome.state-transition.v1"
	OutcomeProfileTerminal                  = "tos.outcome.terminal-disposition.v1"
	OutcomeProfileCost                      = "tos.outcome.cost.v1"
	OutcomeProfileCohortCheckpoint          = "tos.outcome.cohort-checkpoint.v1"
	OutcomeProfileObligationState           = "tos.outcome.obligation-state.v1"
	OutcomeProfileActionResolutionReference = "tos.outcome.action-resolution-reference.v1"
	OutcomeProfileEvidenceAvailability      = "tos.outcome.evidence-availability.v1"
	OutcomeProfileGateExecution             = "tos.outcome.gate-execution.v1"
	OutcomeProfileCarrierReceipt            = "tos.outcome.carrier-receipt.v1"
	OutcomeProfileTransferGift              = "tos.outcome.transfer.gift.v1"
	OutcomeProfileTransferAgreementPayment  = "tos.outcome.transfer.agreement-payment.v1"
	OutcomeProfileTransferTOSEscrow         = "tos.outcome.transfer.tos-escrow.v1"
	OutcomeProfileEconomicPerimeter         = "tos.outcome.economic-perimeter.v1"
	OutcomeProfileRevenueRecognition        = "tos.outcome.revenue-recognition.v1"
	OutcomeProfileAssetConversion           = "tos.outcome.asset-conversion.v1"
	OutcomeProfileForecast                  = "tos.outcome.forecast.v1"
	OutcomeProfileCensoring                 = "tos.outcome.censoring.v1"
	OutcomeProfileEconomicLedger            = "tos.outcome.economic-ledger.v1"
	OutcomeProfileCalibrationReport         = "tos.outcome.calibration-report.v1"
	OutcomeProfileFinancialReport           = "tos.outcome.financial-report.v1"
	OutcomeProfileLearningDataset           = "tos.outcome.learning-dataset.v1"
	OutcomeProfileSkillPromotion            = "tos.outcome.skill-promotion.v1"
)

type ActionResolutionReferencePayloadV1 struct {
	StableActionID          string                `json:"stable_action_id"`
	ExactRequestDigest      string                `json:"exact_request_digest"`
	AuthorizedActionDigest  string                `json:"authorized_action_digest"`
	ActionResolutionDigest  string                `json:"action_resolution_digest"`
	ResolutionState         ActionResolutionState `json:"resolution_state"`
	ResolutionStateRevision uint64                `json:"resolution_state_revision"`
}

// VerifyOperationOutcomeAuthorityV1 upgrades structurally verified artifacts
// to an authority-qualified assertion. It accepts only caller-supplied exact
// proof objects, rejects unreferenced/partial unions, and performs no I/O.
func VerifyOperationOutcomeAuthorityV1(body OperationOutcomeEventBodyV1, manifest OutcomeEvidenceManifestV1,
	materials []OutcomeAuthorityProofMaterialV1, verifier OutcomeEvidenceAuthorityVerifierV1,
	now time.Time) (OutcomeAuthorityAssessmentV1, error) {
	profile, known := outcomeAssertionProfilesV1[body.AssertionProfileURI]
	if !known || profile.EventKind != body.EventKind || now.IsZero() {
		return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority assessment inputs are invalid")
	}
	// A reference-only assertion deliberately carries no qualified source fact.
	if len(profile.RequiredEvidenceRoles) == 0 {
		if len(manifest.AuthorityProofRefs) != 0 || len(manifest.EvidenceItems) != 0 || len(materials) != 0 {
			return OutcomeAuthorityAssessmentV1{}, errors.New("unqualified outcome profile cannot carry authority material")
		}
		return OutcomeAuthorityAssessmentV1{VerifiedEvidenceDigests: []string{}}, nil
	}
	if verifier == nil || len(materials) != len(manifest.AuthorityProofRefs) {
		return OutcomeAuthorityAssessmentV1{}, errors.New("complete outcome authority material is required")
	}
	refs := make(map[string]OutcomeAuthorityProofRefV1, len(manifest.AuthorityProofRefs))
	for _, ref := range manifest.AuthorityProofRefs {
		refs[ref.ObjectDigest] = ref
	}
	objects := make(map[string]OutcomeAuthorityProofMaterialV1, len(materials))
	for _, material := range materials {
		digest, err := OutcomeAuthorityProofObjectDigestV1(material)
		ref, found := refs[digest]
		if err != nil || !found || ref.ProofProfileURI != material.ProofProfileURI || ref.CanonicalSize != uint64(len(material.CanonicalObject)) {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority proof object binding is invalid")
		}
		if _, duplicate := objects[digest]; duplicate {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority proof object is duplicated")
		}
		objects[digest] = material
	}
	used := make(map[string]bool, len(objects))
	verifiedEvidence := make([]string, 0, len(manifest.EvidenceItems))
	var highWater uint64
	for _, item := range manifest.EvidenceItems {
		timeMaterial, timeFound := objects[item.AuthorityTimeProofDigest]
		qualificationMaterial, qualificationFound := objects[item.IssuerQualificationProofDigest]
		if !timeFound || !qualificationFound || timeMaterial.ProofProfileURI != OutcomeAuthorityTimeProofProfileV1 ||
			qualificationMaterial.ProofProfileURI != OutcomeIssuerQualificationProofProfileV1 {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome evidence authority proof profiles are invalid")
		}
		var authorityTime AuthorityTimeProofV1
		var qualification IssuerQualificationProofV1
		if codec.Unmarshal(timeMaterial.CanonicalObject, &authorityTime) != nil || ValidateAuthorityTimeProofV1(authorityTime) != nil ||
			codec.Unmarshal(qualificationMaterial.CanonicalObject, &qualification) != nil || ValidateIssuerQualificationProofV1(qualification) != nil {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority proof object is malformed")
		}
		if qualification.AuthorityTimeProofDigest != item.AuthorityTimeProofDigest ||
			qualification.ScopeProfileURI != item.EvidenceProfileURI ||
			authorityTime.IntervalEndUnix > uint64(now.UTC().Unix()) ||
			item.ClaimedObservationTimeUnix < authorityTime.IntervalStartUnix || item.ClaimedObservationTimeUnix > authorityTime.IntervalEndUnix ||
			authorityTime.IntervalEndUnix < qualification.ValidFromUnix || authorityTime.IntervalEndUnix >= qualification.ValidUntilUnix {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority time or qualification binding is invalid")
		}
		if err := verifier.VerifyOutcomeAuthorityTime(authorityTime, item, now.UTC()); err != nil {
			return OutcomeAuthorityAssessmentV1{}, fmt.Errorf("outcome authority time verification failed: %w", err)
		}
		if err := verifier.VerifyOutcomeIssuerQualification(qualification, item, authorityTime, now.UTC()); err != nil {
			return OutcomeAuthorityAssessmentV1{}, fmt.Errorf("outcome issuer qualification verification failed: %w", err)
		}
		used[item.AuthorityTimeProofDigest] = true
		used[item.IssuerQualificationProofDigest] = true
		verifiedEvidence = append(verifiedEvidence, item.ObjectDigest)
		if authorityTime.FinalizedHighWater > highWater {
			highWater = authorityTime.FinalizedHighWater
		}
	}
	for digest := range objects {
		if !used[digest] {
			return OutcomeAuthorityAssessmentV1{}, errors.New("outcome authority proof object is unreferenced")
		}
	}
	sort.Strings(verifiedEvidence)
	return OutcomeAuthorityAssessmentV1{AuthorityQualified: true, VerifiedEvidenceDigests: verifiedEvidence,
		AuthorityTimeHighWater: highWater}, nil
}

type OutcomeAssertionProfileV1 struct {
	ProfileURI            string                    `json:"profile_uri"`
	EventKind             OperationOutcomeEventKind `json:"event_kind"`
	RequiredEvidenceRoles []string                  `json:"required_evidence_roles"`
	OptionalEvidenceRoles []string                  `json:"optional_evidence_roles"`
	MaximumEvidenceItems  uint16                    `json:"maximum_evidence_items"`
}

var outcomeAssertionProfilesV1 = map[string]OutcomeAssertionProfileV1{
	OutcomeProfileStateTransition:           {ProfileURI: OutcomeProfileStateTransition, EventKind: OutcomeTransitionObservation, RequiredEvidenceRoles: []string{"source_resolution"}, MaximumEvidenceItems: 16},
	OutcomeProfileTerminal:                  {ProfileURI: OutcomeProfileTerminal, EventKind: OutcomeTerminalObservation, RequiredEvidenceRoles: []string{"authoritative_resolution"}, MaximumEvidenceItems: 16},
	OutcomeProfileCost:                      {ProfileURI: OutcomeProfileCost, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"cost_source"}, MaximumEvidenceItems: 16},
	OutcomeProfileCohortCheckpoint:          {ProfileURI: OutcomeProfileCohortCheckpoint, EventKind: OutcomeCohortCheckpoint, RequiredEvidenceRoles: []string{"admission_checkpoint"}, MaximumEvidenceItems: 16},
	OutcomeProfileObligationState:           {ProfileURI: OutcomeProfileObligationState, EventKind: OutcomeTransitionObservation, RequiredEvidenceRoles: []string{"billing_resolution"}, MaximumEvidenceItems: 16},
	OutcomeProfileActionResolutionReference: {ProfileURI: OutcomeProfileActionResolutionReference, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{}, MaximumEvidenceItems: 0},
	OutcomeProfileEvidenceAvailability:      {ProfileURI: OutcomeProfileEvidenceAvailability, EventKind: OutcomeAvailabilityObservation, RequiredEvidenceRoles: []string{"custodian_resolution"}, MaximumEvidenceItems: 8},
	OutcomeProfileGateExecution:             {ProfileURI: OutcomeProfileGateExecution, EventKind: OutcomeTransitionObservation, RequiredEvidenceRoles: []string{"authoritative_resolution"}, MaximumEvidenceItems: 16},
	OutcomeProfileCarrierReceipt:            {ProfileURI: OutcomeProfileCarrierReceipt, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"carrier_receipt"}, MaximumEvidenceItems: 8},
	OutcomeProfileTransferGift:              {ProfileURI: OutcomeProfileTransferGift, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"finalized_transfer"}, MaximumEvidenceItems: 16},
	OutcomeProfileTransferAgreementPayment:  {ProfileURI: OutcomeProfileTransferAgreementPayment, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"finalized_transfer"}, MaximumEvidenceItems: 16},
	OutcomeProfileTransferTOSEscrow:         {ProfileURI: OutcomeProfileTransferTOSEscrow, EventKind: OutcomeTransitionObservation, RequiredEvidenceRoles: []string{"escrow_state", "authority_finality"}, OptionalEvidenceRoles: []string{"transaction_bytes"}, MaximumEvidenceItems: 8},
	OutcomeProfileEconomicPerimeter:         {ProfileURI: OutcomeProfileEconomicPerimeter, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"perimeter_authority"}, MaximumEvidenceItems: 16},
	OutcomeProfileRevenueRecognition:        {ProfileURI: OutcomeProfileRevenueRecognition, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"accounting_authority"}, MaximumEvidenceItems: 16},
	OutcomeProfileAssetConversion:           {ProfileURI: OutcomeProfileAssetConversion, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"price_evidence"}, MaximumEvidenceItems: 16},
	OutcomeProfileForecast:                  {ProfileURI: OutcomeProfileForecast, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"forecast_authority"}, MaximumEvidenceItems: 8},
	OutcomeProfileCensoring:                 {ProfileURI: OutcomeProfileCensoring, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"admission_checkpoint"}, MaximumEvidenceItems: 8},
	OutcomeProfileEconomicLedger:            {ProfileURI: OutcomeProfileEconomicLedger, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"accounting_authority"}, MaximumEvidenceItems: 16},
	OutcomeProfileCalibrationReport:         {ProfileURI: OutcomeProfileCalibrationReport, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"cohort_checkpoint"}, MaximumEvidenceItems: 16},
	OutcomeProfileFinancialReport:           {ProfileURI: OutcomeProfileFinancialReport, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"accounting_authority"}, MaximumEvidenceItems: 16},
	OutcomeProfileLearningDataset:           {ProfileURI: OutcomeProfileLearningDataset, EventKind: OutcomeCohortCheckpoint, RequiredEvidenceRoles: []string{"admission_checkpoint"}, MaximumEvidenceItems: 16},
	OutcomeProfileSkillPromotion:            {ProfileURI: OutcomeProfileSkillPromotion, EventKind: OutcomeObservation, RequiredEvidenceRoles: []string{"owner_approval", "evaluation_report"}, MaximumEvidenceItems: 8},
}

func OutcomeAssertionProfileRegistryV1() map[string]OutcomeAssertionProfileV1 {
	result := make(map[string]OutcomeAssertionProfileV1, len(outcomeAssertionProfilesV1))
	for key, value := range outcomeAssertionProfilesV1 {
		value.RequiredEvidenceRoles = append([]string{}, value.RequiredEvidenceRoles...)
		value.OptionalEvidenceRoles = append([]string{}, value.OptionalEvidenceRoles...)
		result[key] = value
	}
	return result
}

// VerifyOperationOutcomeArtifactsV1 validates every content-addressed object
// committed by the event. Unknown assertion profiles fail closed at this
// authority-aware boundary while the generic decoder can still retain them.
func VerifyOperationOutcomeArtifactsV1(body OperationOutcomeEventBodyV1, assertionPayload []byte,
	manifest OutcomeEvidenceManifestV1, extensions OutcomeExtensionSetV1) error {
	if err := ValidateOperationOutcomeEventBodyV1(body); err != nil {
		return err
	}
	profile, known := outcomeAssertionProfilesV1[body.AssertionProfileURI]
	if !known || profile.EventKind != body.EventKind {
		return errors.New("outcome assertion profile is unknown or incompatible with the event kind")
	}
	assertionDigest, err := OutcomeAssertionPayloadDigestV1(body.AssertionProfileURI, assertionPayload)
	if err != nil || assertionDigest != body.AssertionPayloadDigest || uint64(len(assertionPayload)) != body.AssertionPayloadSize {
		return errors.New("outcome assertion payload binding is invalid")
	}
	manifestDigest, err := OutcomeEvidenceManifestDigestV1(manifest)
	if err != nil || manifestDigest != body.EvidenceManifestDigest || len(manifest.EvidenceItems) > int(profile.MaximumEvidenceItems) {
		return errors.New("outcome evidence manifest binding is invalid")
	}
	extensionDigest, err := OutcomeExtensionSetDigestV1(extensions)
	if err != nil || extensionDigest != body.ExtensionSetDigest {
		return errors.New("outcome extension set binding is invalid")
	}
	if err := verifyOutcomeEvidenceProofBindings(manifest); err != nil {
		return err
	}
	for _, role := range profile.RequiredEvidenceRoles {
		count := 0
		for _, item := range manifest.EvidenceItems {
			if item.EvidenceRole == role {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("outcome assertion requires exactly one %s evidence item", role)
		}
	}
	roleCounts := make(map[string]int)
	for _, item := range manifest.EvidenceItems {
		allowed := false
		for _, role := range append(append([]string(nil), profile.RequiredEvidenceRoles...), profile.OptionalEvidenceRoles...) {
			if item.EvidenceRole == role {
				allowed = true
				break
			}
		}
		roleCounts[item.EvidenceRole]++
		if !allowed || roleCounts[item.EvidenceRole] > 1 {
			return errors.New("outcome assertion evidence role is unsupported or duplicated")
		}
	}
	switch body.AssertionProfileURI {
	case OutcomeProfileStateTransition:
		var value StateTransitionPayloadV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("state transition payload is invalid")
		}
		return ValidateStateTransitionPayloadV1(value)
	case OutcomeProfileTerminal:
		var value TerminalDispositionV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("terminal disposition payload is invalid")
		}
		return ValidateTerminalDispositionV1(value)
	case OutcomeProfileCost:
		var value CostObservationPayloadV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("cost observation payload is invalid")
		}
		return ValidateCostObservationPayloadV1(value)
	case OutcomeProfileCohortCheckpoint:
		var value CohortCheckpointPayloadV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("cohort checkpoint payload is invalid")
		}
		return ValidateCohortCheckpointPayloadV1(value)
	case OutcomeProfileObligationState:
		var value AgreementObligationStateObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("obligation state payload is invalid")
		}
		return ValidateAgreementObligationStateObservationV1(value)
	case OutcomeProfileActionResolutionReference:
		var value ActionResolutionReferencePayloadV1
		if codec.Unmarshal(assertionPayload, &value) != nil || !digest32(value.StableActionID) || !digest32(value.ExactRequestDigest) ||
			!digest32(value.AuthorizedActionDigest) || !digest32(value.ActionResolutionDigest) || !validActionResolutionState(value.ResolutionState) || value.ResolutionStateRevision == 0 {
			return errors.New("Action resolution reference payload is invalid")
		}
		return nil
	case OutcomeProfileEvidenceAvailability:
		var value EvidenceAvailabilityObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("evidence availability payload is invalid")
		}
		return ValidateEvidenceAvailabilityObservationV1(value)
	case OutcomeProfileGateExecution:
		var value GateExecutionObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("Gate execution payload is invalid")
		}
		return ValidateGateExecutionObservationV1(value)
	case OutcomeProfileCarrierReceipt:
		var value CarrierReceiptObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("Carrier receipt payload is invalid")
		}
		return ValidateCarrierReceiptObservationV1(value)
	case OutcomeProfileTransferGift, OutcomeProfileTransferAgreementPayment:
		var value TransferObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil ||
			body.AssertionProfileURI == OutcomeProfileTransferGift && value.TransferClass != "gift" ||
			body.AssertionProfileURI == OutcomeProfileTransferAgreementPayment && value.TransferClass != "agreement_bound" {
			return errors.New("transfer observation payload does not match its profile")
		}
		return ValidateTransferObservationV1(value)
	case OutcomeProfileTransferTOSEscrow:
		var value TOSEscrowObservationV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("TOS escrow observation payload is invalid")
		}
		return ValidateTOSEscrowObservationV1(value)
	case OutcomeProfileEconomicPerimeter:
		var value EconomicPerimeterV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("economic perimeter payload is invalid")
		}
		return ValidateEconomicPerimeterV1(value)
	case OutcomeProfileRevenueRecognition:
		var value RevenueRecognitionV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("revenue recognition payload is invalid")
		}
		return ValidateRevenueRecognitionV1(value)
	case OutcomeProfileAssetConversion:
		var value AssetConversionEvidenceV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("asset conversion payload is invalid")
		}
		return ValidateAssetConversionEvidenceV1(value)
	case OutcomeProfileForecast:
		var value OutcomeForecastV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("outcome forecast payload is invalid")
		}
		return ValidateOutcomeForecastV1(value)
	case OutcomeProfileCensoring:
		var value OutcomeCensoringV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("outcome censoring payload is invalid")
		}
		return ValidateOutcomeCensoringV1(value)
	case OutcomeProfileEconomicLedger:
		var value []EconomicLedgerEntryV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("economic ledger payload is invalid")
		}
		return ValidateEconomicLedgerEntriesV1(value)
	case OutcomeProfileCalibrationReport:
		var value CalibrationReportV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("calibration report payload is invalid")
		}
		return ValidateCalibrationReportV1(value)
	case OutcomeProfileFinancialReport:
		var value FinancialReportV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("financial report payload is invalid")
		}
		return ValidateFinancialReportV1(value)
	case OutcomeProfileLearningDataset:
		var value LearningDatasetManifestV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("learning dataset manifest payload is invalid")
		}
		return ValidateLearningDatasetManifestV1(value)
	case OutcomeProfileSkillPromotion:
		var value SkillPromotionDecisionV1
		if codec.Unmarshal(assertionPayload, &value) != nil {
			return errors.New("Skill promotion decision payload is invalid")
		}
		return ValidateSkillPromotionDecisionV1(value)
	default:
		return errors.New("outcome assertion profile has no released verifier")
	}
}

func VerifyOperationOutcomeArtifactBundleV1(body OperationOutcomeEventBodyV1,
	bundle OperationOutcomeArtifactBundleV1) error {
	if err := VerifyOperationOutcomeArtifactsV1(body, bundle.AssertionPayload, bundle.EvidenceManifest, bundle.ExtensionSet); err != nil {
		return err
	}
	if len(bundle.AuthorityProofs) != len(bundle.EvidenceManifest.AuthorityProofRefs) {
		return errors.New("outcome artifact bundle authority proof cardinality mismatch")
	}
	if err := validateCanonicalOutcomeSlice(bundle.AuthorityProofs, func(material OutcomeAuthorityProofMaterialV1) error {
		_, err := OutcomeAuthorityProofObjectDigestV1(material)
		return err
	}); err != nil {
		return errors.New("outcome artifact bundle authority material is not canonical")
	}
	digests := make(map[string]struct{}, len(bundle.AuthorityProofs))
	for _, material := range bundle.AuthorityProofs {
		digest, err := OutcomeAuthorityProofObjectDigestV1(material)
		if err != nil {
			return err
		}
		if _, duplicate := digests[digest]; duplicate {
			return errors.New("outcome artifact bundle contains duplicate authority material")
		}
		digests[digest] = struct{}{}
	}
	for _, ref := range bundle.EvidenceManifest.AuthorityProofRefs {
		if _, found := digests[ref.ObjectDigest]; !found {
			return errors.New("outcome artifact bundle omits referenced authority material")
		}
	}
	return nil
}

func verifyOutcomeEvidenceProofBindings(manifest OutcomeEvidenceManifestV1) error {
	proofs := make(map[string]struct{}, len(manifest.AuthorityProofRefs))
	for _, ref := range manifest.AuthorityProofRefs {
		proofs[ref.ObjectDigest] = struct{}{}
	}
	for _, item := range manifest.EvidenceItems {
		if _, ok := proofs[item.AuthorityTimeProofDigest]; !ok {
			return errors.New("evidence authority-time proof is absent from the manifest")
		}
		if _, ok := proofs[item.IssuerQualificationProofDigest]; !ok {
			return errors.New("evidence issuer qualification proof is absent from the manifest")
		}
	}
	return nil
}
