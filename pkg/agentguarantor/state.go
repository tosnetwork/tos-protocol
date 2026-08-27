package agentguarantor

import "errors"

type OfferStatus string

const (
	OfferRequested           OfferStatus = "requested"
	OfferAllocated           OfferStatus = "allocated"
	OfferReservedUnsigned    OfferStatus = "reserved_unsigned"
	OfferAbortResolving      OfferStatus = "abort_resolving"
	OfferAbortedReleased     OfferStatus = "aborted_released"
	OfferIssued              OfferStatus = "issued"
	OfferAcceptanceResolving OfferStatus = "acceptance_resolving"
	OfferAccepted            OfferStatus = "accepted"
	OfferExpiryResolving     OfferStatus = "expiry_resolving"
	OfferExpired             OfferStatus = "expired"
	OfferReleaseResolving    OfferStatus = "release_resolving"
	OfferReleased            OfferStatus = "released"
	OfferAmbiguous           OfferStatus = "ambiguous"
)

type OfferRecord struct {
	OfferID            string      `json:"offer_id"`
	ReservationID      string      `json:"reservation_id,omitempty"`
	AgreementDigest    string      `json:"agreement_digest,omitempty"`
	Status             OfferStatus `json:"status"`
	StateRevision      uint64      `json:"state_revision"`
	LastEvidenceDigest string      `json:"last_evidence_digest,omitempty"`
}

func TransitionOffer(current OfferRecord, expectedRevision uint64, target OfferStatus, evidenceDigest string) (OfferRecord, error) {
	if !validID(current.OfferID) || current.StateRevision == 0 || current.StateRevision != expectedRevision ||
		!validDigest(evidenceDigest) || !allowedOfferTransition(current.Status, target) {
		return OfferRecord{}, errors.New("offer transition is invalid or stale")
	}
	updated := current
	updated.Status = target
	updated.StateRevision++
	return updated, nil
}

// AcceptIssuedOffer is the serializable acceptance-vs-expiry CAS. Resolving is
// a recovery projection for ambiguous multi-step adapters; a successful local
// authority transaction advances ISSUED directly to ACCEPTED once.
func AcceptIssuedOffer(current OfferRecord, expectedRevision uint64, evidenceDigest string) (OfferRecord, error) {
	if !validID(current.OfferID) || current.Status != OfferIssued || current.StateRevision != expectedRevision ||
		!validDigest(evidenceDigest) {
		return OfferRecord{}, errors.New("offer acceptance CAS is invalid or stale")
	}
	updated := current
	updated.Status = OfferAccepted
	updated.StateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

// ExpireIssuedOffer is the acceptance-vs-expiry loser of the same serializable
// offer revision. The caller must independently prove the signed cutoff and
// admission drain before invoking it.
func ExpireIssuedOffer(current OfferRecord, expectedRevision uint64, evidenceDigest string) (OfferRecord, error) {
	if !validID(current.OfferID) || current.Status != OfferIssued || current.StateRevision != expectedRevision ||
		!validDigest(evidenceDigest) {
		return OfferRecord{}, errors.New("offer expiry CAS is invalid or stale")
	}
	updated := current
	updated.Status = OfferExpired
	updated.StateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func ReleaseExpiredOffer(current OfferRecord, expectedRevision uint64, evidenceDigest string) (OfferRecord, error) {
	if !validID(current.OfferID) || current.Status != OfferExpired || current.StateRevision != expectedRevision ||
		!validDigest(evidenceDigest) {
		return OfferRecord{}, errors.New("offer release CAS is invalid or stale")
	}
	updated := current
	updated.Status = OfferReleased
	updated.StateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func allowedOfferTransition(from, to OfferStatus) bool {
	switch from {
	case OfferRequested:
		return to == OfferAllocated
	case OfferAllocated:
		return to == OfferReservedUnsigned
	case OfferReservedUnsigned:
		return to == OfferIssued || to == OfferAbortResolving
	case OfferAbortResolving:
		return to == OfferAbortedReleased
	case OfferIssued:
		return to == OfferAcceptanceResolving || to == OfferExpiryResolving
	case OfferAcceptanceResolving:
		return to == OfferAccepted || to == OfferExpiryResolving || to == OfferAmbiguous
	case OfferExpiryResolving:
		return to == OfferExpired || to == OfferAccepted || to == OfferAmbiguous
	case OfferExpired:
		return to == OfferReleaseResolving
	case OfferReleaseResolving:
		return to == OfferReleased || to == OfferAmbiguous
	default:
		return false
	}
}

type CoverageStatus string

const (
	CoveragePendingAuthorization  CoverageStatus = "pending_authorization"
	CoveragePendingPrerequisites  CoverageStatus = "pending_prerequisites"
	CoverageActivationResolving   CoverageStatus = "activation_resolving"
	CoverageActive                CoverageStatus = "active"
	CoverageNotActivatedConfirmed CoverageStatus = "not_activated_confirmed"
	CoverageCancellationResolving CoverageStatus = "cancellation_resolving"
	CoverageEnded                 CoverageStatus = "coverage_ended"
	CoverageReleasePending        CoverageStatus = "release_pending"
	CoverageClosed                CoverageStatus = "closed"
	CoverageCancelled             CoverageStatus = "cancelled"
	CoverageExhausted             CoverageStatus = "exhausted"
	CoverageDefaulted             CoverageStatus = "defaulted"
	CoverageClosedNotActivated    CoverageStatus = "closed_not_activated"
	CoverageAmbiguous             CoverageStatus = "ambiguous"
)

type ClaimFilingStatus string

const (
	FilingUninitialized  ClaimFilingStatus = "uninitialized"
	FilingNotOpen        ClaimFilingStatus = "not_open"
	FilingOpen           ClaimFilingStatus = "open"
	FilingCloseResolving ClaimFilingStatus = "close_resolving"
	FilingClosePending   ClaimFilingStatus = "filing_close_pending"
	FilingFrozen         ClaimFilingStatus = "frozen"
	FilingResolved       ClaimFilingStatus = "resolved"
)

type AdapterEvidenceStatus string

const (
	AdapterEvidenceCurrent         AdapterEvidenceStatus = "current"
	AdapterEvidenceUnknown         AdapterEvidenceStatus = "evidence_unknown"
	AdapterEvidenceImpaired        AdapterEvidenceStatus = "impaired"
	AdapterEvidenceTerminalDefault AdapterEvidenceStatus = "terminal_default"
)

type CoverageRecord struct {
	CoverageAgreementBodyDigest   string                `json:"coverage_agreement_body_digest"`
	CoverageObligationID          string                `json:"coverage_obligation_id"`
	ReservationID                 string                `json:"reservation_id"`
	CoverageStatus                CoverageStatus        `json:"coverage_status"`
	ClaimFilingStatus             ClaimFilingStatus     `json:"claim_filing_status"`
	AdapterEvidenceStatus         AdapterEvidenceStatus `json:"adapter_evidence_status"`
	CoverageRevision              uint64                `json:"coverage_revision"`
	FilingStateRevision           uint64                `json:"filing_state_revision"`
	ClaimAdmissionHighWater       uint64                `json:"claim_admission_high_water,omitempty"`
	ClaimAdmissionLogRoot         string                `json:"claim_admission_log_root,omitempty"`
	IncidentEligibilityEndsAtUnix uint64                `json:"incident_eligibility_ends_at_unix,omitempty"`
	CoverageEndReason             string                `json:"coverage_end_reason,omitempty"`
	CoverageEndEvidenceDigest     string                `json:"coverage_end_evidence_digest,omitempty"`
	LastEvidenceDigest            string                `json:"last_evidence_digest"`
}

func ApplyCoverageCancellation(current CoverageRecord, expectedCoverageRevision uint64, effectiveAtUnix uint64,
	evidenceDigest string) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageStatus != CoverageActive ||
		current.CoverageRevision != expectedCoverageRevision || effectiveAtUnix == 0 || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("coverage cancellation CAS is invalid or stale")
	}
	updated := current
	updated.CoverageStatus = CoverageEnded
	updated.CoverageRevision++
	updated.IncidentEligibilityEndsAtUnix = effectiveAtUnix
	updated.CoverageEndReason = "accepted_cancellation"
	updated.CoverageEndEvidenceDigest = evidenceDigest
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

// AdmitClaimRevision advances the shared coverage CAS for either a new claim
// or one predecessor-linked revision. Claim admission races cancellation and
// filing close in this domain; keeping the revision and append-only claim root
// in the same record prevents either operation from being accepted against a
// stale view.
func AdmitClaimRevision(current CoverageRecord, expectedCoverageRevision, resultingHighWater uint64,
	resultingLogRoot, evidenceDigest string, initial bool) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageRevision != expectedCoverageRevision ||
		!validDigest(resultingLogRoot) || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("claim admission coverage CAS is invalid or stale")
	}
	if initial {
		if current.CoverageStatus != CoverageActive || current.ClaimFilingStatus != FilingOpen ||
			resultingHighWater != current.ClaimAdmissionHighWater+1 {
			return CoverageRecord{}, errors.New("initial claim admission is not permitted")
		}
	} else if (current.CoverageStatus != CoverageActive && current.CoverageStatus != CoverageEnded) ||
		(current.ClaimFilingStatus != FilingOpen && current.ClaimFilingStatus != FilingFrozen) ||
		resultingHighWater != current.ClaimAdmissionHighWater {
		return CoverageRecord{}, errors.New("claim revision admission is not permitted")
	}
	updated := current
	updated.CoverageRevision++
	updated.ClaimAdmissionHighWater = resultingHighWater
	updated.ClaimAdmissionLogRoot = resultingLogRoot
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func NewAcceptedCoverageRecord(agreementDigest, obligationID, reservationID, evidenceDigest string) (CoverageRecord, error) {
	if !validDigest(agreementDigest) || !validToken(obligationID, 128) || !validDigest(reservationID) || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("accepted coverage genesis is invalid")
	}
	return CoverageRecord{CoverageAgreementBodyDigest: agreementDigest, CoverageObligationID: obligationID,
		ReservationID: reservationID, CoverageStatus: CoveragePendingAuthorization, ClaimFilingStatus: FilingNotOpen,
		AdapterEvidenceStatus: AdapterEvidenceCurrent, CoverageRevision: 1, FilingStateRevision: 1,
		LastEvidenceDigest: evidenceDigest}, nil
}

func TransitionCoverage(current CoverageRecord, expectedRevision uint64, target CoverageStatus, evidenceDigest string) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageRevision != expectedRevision || !validDigest(evidenceDigest) ||
		!allowedCoverageTransition(current.CoverageStatus, target) {
		return CoverageRecord{}, errors.New("coverage transition is invalid or stale")
	}
	if target == CoverageReleasePending && current.ClaimFilingStatus != FilingFrozen && current.ClaimFilingStatus != FilingResolved {
		return CoverageRecord{}, errors.New("coverage cannot release before the filing cut is frozen")
	}
	updated := current
	updated.CoverageStatus = target
	updated.CoverageRevision++
	updated.LastEvidenceDigest = evidenceDigest
	if target == CoverageActive && updated.ClaimFilingStatus == FilingNotOpen {
		updated.ClaimFilingStatus = FilingOpen
		updated.FilingStateRevision++
	}
	return updated, nil
}

// ActivateAcceptedCoverage is the single-CAS activation transition. Adapter
// implementations must not persist the intermediate resolving states one by
// one: a crash between them could otherwise create a half-active coverage.
func ActivateAcceptedCoverage(current CoverageRecord, expectedCoverageRevision, expectedFilingRevision uint64,
	evidenceDigest string) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageStatus != CoveragePendingAuthorization ||
		current.ClaimFilingStatus != FilingNotOpen || current.CoverageRevision != expectedCoverageRevision ||
		current.FilingStateRevision != expectedFilingRevision || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("coverage activation CAS is invalid or stale")
	}
	updated := current
	updated.CoverageStatus = CoverageActive
	updated.ClaimFilingStatus = FilingOpen
	updated.CoverageRevision++
	updated.FilingStateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

// ConfirmCoverageNonActivation is the mutually exclusive loser of activation.
// It preserves the NOT_OPEN filing state and its revision byte-for-byte.
func ConfirmCoverageNonActivation(current CoverageRecord, expectedCoverageRevision, expectedFilingRevision uint64,
	evidenceDigest string) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageStatus != CoveragePendingAuthorization ||
		current.ClaimFilingStatus != FilingNotOpen || current.CoverageRevision != expectedCoverageRevision ||
		current.FilingStateRevision != expectedFilingRevision || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("coverage non-activation CAS is invalid or stale")
	}
	updated := current
	updated.CoverageStatus = CoverageNotActivatedConfirmed
	updated.CoverageRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func allowedCoverageTransition(from, to CoverageStatus) bool {
	switch from {
	case CoveragePendingAuthorization:
		return to == CoveragePendingPrerequisites
	case CoveragePendingPrerequisites:
		return to == CoverageActivationResolving
	case CoverageActivationResolving:
		return to == CoverageActive || to == CoverageNotActivatedConfirmed || to == CoverageAmbiguous
	case CoverageActive:
		return to == CoverageCancellationResolving || to == CoverageReleasePending
	case CoverageCancellationResolving:
		return to == CoverageEnded || to == CoverageAmbiguous
	case CoverageEnded, CoverageNotActivatedConfirmed:
		return to == CoverageReleasePending
	case CoverageReleasePending:
		return to == CoverageClosed || to == CoverageCancelled || to == CoverageExhausted || to == CoverageDefaulted ||
			to == CoverageClosedNotActivated || to == CoverageAmbiguous
	default:
		return false
	}
}

func FreezeClaimFiling(current CoverageRecord, expectedCoverageRevision, expectedFilingRevision, highWater uint64,
	logRoot, evidenceDigest string, neverActivated bool) (CoverageRecord, error) {
	if !validCoverageRecord(current) || current.CoverageRevision != expectedCoverageRevision ||
		current.FilingStateRevision != expectedFilingRevision || !validDigest(logRoot) || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("claim filing close is invalid or stale")
	}
	if neverActivated {
		if current.CoverageStatus != CoverageNotActivatedConfirmed || current.ClaimFilingStatus != FilingNotOpen || highWater != 0 {
			return CoverageRecord{}, errors.New("never-activated filing close has invalid state")
		}
	} else if current.ClaimFilingStatus != FilingOpen && current.ClaimFilingStatus != FilingCloseResolving {
		return CoverageRecord{}, errors.New("active filing close has invalid state")
	}
	updated := current
	updated.ClaimFilingStatus = FilingFrozen
	updated.ClaimAdmissionHighWater = highWater
	updated.ClaimAdmissionLogRoot = logRoot
	updated.CoverageRevision++
	updated.FilingStateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func UpdateAdapterEvidence(current CoverageRecord, target AdapterEvidenceStatus, evidenceDigest string) (CoverageRecord, error) {
	if !validCoverageRecord(current) || !validDigest(evidenceDigest) {
		return CoverageRecord{}, errors.New("Adapter evidence update is invalid")
	}
	allowed := current.AdapterEvidenceStatus == AdapterEvidenceCurrent && target == AdapterEvidenceUnknown ||
		current.AdapterEvidenceStatus == AdapterEvidenceUnknown &&
			(target == AdapterEvidenceCurrent || target == AdapterEvidenceImpaired || target == AdapterEvidenceTerminalDefault)
	if !allowed {
		return CoverageRecord{}, errors.New("Adapter evidence transition is not permitted")
	}
	updated := current
	updated.AdapterEvidenceStatus = target
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func validCoverageRecord(record CoverageRecord) bool {
	return validDigest(record.CoverageAgreementBodyDigest) && validToken(record.CoverageObligationID, 128) &&
		validDigest(record.ReservationID) && record.CoverageRevision > 0 && record.FilingStateRevision > 0 &&
		record.CoverageStatus != "" && record.ClaimFilingStatus != "" && record.AdapterEvidenceStatus != ""
}

type ClaimStatus string

const (
	ClaimDraft                    ClaimStatus = "draft"
	ClaimSubmitting               ClaimStatus = "submitting"
	ClaimAdmitted                 ClaimStatus = "admitted"
	ClaimReviewing                ClaimStatus = "reviewing"
	ClaimDecisionAdmissionPending ClaimStatus = "decision_admission_pending"
	ClaimEvidenceRequired         ClaimStatus = "evidence_required"
	ClaimApproved                 ClaimStatus = "approved"
	ClaimPartiallyApproved        ClaimStatus = "partially_approved"
	ClaimDenied                   ClaimStatus = "denied"
	ClaimDisputed                 ClaimStatus = "disputed"
	ClaimFinalApproved            ClaimStatus = "final_approved"
	ClaimFinalPartiallyApproved   ClaimStatus = "final_partially_approved"
	ClaimFinalDenied              ClaimStatus = "final_denied"
	ClaimAmbiguous                ClaimStatus = "ambiguous"
)

type PayoutStatus string

const (
	PayoutNotMaterialized PayoutStatus = "not_materialized"
	PayoutNotApplicable   PayoutStatus = "not_applicable"
	PayoutPrepared        PayoutStatus = "prepared"
	PayoutSubmitted       PayoutStatus = "submitted"
	PayoutPartiallyPaid   PayoutStatus = "partially_paid"
	PayoutPaid            PayoutStatus = "paid"
	PayoutDefaulted       PayoutStatus = "defaulted"
	PayoutAmbiguous       PayoutStatus = "ambiguous"
)

type ClaimRecord struct {
	ClaimID                string       `json:"claim_id"`
	ClaimRevision          uint64       `json:"claim_revision"`
	ClaimStatus            ClaimStatus  `json:"claim_status"`
	PayoutStatus           PayoutStatus `json:"payout_status"`
	ClaimStateRevision     uint64       `json:"claim_state_revision"`
	DecisionSequence       uint64       `json:"decision_sequence"`
	CurrentClaimBodyDigest string       `json:"current_claim_body_digest"`
	LastEvidenceDigest     string       `json:"last_evidence_digest"`
}

// ReviseAdmittedClaim advances the immutable claim lineage without allocating
// a second covered incident or claim-admission sequence. A terminal decision,
// approved payout, or ambiguous state can only be changed by its own released
// transition, never by presenting another claim envelope.
func ReviseAdmittedClaim(current ClaimRecord, targetRevision uint64, predecessorDigest,
	evidenceDigest string) (ClaimRecord, error) {
	if !validDigest(current.ClaimID) || targetRevision != current.ClaimRevision+1 ||
		!validDigest(predecessorDigest) || predecessorDigest != current.CurrentClaimBodyDigest ||
		!validDigest(evidenceDigest) || !claimRevisionOpen(current.ClaimStatus) ||
		current.PayoutStatus != PayoutNotMaterialized {
		return ClaimRecord{}, errors.New("claim revision is invalid, stale, or terminal")
	}
	updated := current
	updated.ClaimRevision = targetRevision
	updated.ClaimStatus = ClaimAdmitted
	updated.ClaimStateRevision++
	updated.DecisionSequence = 0
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func claimRevisionOpen(status ClaimStatus) bool {
	switch status {
	case ClaimAdmitted, ClaimReviewing, ClaimDecisionAdmissionPending, ClaimEvidenceRequired, ClaimDisputed:
		return true
	default:
		return false
	}
}

func TransitionClaim(current ClaimRecord, expectedRevision uint64, target ClaimStatus, evidenceDigest string) (ClaimRecord, error) {
	if !validDigest(current.ClaimID) || current.ClaimRevision == 0 || current.ClaimStateRevision != expectedRevision ||
		!validDigest(evidenceDigest) || !allowedClaimTransition(current.ClaimStatus, target) {
		return ClaimRecord{}, errors.New("claim transition is invalid or stale")
	}
	updated := current
	updated.ClaimStatus = target
	updated.ClaimStateRevision++
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func allowedClaimTransition(from, to ClaimStatus) bool {
	switch from {
	case ClaimDraft:
		return to == ClaimSubmitting
	case ClaimSubmitting:
		return to == ClaimAdmitted || to == ClaimAmbiguous
	case ClaimAdmitted:
		return to == ClaimReviewing
	case ClaimReviewing:
		return to == ClaimDecisionAdmissionPending
	case ClaimDecisionAdmissionPending:
		return to == ClaimEvidenceRequired || to == ClaimApproved || to == ClaimPartiallyApproved || to == ClaimDenied ||
			to == ClaimDisputed || to == ClaimAmbiguous
	case ClaimEvidenceRequired, ClaimDisputed:
		return to == ClaimReviewing
	case ClaimApproved:
		return to == ClaimReviewing || to == ClaimFinalApproved
	case ClaimPartiallyApproved:
		return to == ClaimReviewing || to == ClaimFinalPartiallyApproved
	case ClaimDenied:
		return to == ClaimReviewing || to == ClaimFinalDenied
	default:
		return false
	}
}

func TransitionPayout(current ClaimRecord, target PayoutStatus, evidenceDigest string) (ClaimRecord, error) {
	if !validDigest(current.ClaimID) || !validDigest(evidenceDigest) || !allowedPayoutTransition(current.PayoutStatus, target) {
		return ClaimRecord{}, errors.New("payout transition is invalid")
	}
	updated := current
	updated.PayoutStatus = target
	updated.LastEvidenceDigest = evidenceDigest
	return updated, nil
}

func allowedPayoutTransition(from, to PayoutStatus) bool {
	switch from {
	case PayoutNotMaterialized:
		return to == PayoutNotApplicable || to == PayoutPrepared
	case PayoutPrepared:
		return to == PayoutSubmitted || to == PayoutPartiallyPaid || to == PayoutPaid || to == PayoutAmbiguous
	case PayoutSubmitted, PayoutPartiallyPaid:
		return to == PayoutPartiallyPaid || to == PayoutPaid || to == PayoutDefaulted || to == PayoutAmbiguous
	case PayoutAmbiguous:
		return to == PayoutSubmitted || to == PayoutPartiallyPaid || to == PayoutPaid || to == PayoutDefaulted
	default:
		return false
	}
}

func TransitionCollateral(current CollateralPositionStateV1, expectedRevision uint64, target CollateralStatus,
	evidenceDigest string) (CollateralPositionStateV1, error) {
	if current.SchemaVersion != 1 || !validID(current.PositionID) || !validDigest(current.CoverageAgreementBodyDigest) ||
		!validToken(current.CollateralObligationID, 128) || current.StateRevision != expectedRevision ||
		!validDigest(evidenceDigest) || !allowedCollateralTransition(current.Status, target) {
		return CollateralPositionStateV1{}, errors.New("collateral transition is invalid or stale")
	}
	updated := current
	updated.Status = target
	updated.StateRevision++
	return updated, nil
}

func allowedCollateralTransition(from, to CollateralStatus) bool {
	switch from {
	case CollateralUnproven:
		return to == CollateralLockPending
	case CollateralLockPending:
		return to == CollateralLocked || to == CollateralAmbiguous || to == CollateralReorged
	case CollateralLocked:
		return to == CollateralEncumbered || to == CollateralReleasePending || to == CollateralReorged
	case CollateralEncumbered, CollateralPartiallyConsumed:
		return to == CollateralPayoutPending || to == CollateralReleasePending || to == CollateralReorged || to == CollateralDefaulted
	case CollateralPayoutPending:
		return to == CollateralPartiallyConsumed || to == CollateralDepleted || to == CollateralAmbiguous || to == CollateralDefaulted
	case CollateralReleasePending:
		return to == CollateralReleased || to == CollateralAmbiguous || to == CollateralReorged
	case CollateralAmbiguous:
		return to == CollateralLocked || to == CollateralEncumbered || to == CollateralPartiallyConsumed ||
			to == CollateralDepleted || to == CollateralReleased || to == CollateralReorged || to == CollateralDefaulted
	default:
		return false
	}
}
