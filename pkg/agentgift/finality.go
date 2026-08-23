package agentgift

import "errors"

type Resolution string

const (
	ResolutionPending               Resolution = "pending"
	ResolutionCurrentlyExecutable   Resolution = "currently-executable"
	ResolutionCurrentlyUnexecutable Resolution = "currently-unexecutable"
	ResolutionInsufficientFunds     Resolution = "insufficient-funds"
	ResolutionFinalizedPaid         Resolution = "finalized-paid"
	ResolutionExpiredUnpaid         Resolution = "expired-unpaid"
	ResolutionInvalidatedUnpaid     Resolution = "invalidated-unpaid"
	ResolutionFinalityUnknown       Resolution = "finality-unknown"
)

type FinalizedGiftObservation struct {
	Available                bool
	FinalizedChainTime       uint32
	ExpectedDeploymentID     string
	CurrentDeploymentID      string
	SignedSeqno              uint32
	CurrentSeqno             uint32
	ValidUntil               uint32
	ExactExternalBOCExecuted bool
	ExecutionFinalityKnown   bool
	ExactDestinationCredit   bool
	// DestinationCreditFinalityKnown is true either when the exact recipient
	// credit has been resolved or when a finalized sender transaction already
	// makes the required one-output payment proof impossible.
	DestinationCreditFinalityKnown bool
	ControllerCurrentlyMatches     bool
	PolicyCurrentlyAllows          bool
	BalanceAtomic                  uint64
	AmountAtomic                   uint64
	FeeReserveAtomic               uint64
}

func ResolveFinalizedGift(v FinalizedGiftObservation) (Resolution, error) {
	if v.ValidUntil == 0 || v.ExpectedDeploymentID == "" || v.SignedSeqno == ^uint32(0) || v.AmountAtomic == 0 {
		return "", errors.New("incomplete finalized Gift observation")
	}
	if !v.Available {
		return ResolutionFinalityUnknown, nil
	}
	if v.ExactExternalBOCExecuted {
		if v.ExactDestinationCredit {
			return ResolutionFinalizedPaid, nil
		}
		if !v.DestinationCreditFinalityKnown {
			return ResolutionPending, nil
		}
		return ResolutionInvalidatedUnpaid, nil
	}
	if !v.ExecutionFinalityKnown {
		return ResolutionFinalityUnknown, nil
	}
	if v.CurrentDeploymentID != v.ExpectedDeploymentID || v.CurrentSeqno > v.SignedSeqno {
		return ResolutionInvalidatedUnpaid, nil
	}
	if v.FinalizedChainTime > v.ValidUntil {
		return ResolutionExpiredUnpaid, nil
	}
	if !v.ControllerCurrentlyMatches || !v.PolicyCurrentlyAllows {
		return ResolutionCurrentlyUnexecutable, nil
	}
	if v.FeeReserveAtomic > ^uint64(0)-v.AmountAtomic || v.BalanceAtomic < v.AmountAtomic+v.FeeReserveAtomic {
		return ResolutionInsufficientFunds, nil
	}
	return ResolutionCurrentlyExecutable, nil
}
