package edge

import (
	"errors"
)

// SuccessfulChargeBasisPoints is the complete quoted-price denominator.
const SuccessfulChargeBasisPoints uint16 = 10_000

// SuccessfulReceiptPolicy is an immutable, declarative charging rule for a
// successfully completed invocation. The zero value is deliberately invalid;
// a missing policy on a profile registration is normalized to the compatible
// full-quoted-price policy when the immutable deployment plan is built.
//
// Keeping this value data-only makes live and restart recovery evaluation
// deterministic and prevents request-driven callbacks from accumulating
// process state.
type SuccessfulReceiptPolicy struct {
	chargeBasisPoints uint16
	valid             bool
}

// FullSuccessfulReceiptPolicy preserves the v0.1 default: a validated
// successful result charges the complete quoted price.
func FullSuccessfulReceiptPolicy() SuccessfulReceiptPolicy {
	return SuccessfulReceiptPolicy{
		chargeBasisPoints: SuccessfulChargeBasisPoints,
		valid:             true,
	}
}

// NewProportionalSuccessfulReceiptPolicy constructs a deterministic fraction
// of the quoted price. The result is rounded down to whole nano-TOS, can be
// zero, and can never exceed the quote.
func NewProportionalSuccessfulReceiptPolicy(
	chargeBasisPoints uint16,
) (SuccessfulReceiptPolicy, error) {
	if chargeBasisPoints > SuccessfulChargeBasisPoints {
		return SuccessfulReceiptPolicy{}, errors.New(
			"successful charge basis points exceed 10000",
		)
	}
	return SuccessfulReceiptPolicy{
		chargeBasisPoints: chargeBasisPoints,
		valid:             true,
	}, nil
}

func (p SuccessfulReceiptPolicy) chargedNanoTOS(
	quotedNanoTOS uint64,
) (uint64, error) {
	if !p.valid || p.chargeBasisPoints > SuccessfulChargeBasisPoints {
		return 0, errors.New("invalid successful receipt policy")
	}
	// Split before multiplication so all uint64 quote values, including
	// math.MaxUint64, are evaluated without overflow.
	whole := quotedNanoTOS / uint64(SuccessfulChargeBasisPoints)
	remainder := quotedNanoTOS % uint64(SuccessfulChargeBasisPoints)
	charged := whole*uint64(p.chargeBasisPoints) +
		(remainder*uint64(p.chargeBasisPoints))/
			uint64(SuccessfulChargeBasisPoints)
	if charged > quotedNanoTOS {
		return 0, errors.New("successful receipt charge exceeds quote")
	}
	return charged, nil
}
