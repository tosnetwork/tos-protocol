package protocol

import (
	"errors"
	"fmt"
	"time"
)

type ErrorCode string

const (
	ErrorInvalidArgument      ErrorCode = "INVALID_ARGUMENT"
	ErrorUnsupportedVersion   ErrorCode = "UNSUPPORTED_VERSION"
	ErrorAuthenticationFailed ErrorCode = "AUTHENTICATION_FAILED"
	ErrorAuthorizationDenied  ErrorCode = "AUTHORIZATION_DENIED"
	ErrorReplayDetected       ErrorCode = "REPLAY_DETECTED"
	ErrorQuoteExpired         ErrorCode = "QUOTE_EXPIRED"
	ErrorQuoteMismatch        ErrorCode = "QUOTE_MISMATCH"
	ErrorPaymentRequired      ErrorCode = "PAYMENT_REQUIRED"
	ErrorPaymentUnconfirmed   ErrorCode = "PAYMENT_UNCONFIRMED"
	ErrorPaymentReorganized   ErrorCode = "PAYMENT_REORGANIZED"
	ErrorAdmissionRejected    ErrorCode = "ADMISSION_REJECTED"
	ErrorResourceExhausted    ErrorCode = "RESOURCE_EXHAUSTED"
	ErrorDeadlineExceeded     ErrorCode = "DEADLINE_EXCEEDED"
	ErrorCanceled             ErrorCode = "CANCELED"
	ErrorRuntimeFailed        ErrorCode = "RUNTIME_FAILED"
	ErrorEvidenceInvalid      ErrorCode = "EVIDENCE_INVALID"
	ErrorSettlementPending    ErrorCode = "SETTLEMENT_PENDING"
	ErrorInternal             ErrorCode = "INTERNAL"
)

type RetryClass string

const (
	RetryNever            RetryClass = "never"
	RetrySafe             RetryClass = "safe"
	RetryAfterDelay       RetryClass = "after-delay"
	RetryAfterReauthorize RetryClass = "after-reauthorize"
	RetryAfterPayment     RetryClass = "after-payment"
	RetryAfterStateChange RetryClass = "after-state-change"
)

type ProtocolError struct {
	Code             ErrorCode         `json:"code"`
	Message          string            `json:"message"`
	Retry            RetryClass        `json:"retry"`
	RetryAfterMillis uint64            `json:"retryAfterMillis,omitempty"`
	Details          map[string]string `json:"details,omitempty"`
}

func (e ProtocolError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e ProtocolError) Validate() error {
	if !e.Code.Valid() {
		return errors.New("invalid protocol error code")
	}
	if err := boundedString("error message", e.Message, 1, 1024); err != nil {
		return err
	}
	switch e.Retry {
	case RetryNever, RetrySafe, RetryAfterDelay, RetryAfterReauthorize,
		RetryAfterPayment, RetryAfterStateChange:
	default:
		return errors.New("invalid retry class")
	}
	if e.Retry == RetryAfterDelay {
		if e.RetryAfterMillis == 0 || e.RetryAfterMillis > uint64((24*time.Hour).Milliseconds()) {
			return errors.New("after-delay error requires a bounded retry delay")
		}
	} else if e.RetryAfterMillis != 0 {
		return errors.New("retryAfterMillis is valid only for after-delay")
	}
	if len(e.Details) > 16 {
		return errors.New("too many error detail fields")
	}
	for key, value := range e.Details {
		if !serviceIDPattern.MatchString(key) {
			return errors.New("invalid error detail key")
		}
		if err := boundedString("error detail", value, 0, 512); err != nil {
			return err
		}
	}
	return nil
}

func (c ErrorCode) Valid() bool {
	switch c {
	case ErrorInvalidArgument, ErrorUnsupportedVersion, ErrorAuthenticationFailed,
		ErrorAuthorizationDenied, ErrorReplayDetected, ErrorQuoteExpired,
		ErrorQuoteMismatch, ErrorPaymentRequired, ErrorPaymentUnconfirmed,
		ErrorPaymentReorganized, ErrorAdmissionRejected, ErrorResourceExhausted,
		ErrorDeadlineExceeded, ErrorCanceled, ErrorRuntimeFailed,
		ErrorEvidenceInvalid, ErrorSettlementPending, ErrorInternal:
		return true
	default:
		return false
	}
}
