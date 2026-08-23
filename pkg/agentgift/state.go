package agentgift

import "errors"

import "fmt"

type SenderState string

const (
	SenderDraft             SenderState = "draft"
	SenderRecipientResolved SenderState = "recipient-resolved"
	SenderAddressRequested  SenderState = "address-requested"
	SenderAddressReceived   SenderState = "address-received"
	SenderOwnerAuthorized   SenderState = "owner-authorized"
	SenderBOCSigned         SenderState = "boc-signed"
	SenderOfferDelivered    SenderState = "offer-delivered"
	SenderFinalizedPaid     SenderState = "finalized-paid"
	SenderExpiredUnpaid     SenderState = "expired-unpaid"
	SenderInvalidatedUnpaid SenderState = "invalidated-unpaid"
	SenderFinalityUnknown   SenderState = "finality-unknown"
)

type RecipientState string

const (
	RecipientAddressRequestObserved RecipientState = "address-request-observed"
	RecipientAddressResponseSent    RecipientState = "address-response-sent"
	RecipientSignedOfferObserved    RecipientState = "signed-offer-observed"
	RecipientVerified               RecipientState = "verified"
	RecipientBroadcastSubmitted     RecipientState = "broadcast-submitted"
	RecipientFinalizedPaid          RecipientState = "finalized-paid"
	RecipientExpiredUnpaid          RecipientState = "expired-unpaid"
	RecipientInvalidatedUnpaid      RecipientState = "invalidated-unpaid"
	RecipientFinalityUnknown        RecipientState = "finality-unknown"
)

type RetryDisposition string

const (
	RetryExact               RetryDisposition = "retry-exact"
	RetryAfterFinalizedRead  RetryDisposition = "retry-after-finalized-read"
	RetryAfterExternalChange RetryDisposition = "retry-after-external-change"
	RetryNever               RetryDisposition = "never"
)

type ErrorCode string

const (
	ErrInvalidCanonical     ErrorCode = "gift_invalid_canonical"
	ErrConversationRequired ErrorCode = "gift_direct_authenticated_conversation_required"
	ErrIntentConflict       ErrorCode = "gift_intent_conflict"
	ErrOwnerAuthorization   ErrorCode = "gift_owner_authorization_required"
	ErrCustodyConflict      ErrorCode = "gift_custody_seqno_conflict"
	ErrNotExecutable        ErrorCode = "gift_currently_not_executable"
	ErrFinalityUnavailable  ErrorCode = "gift_finality_unavailable"
	ErrTerminal             ErrorCode = "gift_terminal"
)

// TypedError is a sealed classification interface. Only this package can
// construct an implementation, so every value exposed through errors.As has
// passed the bounded code and retry-disposition checks in NewError.
type TypedError interface {
	error
	Code() ErrorCode
	Retry() RetryDisposition
	isGiftTypedError()
}

type typedError struct {
	code  ErrorCode
	retry RetryDisposition
	cause error
}

func (e *typedError) Error() string {
	if e == nil {
		return ""
	}
	if e.cause != nil {
		return string(e.code) + ": " + e.cause.Error()
	}
	return string(e.code)
}
func (e *typedError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *typedError) Code() ErrorCode {
	if e == nil {
		return ""
	}
	return e.code
}

func (e *typedError) Retry() RetryDisposition {
	if e == nil {
		return ""
	}
	return e.retry
}

func (*typedError) isGiftTypedError() {}

func NewError(code ErrorCode, retry RetryDisposition, cause error) error {
	if !knownErrorCode(code) || !knownRetryDisposition(retry) {
		if cause != nil {
			return fmt.Errorf("invalid typed Gift error (code=%q retry=%q): %w", code, retry, cause)
		}
		return fmt.Errorf("invalid typed Gift error (code=%q retry=%q)", code, retry)
	}
	return &typedError{code: code, retry: retry, cause: cause}
}

func knownErrorCode(code ErrorCode) bool {
	switch code {
	case ErrInvalidCanonical, ErrConversationRequired, ErrIntentConflict, ErrOwnerAuthorization,
		ErrCustodyConflict, ErrNotExecutable, ErrFinalityUnavailable, ErrTerminal:
		return true
	default:
		return false
	}
}

func knownRetryDisposition(retry RetryDisposition) bool {
	switch retry {
	case RetryExact, RetryAfterFinalizedRead, RetryAfterExternalChange, RetryNever:
		return true
	default:
		return false
	}
}

func SenderTerminal(state SenderState) bool {
	return state == SenderFinalizedPaid || state == SenderExpiredUnpaid || state == SenderInvalidatedUnpaid
}
func RecipientTerminal(state RecipientState) bool {
	return state == RecipientFinalizedPaid || state == RecipientExpiredUnpaid || state == RecipientInvalidatedUnpaid
}

func ValidateSenderTransition(from, to SenderState) error {
	allowed := map[SenderState]map[SenderState]bool{
		SenderDraft:             {SenderRecipientResolved: true},
		SenderRecipientResolved: {SenderAddressRequested: true},
		SenderAddressRequested:  {SenderAddressReceived: true},
		SenderAddressReceived:   {SenderOwnerAuthorized: true},
		SenderOwnerAuthorized:   {SenderBOCSigned: true},
		SenderBOCSigned:         {SenderOfferDelivered: true, SenderFinalityUnknown: true},
		SenderOfferDelivered:    {SenderFinalizedPaid: true, SenderExpiredUnpaid: true, SenderInvalidatedUnpaid: true, SenderFinalityUnknown: true},
		SenderFinalityUnknown:   {SenderOfferDelivered: true, SenderFinalizedPaid: true, SenderExpiredUnpaid: true, SenderInvalidatedUnpaid: true},
	}
	if from == to || allowed[from][to] {
		return nil
	}
	return errors.New("invalid sender Gift lifecycle transition")
}

func ValidateRecipientTransition(from, to RecipientState) error {
	allowed := map[RecipientState]map[RecipientState]bool{
		RecipientAddressRequestObserved: {RecipientAddressResponseSent: true},
		RecipientAddressResponseSent:    {RecipientSignedOfferObserved: true},
		RecipientSignedOfferObserved:    {RecipientVerified: true},
		RecipientVerified:               {RecipientBroadcastSubmitted: true, RecipientFinalityUnknown: true},
		RecipientBroadcastSubmitted:     {RecipientFinalizedPaid: true, RecipientExpiredUnpaid: true, RecipientInvalidatedUnpaid: true, RecipientFinalityUnknown: true},
		RecipientFinalityUnknown:        {RecipientVerified: true, RecipientBroadcastSubmitted: true, RecipientFinalizedPaid: true, RecipientExpiredUnpaid: true, RecipientInvalidatedUnpaid: true},
	}
	if from == to || allowed[from][to] {
		return nil
	}
	return errors.New("invalid recipient Gift lifecycle transition")
}
