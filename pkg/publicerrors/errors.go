// Package publicerrors defines the stable Connect error detail and automatic
// retry contract shared by public Native Gateways and clients.
package publicerrors

import (
	"errors"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
)

type Kind uint8

const (
	BadRequest Kind = iota + 1
	NotFound
	Conflict
	DependencyUnavailable
	Capacity
	AmbiguousOutcome
	Deadline
	Unauthenticated
	PermissionDenied
)

type definition struct {
	connectCode  connect.Code
	protocolCode nativev1.NativeErrorCodeV1
	identifier   string
	retry        nativev1.RetryDispositionV1
}

var definitions = map[Kind]definition{
	BadRequest: {connect.CodeInvalidArgument, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_BAD_REQUEST,
		"PUBLIC_BAD_REQUEST", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
	NotFound: {connect.CodeNotFound, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_NOT_FOUND,
		"PUBLIC_NOT_FOUND", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
	Conflict: {connect.CodeFailedPrecondition, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_CONFLICT,
		"PUBLIC_CONFLICT", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
	DependencyUnavailable: {connect.CodeUnavailable, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_DEPENDENCY_UNAVAILABLE,
		"PUBLIC_DEPENDENCY_UNAVAILABLE", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_SAME_REQUEST_AFTER_BACKOFF},
	Capacity: {connect.CodeResourceExhausted, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_CAPACITY,
		"PUBLIC_CAPACITY", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_SAME_REQUEST_AFTER_BACKOFF},
	AmbiguousOutcome: {connect.CodeAborted, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_AMBIGUOUS_OUTCOME,
		"PUBLIC_AMBIGUOUS_OUTCOME", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_RESOLVE_BEFORE_RETRY},
	Deadline: {connect.CodeDeadlineExceeded, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_DEADLINE,
		"PUBLIC_DEADLINE", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
	Unauthenticated: {connect.CodeUnauthenticated, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_UNAUTHENTICATED,
		"PUBLIC_UNAUTHENTICATED", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
	PermissionDenied: {connect.CodePermissionDenied, nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_PERMISSION_DENIED,
		"PUBLIC_PERMISSION_DENIED", nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER},
}

// New creates one canonical public error. retryAfter is required only for the
// backoff disposition and is bounded so a peer cannot induce an unbounded wait.
func New(kind Kind, cause error, retryAfter time.Duration) error {
	definition, ok := definitions[kind]
	if !ok || cause == nil {
		return errors.New("invalid public error construction")
	}
	millis := uint32(0)
	if definition.retry == nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_SAME_REQUEST_AFTER_BACKOFF {
		if retryAfter == 0 {
			retryAfter = time.Second
		}
		if retryAfter < 100*time.Millisecond || retryAfter > 5*time.Minute || retryAfter%time.Millisecond != 0 {
			return errors.New("invalid public error retry delay")
		}
		millis = uint32(retryAfter / time.Millisecond)
	} else if retryAfter != 0 {
		return errors.New("retry delay is forbidden for this public error")
	}
	result := connect.NewError(definition.connectCode, cause)
	detail, err := connect.NewErrorDetail(&nativev1.NativeErrorV1{Code: definition.protocolCode,
		Identifier: definition.identifier, RetryDisposition: definition.retry, RetryAfterMillis: millis})
	if err != nil {
		return errors.New("construct public error detail")
	}
	result.AddDetail(detail)
	return result
}

// Detail returns a validated canonical detail. Unknown or conflicting details
// are ignored, so callers fail closed instead of applying unsafe retry policy.
func Detail(err error) (*nativev1.NativeErrorV1, bool) {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || len(connectErr.Details()) != 1 {
		return nil, false
	}
	value, valueErr := connectErr.Details()[0].Value()
	if valueErr != nil {
		return nil, false
	}
	detail, ok := value.(*nativev1.NativeErrorV1)
	if !ok {
		return nil, false
	}
	for _, definition := range definitions {
		if detail.Code == definition.protocolCode && detail.Identifier == definition.identifier &&
			detail.RetryDisposition == definition.retry && connectErr.Code() == definition.connectCode {
			if definition.retry == nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_SAME_REQUEST_AFTER_BACKOFF {
				if detail.RetryAfterMillis < 100 || detail.RetryAfterMillis > 300_000 {
					return nil, false
				}
			} else if detail.RetryAfterMillis != 0 {
				return nil, false
			}
			return detail, true
		}
	}
	return nil, false
}
