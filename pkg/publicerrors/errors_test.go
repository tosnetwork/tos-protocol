package publicerrors

import (
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

func TestCanonicalPublicErrorMatrix(t *testing.T) {
	for _, test := range []struct {
		kind  Kind
		retry time.Duration
	}{
		{BadRequest, 0}, {NotFound, 0}, {Conflict, 0}, {DependencyUnavailable, time.Second},
		{Capacity, 2 * time.Second}, {AmbiguousOutcome, 0}, {Deadline, 0}, {Unauthenticated, 0}, {PermissionDenied, 0},
	} {
		err := New(test.kind, errors.New("diagnostic"), test.retry)
		detail, ok := Detail(err)
		if !ok || detail.Code == nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_UNSPECIFIED ||
			detail.RetryDisposition == nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_UNSPECIFIED {
			t.Fatalf("kind=%d detail=%+v err=%v", test.kind, detail, err)
		}
	}
}

func TestDetailRejectsMissingOrConflictingRetryContract(t *testing.T) {
	if _, ok := Detail(connect.NewError(connect.CodeUnavailable, errors.New("untyped"))); ok {
		t.Fatal("untyped error accepted")
	}
	err := connect.NewError(connect.CodeUnavailable, errors.New("conflicting"))
	detail, detailErr := connect.NewErrorDetail(&nativev1.NativeErrorV1{
		Code:             nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_PUBLIC_DEPENDENCY_UNAVAILABLE,
		Identifier:       "PUBLIC_DEPENDENCY_UNAVAILABLE",
		RetryDisposition: nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_SAME_REQUEST_AFTER_BACKOFF})
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	err.AddDetail(detail)
	if _, ok := Detail(err); ok {
		t.Fatal("zero backoff accepted")
	}
}

func TestNewRejectsUnsafeDelayShapes(t *testing.T) {
	if _, ok := Detail(New(DependencyUnavailable, errors.New("x"), 6*time.Minute)); ok {
		t.Fatal("oversized delay accepted")
	}
	if _, ok := Detail(New(BadRequest, errors.New("x"), time.Second)); ok {
		t.Fatal("delay on permanent error accepted")
	}
}
