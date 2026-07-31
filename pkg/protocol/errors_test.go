package protocol

import "testing"

func TestProtocolErrorRetrySemantics(t *testing.T) {
	valid := ProtocolError{
		Code:             ErrorResourceExhausted,
		Message:          "capacity unavailable",
		Retry:            RetryAfterDelay,
		RetryAfterMillis: 1000,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.Retry = RetryNever
	if err := valid.Validate(); err == nil {
		t.Fatal("retry delay with RetryNever accepted")
	}
}
