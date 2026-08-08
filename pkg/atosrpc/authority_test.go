package atosrpc

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

type failingAuthority struct {
	closed bool
}

func (*failingAuthority) Network() string                  { return "tos-test" }
func (*failingAuthority) Supports(TrustMode) bool          { return false }
func (*failingAuthority) CheckReady(context.Context) error { return errors.New("not ready") }
func (*failingAuthority) Commit(context.Context, string, string, string) (NetworkReference, error) {
	return NetworkReference{}, errors.New("not ready")
}
func (a *failingAuthority) Close() error { a.closed = true; return nil }

func TestOpenRequiresExplicitReadyAuthority(t *testing.T) {
	if _, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret",
	}); err == nil {
		t.Fatal("server without explicit Authority was accepted")
	}
	authority := new(failingAuthority)
	if _, err := Open(Config{
		StatePath:   filepath.Join(t.TempDir(), "atos-rpc.db"),
		BearerToken: "test-secret", Authority: authority,
	}); err == nil {
		t.Fatal("server with unready Authority was accepted")
	}
	if !authority.closed {
		t.Fatal("unready Authority was not closed after startup failure")
	}
}
