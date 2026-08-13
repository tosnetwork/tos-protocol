package atosrpc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type mutableReadinessAuthority struct {
	mu  sync.RWMutex
	err error
}

type deadlineAuthority struct{ remaining time.Duration }

func (*deadlineAuthority) Network() string         { return "tos-test" }
func (*deadlineAuthority) Supports(TrustMode) bool { return true }
func (a *deadlineAuthority) CheckReady(ctx context.Context) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("readiness context has no deadline")
	}
	a.remaining = time.Until(deadline)
	return nil
}
func (*deadlineAuthority) Commit(context.Context, string, string, string) (NetworkReference, error) {
	return NetworkReference{}, errors.New("unused")
}
func (*deadlineAuthority) Close() error { return nil }

func (*mutableReadinessAuthority) Network() string         { return "tos-test" }
func (*mutableReadinessAuthority) Supports(TrustMode) bool { return true }
func (a *mutableReadinessAuthority) CheckReady(context.Context) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.err
}
func (*mutableReadinessAuthority) Commit(context.Context, string, string, string) (NetworkReference, error) {
	return NetworkReference{}, errors.New("unused")
}
func (*mutableReadinessAuthority) Close() error { return nil }
func (a *mutableReadinessAuthority) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

func TestHealthAndReadyzFailClosedButLivezStaysLive(t *testing.T) {
	authority := new(mutableReadinessAuthority)
	server, err := Open(Config{StatePath: filepath.Join(t.TempDir(), "rpc.db"), BearerToken: "secret", Authority: authority})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	for _, path := range []string{"/healthz", "/readyz", "/livez"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, response.Code)
		}
	}
	authority.fail(errors.New("quorum unavailable"))
	server.readinessMu.Lock()
	server.readinessAt = time.Time{}
	server.readinessMu.Unlock()
	for _, path := range []string{"/healthz", "/readyz"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s status=%d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("liveness status=%d", response.Code)
	}
}

func TestPublicReadinessUsesIndependentShortTimeout(t *testing.T) {
	authority := new(deadlineAuthority)
	server := &Server{config: Config{CallTimeout: time.Minute}, authority: authority}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	if authority.remaining <= 0 || authority.remaining > readinessProbeTimeout {
		t.Fatalf("readiness timeout=%s", authority.remaining)
	}
}
