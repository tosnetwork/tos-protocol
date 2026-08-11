package taskescrowpublisher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

type fakeBackend struct {
	mu             sync.Mutex
	prepareCalls   int
	publishCalls   int
	recoveringSeen bool
	failFirst      bool
}

func (f *fakeBackend) CheckReady(context.Context) error { return nil }
func (f *fakeBackend) Prepare(_ context.Context, action chain.TaskEscrowAction) (PreparedAction, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prepareCalls++
	return PreparedAction{
		ContractAddress: "0:" + strings.Repeat("44", 32),
		PreparedAt:      time.Now().UnixMilli(),
	}, nil
}
func (f *fakeBackend) Publish(
	_ context.Context,
	action chain.TaskEscrowAction,
	prepared PreparedAction,
	recovering bool,
) (chain.TaskEscrowActionReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.publishCalls++
	f.recoveringSeen = f.recoveringSeen || recovering
	if f.failFirst && f.publishCalls == 1 {
		return chain.TaskEscrowActionReceipt{}, errors.New("lost response")
	}
	return taskEscrowReceipt(
		action, prepared.ContractAddress,
		"tos:tx:v1:0:"+strings.Repeat("44", 32)+":1:"+strings.Repeat("55", 32),
	), nil
}
func (f *fakeBackend) Close() error { return nil }

func TestServerReplaysCompletedActionAndRejectsSubstitution(t *testing.T) {
	backend := new(fakeBackend)
	now := time.Unix(1_800_000_000, 0)
	statePath := filepath.Join(t.TempDir(), "state.db")
	if err := InitializeJournal(statePath, "test-journal"); err != nil {
		t.Fatal(err)
	}
	server, err := Open(Config{
		Network: "tos-test", StatePath: statePath, JournalIdentity: "test-journal",
		Backend: backend, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	action := testAction(now)
	first := postAction(t, server.Handler(), action)
	if first.Code != http.StatusOK {
		t.Fatalf("first publish status=%d body=%s", first.Code, first.Body.String())
	}
	// Freshness may be extended without changing the stable Action identity.
	action.ExpiresUnixMillis += 60_000
	second := postAction(t, server.Handler(), action)
	if second.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", second.Code, second.Body.String())
	}
	backend.mu.Lock()
	prepareCalls, publishCalls := backend.prepareCalls, backend.publishCalls
	backend.mu.Unlock()
	if prepareCalls != 1 || publishCalls != 1 {
		t.Fatalf("completed action executed more than once: prepare=%d publish=%d", prepareCalls, publishCalls)
	}
	action.BudgetNanoTOS++
	conflict := postAction(t, server.Handler(), action)
	if conflict.Code != http.StatusConflict {
		t.Fatalf("substitution status=%d body=%s", conflict.Code, conflict.Body.String())
	}
}

func TestServerRecoversPendingAction(t *testing.T) {
	backend := &fakeBackend{failFirst: true}
	now := time.Unix(1_800_000_000, 0)
	statePath := filepath.Join(t.TempDir(), "state.db")
	if err := InitializeJournal(statePath, "test-journal"); err != nil {
		t.Fatal(err)
	}
	server, err := Open(Config{
		Network: "tos-test", StatePath: statePath, JournalIdentity: "test-journal",
		Backend: backend, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	action := testAction(now)
	if response := postAction(t, server.Handler(), action); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("first attempt status=%d", response.Code)
	}
	action.ExpiresUnixMillis += 60_000
	if response := postAction(t, server.Handler(), action); response.Code != http.StatusOK {
		t.Fatalf("recovery status=%d body=%s", response.Code, response.Body.String())
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if backend.prepareCalls != 1 || backend.publishCalls != 2 || !backend.recoveringSeen {
		t.Fatalf("pending recovery was not preserved: %#v", backend)
	}
}

func TestHealthUsesExactClientContract(t *testing.T) {
	backend := new(fakeBackend)
	statePath := filepath.Join(t.TempDir(), "state.db")
	if err := InitializeJournal(statePath, "test-journal"); err != nil {
		t.Fatal(err)
	}
	server, err := Open(Config{
		Network: "tos-test", StatePath: statePath, JournalIdentity: "test-journal", Backend: backend,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := httptest.NewRequest(http.MethodGet, localrpc.TaskEscrowActionHealthPath, nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("health status=%d", response.Code)
	}
	var health map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	if health["status"] != "ready" || health["network"] != "tos-test" ||
		health["path"] != localrpc.TaskEscrowActionPath {
		t.Fatalf("unexpected health response: %#v", health)
	}
}

func TestPublisherRequiresEnrolledJournalAndTypedResolve(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.db")
	if _, err := Open(Config{Network: "tos-test", StatePath: path, JournalIdentity: "journal-a", Backend: new(fakeBackend)}); err == nil {
		t.Fatal("missing journal was silently initialized")
	}
	if err := InitializeJournal(path, "journal-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Network: "tos-test", StatePath: path, JournalIdentity: "journal-b", Backend: new(fakeBackend)}); err == nil {
		t.Fatal("mismatched journal identity was accepted")
	}
	server, err := Open(Config{Network: "tos-test", StatePath: path, JournalIdentity: "journal-a", Backend: new(fakeBackend), Now: func() time.Time { return time.Unix(1_800_000_000, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	action := testAction(time.Unix(1_800_000_000, 0))
	encoded, _ := json.Marshal(action)
	req := httptest.NewRequest(http.MethodPost, localrpc.TaskEscrowActionResolvePath, bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("resolve status=%d body=%s", res.Code, res.Body.String())
	}
	var missing map[string]string
	if json.Unmarshal(res.Body.Bytes(), &missing) != nil || missing["code"] != "action_not_found" || missing["actionId"] != action.ActionID {
		t.Fatalf("untyped absence: %#v", missing)
	}
}

func testAction(now time.Time) chain.TaskEscrowAction {
	return chain.TaskEscrowAction{
		Version:  chain.TaskEscrowActionVersion,
		ActionID: "act-" + strings.Repeat("11", 32), Network: "tos-test",
		Kind: chain.TaskEscrowActionDeploy, EscrowID: "esc-1",
		Creator:       "0:" + strings.Repeat("11", 32),
		Agent:         "0:" + strings.Repeat("22", 32),
		Verifier:      "0:" + strings.Repeat("33", 32),
		BudgetNanoTOS: 1_000_000_000, FundingNanoTOS: 1_100_000_000,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		PolicyHash:        "sha256:" + strings.Repeat("aa", 32),
		PermissionHash:    "sha256:" + strings.Repeat("bb", 32),
		ExpiresUnixMillis: now.Add(time.Minute).UnixMilli(),
	}
}

func postAction(t *testing.T, handler http.Handler, action chain.TaskEscrowAction) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(action)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, localrpc.TaskEscrowActionPath, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
