package localrpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
)

const (
	testNativeJournal = "journal-1"
	testNativeBinding = "sha256:binding"
	testNativeAction  = "sha256:action"
)

func newNativeRegistryTestClient(t *testing.T, handler http.Handler) *NativeRegistryPublisherClient {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "nrpc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "publisher.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socket, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = os.Remove(socket) })
	client, err := NewNativeRegistryPublisherClient(NativeRegistryPublisherClientConfig{
		SocketPath: socket, JournalIdentity: testNativeJournal, JournalBinding: testNativeBinding, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func nativeRegistryResponseHandler(status int, body any) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw, ok := body.(string); ok {
			_, _ = w.Write([]byte(raw))
			return
		}
		_ = json.NewEncoder(w).Encode(body)
	})
}

func TestNativeRegistryPublisherClientRejectsGeneric404(t *testing.T) {
	client := newNativeRegistryTestClient(t, http.NotFoundHandler())
	err := client.Resolve(context.Background(), nativeregistry.Submission{}, testNativeAction, "sha256:semantics")
	if err == nil || errors.Is(err, nativeregistry.ErrPublisherNotFound) {
		t.Fatalf("generic 404 authorized replay: %v", err)
	}
}

func TestNativeRegistryPublisherClientTypedAbsenceAndPending(t *testing.T) {
	base := map[string]string{
		"version":          "tos.native.registry-publisher.v1",
		"action_id":        testNativeAction,
		"journal_identity": testNativeJournal,
		"journal_binding":  testNativeBinding,
	}
	for _, test := range []struct {
		name   string
		status int
		code   string
		want   error
	}{
		{name: "typed absence", status: http.StatusNotFound, code: "action_not_found", want: nativeregistry.ErrPublisherNotFound},
		{name: "pending intent", status: http.StatusConflict, code: "action_pending", want: nativeregistry.ErrPublisherPending},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := make(map[string]string, len(base)+1)
			for key, value := range base {
				body[key] = value
			}
			body["code"] = test.code
			client := newNativeRegistryTestClient(t, nativeRegistryResponseHandler(test.status, body))
			err := client.Resolve(context.Background(), nativeregistry.Submission{}, testNativeAction, "sha256:semantics")
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}
}

func TestNativeRegistryPublisherClientRejectsUnboundOrMalformedEvidence(t *testing.T) {
	valid := map[string]string{
		"version":          "tos.native.registry-publisher.v1",
		"status":           "completed",
		"code":             "",
		"action_id":        testNativeAction,
		"journal_identity": testNativeJournal,
		"journal_binding":  testNativeBinding,
	}
	tests := []struct {
		name   string
		status int
		body   any
	}{
		{name: "malformed json", status: http.StatusOK, body: "{"},
		{name: "wrong schema", status: http.StatusOK, body: map[string]string{"version": "v0", "action_id": testNativeAction}},
		{name: "wrong action", status: http.StatusOK, body: map[string]string{"version": "tos.native.registry-publisher.v1", "action_id": "sha256:other"}},
		{name: "wrong service success", status: http.StatusOK, body: map[string]string{"version": "tos.native.registry-publisher.v1", "status": "completed", "action_id": testNativeAction}},
		{name: "wrong journal identity", status: http.StatusOK, body: cloneStringMap(valid, "journal_identity", "replacement-journal")},
		{name: "wrong journal binding", status: http.StatusOK, body: cloneStringMap(valid, "journal_binding", "sha256:replacement")},
		{name: "wrong success status", status: http.StatusOK, body: cloneStringMap(valid, "status", "accepted")},
		{name: "typed code on success", status: http.StatusOK, body: cloneStringMap(valid, "code", "action_not_found")},
		{name: "proxy 404", status: http.StatusNotFound, body: map[string]string{"version": "tos.native.registry-publisher.v1", "code": "action_not_found", "action_id": testNativeAction}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := newNativeRegistryTestClient(t, nativeRegistryResponseHandler(test.status, test.body))
			err := client.Resolve(context.Background(), nativeregistry.Submission{}, testNativeAction, "sha256:semantics")
			if err == nil || errors.Is(err, nativeregistry.ErrPublisherNotFound) {
				t.Fatalf("untrusted evidence was accepted: %v", err)
			}
		})
	}
}

func cloneStringMap(source map[string]string, key, value string) map[string]string {
	clone := make(map[string]string, len(source))
	for field, fieldValue := range source {
		clone[field] = fieldValue
	}
	clone[key] = value
	return clone
}
