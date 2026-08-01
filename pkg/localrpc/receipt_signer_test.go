package localrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

func TestReceiptSignerClientSignsWithoutLoadingKeyIntoEdge(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != ReceiptSignerPath {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			var input receiptSignerRequest
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.Version != "1" {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			envelope, err := identity.Sign(
				privateKey, protocol.ReceiptDomain, "receipt-key-1", input.Payload,
				time.UnixMilli(input.IssuedUnixMillis),
				time.UnixMilli(input.ExpiresUnixMillis),
			)
			if err != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(writer).Encode(envelope)
		},
	))
	t.Cleanup(stop)
	client, err := NewReceiptSignerClient(
		DefaultReceiptSignerClientConfig(socketPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.UnixMilli(1_800_000_000_000).UTC()
	expiresAt := issuedAt.Add(time.Minute)
	payload := []byte("canonical-receipt")
	envelope, err := client.SignReceipt(
		context.Background(), payload, issuedAt, expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := envelope.Verify(publicKey, protocol.ReceiptDomain, issuedAt); err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	if string(envelope.Payload) != "canonical-receipt" {
		t.Fatal("receipt signer response aliases caller payload")
	}

	const workers = 64
	var wait sync.WaitGroup
	errorsSeen := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			value, err := client.SignReceipt(
				context.Background(), []byte("parallel"), issuedAt, expiresAt,
			)
			if err == nil {
				err = value.Verify(publicKey, protocol.ReceiptDomain, issuedAt)
			}
			if err != nil {
				errorsSeen <- err
			}
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		t.Error(err)
	}
}

func TestReceiptSignerClientRejectsMalformedOrChangedResponses(t *testing.T) {
	issuedAt := time.UnixMilli(1_800_000_000_000).UTC()
	expiresAt := issuedAt.Add(time.Minute)
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := identity.Sign(
		privateKey, protocol.ReceiptDomain, "receipt-key-1", []byte("payload"),
		issuedAt, expiresAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		status      int
		contentType string
		location    string
		body        func() string
	}{
		{name: "rejection", status: http.StatusForbidden, contentType: "application/json", body: func() string { return `{}` }},
		{name: "redirect", status: http.StatusTemporaryRedirect, contentType: "application/json", location: "http://unix/other", body: func() string { return `{}` }},
		{name: "content type", status: http.StatusOK, contentType: "text/plain", body: func() string { data, _ := json.Marshal(valid); return string(data) }},
		{name: "duplicate", status: http.StatusOK, contentType: "application/json", body: func() string { return `{"version":1,"version":1}` }},
		{name: "unknown field", status: http.StatusOK, contentType: "application/json", body: func() string {
			data, _ := json.Marshal(valid)
			return strings.TrimSuffix(string(data), "}") + `,"secret":"leak"}`
		}},
		{name: "changed payload", status: http.StatusOK, contentType: "application/json", body: func() string {
			changed := valid
			changed.Payload = []byte("other")
			data, _ := json.Marshal(changed)
			return string(data)
		}},
		{name: "changed time", status: http.StatusOK, contentType: "application/json", body: func() string {
			changed := valid
			changed.ExpiresAt++
			data, _ := json.Marshal(changed)
			return string(data)
		}},
		{name: "wrong domain", status: http.StatusOK, contentType: "application/json", body: func() string {
			changed := valid
			changed.Domain = "tos.quote.v1"
			data, _ := json.Marshal(changed)
			return string(data)
		}},
		{name: "malformed signature", status: http.StatusOK, contentType: "application/json", body: func() string {
			changed := valid
			changed.Signature = "bad"
			data, _ := json.Marshal(changed)
			return string(data)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
				func(writer http.ResponseWriter, _ *http.Request) {
					writer.Header().Set("Content-Type", test.contentType)
					if test.location != "" {
						writer.Header().Set("Location", test.location)
					}
					writer.WriteHeader(test.status)
					_, _ = writer.Write([]byte(test.body()))
				},
			))
			defer stop()
			client, err := NewReceiptSignerClient(
				DefaultReceiptSignerClientConfig(socketPath),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.SignReceipt(
				context.Background(), []byte("payload"), issuedAt, expiresAt,
			); err == nil {
				t.Fatal("unsafe receipt signer response accepted")
			}
		})
	}
}

func TestReceiptSignerClientPinsEverySignatureToStartupIdentity(t *testing.T) {
	expectedPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := time.UnixMilli(1_800_000_000_000).UTC()
	expiresAt := issuedAt.Add(time.Minute)
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			envelope, signErr := identity.Sign(
				wrongPrivate, protocol.ReceiptDomain, "receipt-key-1",
				[]byte("payload"), issuedAt, expiresAt,
			)
			if signErr != nil {
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(envelope)
		},
	))
	defer stop()
	config := DefaultReceiptSignerClientConfig(socketPath)
	config.ExpectedKeyID = "receipt-key-1"
	config.ExpectedPublicKey = base64.RawURLEncoding.EncodeToString(expectedPublic)
	client, err := NewReceiptSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SignReceipt(
		context.Background(), []byte("payload"), issuedAt, expiresAt,
	); err == nil {
		t.Fatal("accepted a signature from a key outside startup policy")
	}
}

func TestReceiptSignerClientBoundsTransportAndInputs(t *testing.T) {
	if _, err := NewReceiptSignerClient(ReceiptSignerClientConfig{}); err == nil {
		t.Fatal("empty signer configuration accepted")
	}
	partialIdentity := DefaultReceiptSignerClientConfig("/private/signer.sock")
	partialIdentity.ExpectedKeyID = "receipt-key"
	if _, err := NewReceiptSignerClient(partialIdentity); err == nil {
		t.Fatal("partial expected signer identity accepted")
	}
	partialIdentity.ExpectedPublicKey = "invalid"
	if _, err := NewReceiptSignerClient(partialIdentity); err == nil {
		t.Fatal("invalid expected signer public key accepted")
	}
	handlerStarted := make(chan struct{}, 1)
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			handlerStarted <- struct{}{}
			<-request.Context().Done()
			writer.WriteHeader(http.StatusGatewayTimeout)
		},
	))
	defer stop()
	config := DefaultReceiptSignerClientConfig(socketPath)
	config.Timeout = 20 * time.Millisecond
	client, err := NewReceiptSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := client.SignReceipt(
		context.Background(), []byte("payload"), now, now.Add(time.Minute),
	); err == nil {
		t.Fatal("signer timeout was ignored")
	}
	<-handlerStarted

	config = DefaultReceiptSignerClientConfig(socketPath)
	config.MaxMessageBytes = 64
	client, err = NewReceiptSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SignReceipt(
		context.Background(), make([]byte, 64), now, now.Add(time.Minute),
	); err == nil {
		t.Fatal("oversized signing request accepted")
	}
	if _, err := client.SignReceipt(
		context.Background(), nil, now, now,
	); err == nil {
		t.Fatal("invalid signing interval accepted")
	}

	if err := os.Chmod(socketPath, 0o666); err != nil {
		t.Fatal(err)
	}
	config = DefaultReceiptSignerClientConfig(socketPath)
	client, err = NewReceiptSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.SignReceipt(
		context.Background(), []byte("payload"), now, now.Add(time.Minute),
	); err == nil {
		t.Fatal("group/other-accessible signer socket accepted")
	}
}

func TestReceiptSignerClientBoundsConcurrentRequests(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var calls atomic.Int32
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			entered <- struct{}{}
			<-release
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusServiceUnavailable)
		},
	))
	defer stop()
	config := DefaultReceiptSignerClientConfig(socketPath)
	config.MaxConcurrent = 1
	client, err := NewReceiptSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	firstDone := make(chan error, 1)
	go func() {
		_, err := client.SignReceipt(
			context.Background(), []byte("first"), now, now.Add(time.Minute),
		)
		firstDone <- err
	}()
	<-entered
	waiting, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := client.SignReceipt(
		waiting, []byte("second"), now, now.Add(time.Minute),
	); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("concurrency wait error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("signer calls exceeded active bound: %d", calls.Load())
	}
	close(release)
	if err := <-firstDone; err == nil {
		t.Fatal("sidecar rejection was accepted")
	}
}

func TestReceiptSignerClientCloseCancelsAndRejectsRequests(t *testing.T) {
	entered := make(chan struct{}, 1)
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(_ http.ResponseWriter, request *http.Request) {
			entered <- struct{}{}
			<-request.Context().Done()
		},
	))
	defer stop()
	client, err := NewReceiptSignerClient(
		DefaultReceiptSignerClientConfig(socketPath),
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	done := make(chan error, 1)
	go func() {
		_, err := client.SignReceipt(
			context.Background(), []byte("active"), now, now.Add(time.Minute),
		)
		done <- err
	}()
	<-entered
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil || err.Error() != "receipt signer client is closed" {
			t.Fatalf("active close error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("client close did not cancel active signing")
	}
	if _, err := client.SignReceipt(
		context.Background(), []byte("new"), now, now.Add(time.Minute),
	); err == nil || err.Error() != "receipt signer client is closed" {
		t.Fatalf("closed client signing error=%v", err)
	}
	if err := client.CheckReady(context.Background()); err == nil ||
		err.Error() != "receipt signer client is closed" {
		t.Fatalf("closed client readiness error=%v", err)
	}
}

func TestReceiptSignerReadinessRejectsMalformedResponses(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityFields := `,"keyId":"receipt-key-1","publicKey":"` +
		base64.RawURLEncoding.EncodeToString(publicKey) +
		`","domain":"` + protocol.ReceiptDomain +
		`","path":"` + ReceiptSignerPath + `"`
	tests := []struct {
		name, contentType, body string
		status                  int
		wantSuccess             bool
	}{
		{"ready", "application/json", `{"status":"ready"` + identityFields + `}`, http.StatusOK, true},
		{"status", "application/json", `{"status":"ready"` + identityFields + `}`, http.StatusServiceUnavailable, false},
		{"media", "text/plain", `{"status":"ready"` + identityFields + `}`, http.StatusOK, false},
		{"wrong value", "application/json", `{"status":"starting"` + identityFields + `}`, http.StatusOK, false},
		{"missing identity", "application/json", `{"status":"ready"}`, http.StatusOK, false},
		{"duplicate", "application/json", `{"status":"ready","status":"ready"` + identityFields + `}`, http.StatusOK, false},
		{"unknown", "application/json", `{"status":"ready"` + identityFields + `,"detail":"secret"}`, http.StatusOK, false},
		{"wrong purpose", "application/json", strings.Replace(
			`{"status":"ready"`+identityFields+`}`,
			`"domain":"`+protocol.ReceiptDomain+`"`,
			`"domain":"`+protocol.QuoteDomain+`"`, 1,
		), http.StatusOK, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
				func(writer http.ResponseWriter, request *http.Request) {
					if request.Method != http.MethodGet || request.URL.Path != ReceiptSignerHealthPath {
						writer.WriteHeader(http.StatusNotFound)
						return
					}
					writer.Header().Set("Content-Type", test.contentType)
					writer.WriteHeader(test.status)
					_, _ = writer.Write([]byte(test.body))
				},
			))
			defer stop()
			client, err := NewReceiptSignerClient(DefaultReceiptSignerClientConfig(socketPath))
			if err != nil {
				t.Fatal(err)
			}
			err = client.CheckReady(context.Background())
			if (err == nil) != test.wantSuccess {
				t.Fatalf("CheckReady error=%v wantSuccess=%v", err, test.wantSuccess)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatalf("readiness leaked response detail: %v", err)
			}
		})
	}

	t.Run("expected identity", func(t *testing.T) {
		socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
			func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(`{"status":"ready"` + identityFields + `}`))
			},
		))
		defer stop()
		config := DefaultReceiptSignerClientConfig(socketPath)
		config.ExpectedKeyID = "wrong-key"
		config.ExpectedPublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
		client, err := NewReceiptSignerClient(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckReady(context.Background()); err == nil {
			t.Fatal("accepted a signer with the wrong expected identity")
		}
		otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		config.ExpectedKeyID = "receipt-key-1"
		config.ExpectedPublicKey = base64.RawURLEncoding.EncodeToString(otherPublicKey)
		client, err = NewReceiptSignerClient(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CheckReady(context.Background()); err == nil {
			t.Fatal("accepted a signer with the wrong expected public key")
		}
	})
}

func startReceiptSignerHTTPServer(
	t *testing.T,
	handler http.Handler,
) (string, func()) {
	t.Helper()
	directory, err := os.MkdirTemp("", "tos-sign-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "receipt-signer.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	var once sync.Once
	return socketPath, func() {
		once.Do(func() {
			_ = server.Close()
			_ = listener.Close()
			_ = os.Remove(socketPath)
		})
	}
}
