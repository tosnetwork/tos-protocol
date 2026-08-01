package receiptsigner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

var (
	_ authorization.QuoteSigner   = (*localrpc.QuoteSignerClient)(nil)
	_ authorization.ReceiptSigner = (*localrpc.ReceiptSignerClient)(nil)
)

func TestHandlerInteroperatesWithBoundedClient(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "receipt-key-1", PrivateKey: privateKey,
		MaxMessageBytes: DefaultMaxMessageBytes, MaxConcurrent: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "signer.sock")
	listener, err := ListenPrivateUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-serverDone
	})
	client, err := localrpc.NewReceiptSignerClient(
		func() localrpc.ReceiptSignerClientConfig {
			config := localrpc.DefaultReceiptSignerClientConfig(socketPath)
			config.ExpectedKeyID = "receipt-key-1"
			config.ExpectedPublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
			return config
		}(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.CheckReady(context.Background()); err != nil {
		t.Fatalf("signer readiness: %v", err)
	}
	issuedAt := time.UnixMilli(1_800_000_000_000)
	envelope, err := client.SignReceipt(
		context.Background(), []byte("canonical receipt"),
		issuedAt, issuedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "receipt-key-1" {
		t.Fatalf("unexpected signing key %q", envelope.KeyID)
	}
	if err := envelope.Verify(publicKey, protocol.ReceiptDomain, issuedAt); err != nil {
		t.Fatalf("invalid signed envelope: %v", err)
	}
}

func TestQuoteHandlerInteroperatesWithPurposeBoundClient(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "quote-key-1", PrivateKey: privateKey,
		MaxMessageBytes: DefaultMaxMessageBytes, MaxConcurrent: 4,
		Domain: protocol.QuoteDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory, "quote-signer.sock")
	listener, err := ListenPrivateUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-serverDone
	})
	config := localrpc.DefaultQuoteSignerClientConfig(socketPath)
	config.ExpectedKeyID = "quote-key-1"
	config.ExpectedPublicKey = base64.RawURLEncoding.EncodeToString(publicKey)
	client, err := localrpc.NewQuoteSignerClient(config)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.CheckReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	issuedAt := time.UnixMilli(1_800_000_000_000)
	envelope, err := client.SignQuote(
		context.Background(), []byte("canonical quote"),
		issuedAt, issuedAt.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.KeyID != "quote-key-1" ||
		envelope.Verify(publicKey, protocol.QuoteDomain, issuedAt) != nil {
		t.Fatal("quote signer returned an invalid purpose-bound envelope")
	}
	request := httptest.NewRequest(
		http.MethodPost, localrpc.ReceiptSignerPath, strings.NewReader(`{}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("quote signer exposed receipt path: %d", response.Code)
	}
}

func TestHandlerRejectsAmbiguousOrUnboundedRequests(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "receipt-key", PrivateKey: privateKey,
		MaxMessageBytes: 200, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid := `{"version":"1","payload":"eA==","issuedUnixMillis":1000,"expiresUnixMillis":2000}`
	cases := []struct {
		name, method, path, contentType, body string
		status                                int
	}{
		{"method", http.MethodGet, localrpc.ReceiptSignerPath, "application/json", valid, http.StatusMethodNotAllowed},
		{"path", http.MethodPost, "/other", "application/json", valid, http.StatusNotFound},
		{"media", http.MethodPost, localrpc.ReceiptSignerPath, "text/plain", valid, http.StatusUnsupportedMediaType},
		{"media parameter", http.MethodPost, localrpc.ReceiptSignerPath, "application/json; profile=unexpected", valid, http.StatusUnsupportedMediaType},
		{"query", http.MethodPost, localrpc.ReceiptSignerPath + "?purpose=other", "application/json", valid, http.StatusUnsupportedMediaType},
		{"duplicate", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", strings.Replace(valid, `"version":"1"`, `"version":"1","version":"1"`, 1), http.StatusBadRequest},
		{"unknown", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", strings.Replace(valid, `}`, `,"domain":"evil"}`, 1), http.StatusBadRequest},
		{"version", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", strings.Replace(valid, `"1"`, `"2"`, 1), http.StatusBadRequest},
		{"interval", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", strings.Replace(valid, "2000", "1000", 1), http.StatusBadRequest},
		{"response bound", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", valid, http.StatusInternalServerError},
		{"oversized", http.MethodPost, localrpc.ReceiptSignerPath, "application/json", strings.Repeat("x", 201), http.StatusRequestEntityTooLarge},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d want=%d body=%q", response.Code, test.status, response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("response is cacheable")
			}
		})
	}
}

func TestHandlerHealthHasNoSigningSideEffect(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "receipt-key", PrivateKey: privateKey,
		MaxMessageBytes: DefaultMaxMessageBytes, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, localrpc.ReceiptSignerHealthPath, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var health struct {
		Status, KeyID, PublicKey, Domain, Path string
	}
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil ||
		response.Code != http.StatusOK || health.Status != "ready" ||
		health.KeyID != "receipt-key" ||
		health.PublicKey != base64.RawURLEncoding.EncodeToString(publicKey) ||
		health.Domain != protocol.ReceiptDomain ||
		health.Path != localrpc.ReceiptSignerPath ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected health response: %d %q", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, localrpc.ReceiptSignerHealthPath, nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("health POST status=%d", response.Code)
	}
	for _, target := range []string{
		localrpc.ReceiptSignerHealthPath + "?detail=1",
		localrpc.ReceiptSignerHealthPath,
	} {
		var body *strings.Reader
		if target == localrpc.ReceiptSignerHealthPath {
			body = strings.NewReader("unexpected")
		} else {
			body = strings.NewReader("")
		}
		request = httptest.NewRequest(http.MethodGet, target, body)
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("ambiguous health request %q status=%d", target, response.Code)
		}
	}
}

func TestPrivateSeedAndSocketPermissions(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(seed) + "\n"
	seedPath := filepath.Join(directory, "receipt.seed")
	if err := os.WriteFile(seedPath, []byte(encoded), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadPrivateKey(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	want := ed25519.NewKeyFromSeed(seed)
	if !bytes.Equal(key, want) {
		t.Fatal("loaded a different private key")
	}
	if err := os.Chmod(seedPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(seedPath); err == nil {
		t.Fatal("accepted a group-readable seed")
	}
	if err := os.Chmod(seedPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "link.seed")
	if err := os.Symlink(seedPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKey(symlink); err == nil {
		t.Fatal("followed a seed symlink")
	}
	socketPath := filepath.Join(directory, "signer.sock")
	listener, err := ListenPrivateUnix(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(socketPath)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unexpected socket metadata: %v %v", info, err)
	}
	if _, err := ListenPrivateUnix(socketPath); err == nil {
		t.Fatal("replaced an existing socket")
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	publicDirectory := filepath.Join(directory, "public")
	if err := os.Mkdir(publicDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenPrivateUnix(filepath.Join(publicDirectory, "bad.sock")); err == nil {
		t.Fatal("accepted a public socket directory")
	}
}

func TestHandlerConfigurationBounds(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []Config{
		{},
		{KeyID: "key", PrivateKey: privateKey, MaxMessageBytes: MaxMessageBytes + 1, MaxConcurrent: 1},
		{KeyID: "key", PrivateKey: privateKey, MaxMessageBytes: 1, MaxConcurrent: MaxConcurrent + 1},
		{KeyID: "bad\x00key", PrivateKey: privateKey, MaxMessageBytes: 1, MaxConcurrent: 1},
		{KeyID: "key", PrivateKey: privateKey, MaxMessageBytes: 1, MaxConcurrent: 1, Domain: "tos.any.v1"},
	} {
		if _, err := NewHandler(config); err == nil {
			t.Fatal("accepted invalid handler configuration")
		}
	}
}

func TestHandlerCloseClearsKeyAndFailsClosed(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "receipt-key", PrivateKey: privateKey,
		MaxMessageBytes: DefaultMaxMessageBytes, MaxConcurrent: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyStorage := handler.privateKey
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	for index, value := range keyStorage {
		if value != 0 {
			t.Fatalf("private key byte %d was not cleared", index)
		}
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(
		health,
		httptest.NewRequest(http.MethodGet, localrpc.ReceiptSignerHealthPath, nil),
	)
	if health.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed health status=%d", health.Code)
	}
	request := httptest.NewRequest(
		http.MethodPost, localrpc.ReceiptSignerPath,
		strings.NewReader(`{"version":"1","payload":"eA==","issuedUnixMillis":1000,"expiresUnixMillis":2000}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed signing status=%d", response.Code)
	}
}

func TestHandlerCloseWaitsForSigningCriticalSection(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(Config{
		KeyID: "receipt-key", PrivateKey: privateKey,
		MaxMessageBytes: DefaultMaxMessageBytes, MaxConcurrent: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	handler.mutex.RLock()
	closeDone := make(chan error, 1)
	go func() { closeDone <- handler.Close() }()
	select {
	case err := <-closeDone:
		handler.mutex.RUnlock()
		t.Fatalf("close crossed the signing critical section: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	handler.mutex.RUnlock()
	if err := <-closeDone; err != nil {
		t.Fatal(err)
	}
	if _, _, ready := handler.identity(); ready {
		t.Fatal("closed handler retained signing identity")
	}
}

func TestLimitListenerBoundsIdleConnectionsAndCloses(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := LimitListener(base, 1)
	if err != nil {
		t.Fatal(err)
	}
	firstClient, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	firstServer, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	secondResult := make(chan net.Conn, 1)
	go func() {
		connection, _ := listener.Accept()
		secondResult <- connection
	}()
	secondClient, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondResult:
		t.Fatal("accepted more than the configured live-connection limit")
	case <-time.After(20 * time.Millisecond):
	}
	if err := firstServer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case secondServer := <-secondResult:
		if secondServer == nil {
			t.Fatal("second accept failed after a slot was released")
		}
		_ = secondServer.Close()
	case <-time.After(time.Second):
		t.Fatal("second accept did not resume")
	}
	_ = firstClient.Close()
	_ = secondClient.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LimitListener(base, 0); err == nil {
		t.Fatal("accepted a zero connection limit")
	}
}
