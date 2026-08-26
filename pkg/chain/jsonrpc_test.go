package chain

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientPropagatesRPCError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"unavailable"}}`))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, time.Second, 1024)
	err := client.Call(context.Background(), "getSomething", nil, nil)
	var rpcError *RPCError
	if !errors.As(err, &rpcError) || rpcError.Message != "unavailable" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientAcceptsTOSSuccessEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true,"jsonrpc":"2.0","id":1,"result":{"height":7}}`))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, time.Second, 1024)
	var result struct {
		Height uint64 `json:"height"`
	}
	if err := client.Call(context.Background(), "getHeight", nil, &result); err != nil {
		t.Fatal(err)
	}
	if result.Height != 7 {
		t.Fatalf("height = %d", result.Height)
	}
}

func TestClientPropagatesTOSErrorEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":false,"jsonrpc":"2.0","id":1,"error":"cannot locate transaction","code":-32603}`))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, time.Second, 1024)
	err := client.Call(context.Background(), "getTransactions", nil, nil)
	var rpcError *RPCError
	if !errors.As(err, &rpcError) || rpcError.Code != -32603 ||
		rpcError.Message != "cannot locate transaction" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestClientBoundsResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 65)))
	}))
	defer server.Close()

	client, _ := NewClient(server.URL, time.Second, 64)
	if err := client.Call(context.Background(), "getSomething", nil, nil); err == nil {
		t.Fatal("oversized response accepted")
	}
}

func TestClientRejectsRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	client, _ := NewClient(redirect.URL, time.Second, 1024)
	if err := client.Call(context.Background(), "getSomething", nil, nil); err == nil {
		t.Fatal("JSON-RPC redirect accepted")
	}
}

func TestClientRejectsAmbiguousOrMismatchedResponses(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "duplicate key",
			body: `{"jsonrpc":"2.0","id":1,"id":2,"result":{}}`,
		},
		{
			name: "mismatched id",
			body: `{"jsonrpc":"2.0","id":2,"result":{}}`,
		},
		{
			name: "result and error",
			body: `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"failed"}}`,
		},
		{
			name: "missing result and error",
			body: `{"jsonrpc":"2.0","id":1}`,
		},
		{
			name: "false ok without error",
			body: `{"ok":false,"jsonrpc":"2.0","id":1}`,
		},
		{
			name: "string error without code",
			body: `{"ok":false,"jsonrpc":"2.0","id":1,"error":"failed"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(test.body))
			}))
			defer server.Close()

			client, err := NewClient(server.URL, time.Second, 1024)
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]interface{}
			if err := client.Call(context.Background(), "getSomething", nil, &result); err == nil {
				t.Fatal("invalid JSON-RPC response accepted")
			}
		})
	}
}

func TestClientStrictlyDecodesResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"height":7,"height":8}}`))
	}))
	defer server.Close()

	client, err := NewClient(server.URL, time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Height uint64 `json:"height"`
	}
	if err := client.Call(context.Background(), "getHeight", nil, &result); err == nil {
		t.Fatal("ambiguous JSON-RPC result accepted")
	}
}

func TestClientDoesNotUseAmbientProxy(t *testing.T) {
	client, err := NewClient("https://chain.example.invalid", time.Second, 1024)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("owner-pinned chain RPC client permits ambient proxy redirection")
	}
}
