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
