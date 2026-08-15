package nativeclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/native/v1/atosnativev1connect"
)

type nativeService struct {
	atosnativev1connect.UnimplementedNativeServiceHandler
	testing *testing.T
}

func (s nativeService) ResolveNativeState(_ context.Context, request *connect.Request[nativev1.ResolveNativeStateRequest]) (*connect.Response[nativev1.ResolveNativeStateResponse], error) {
	if request.Header().Get("Authorization") != "Bearer relay-secret" {
		s.testing.Fatal("Native client omitted its bearer token")
	}
	return connect.NewResponse(&nativev1.ResolveNativeStateResponse{}), nil
}

func TestClientRequiresExplicitPlaintextAndAuthenticates(t *testing.T) {
	path, handler := atosnativev1connect.NewNativeServiceHandler(nativeService{testing: t})
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path[:len(path)] != path {
			t.Fatal("unexpected Native path")
		}
		handler.ServeHTTP(writer, request)
	}))
	defer server.Close()
	if _, err := New(Config{BaseURL: server.URL, BearerToken: "relay-secret"}); err == nil {
		t.Fatal("plaintext Native gateway accepted implicitly")
	}
	client, err := New(Config{BaseURL: server.URL, BearerToken: "relay-secret", Insecure: true})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.ResolveNativeState(context.Background(), &nativev1.ResolveNativeStateRequest{}); err != nil {
		t.Fatal(err)
	}
}

func TestClientRejectsAmbiguousConfiguration(t *testing.T) {
	for _, config := range []Config{
		{},
		{BaseURL: "https://user@example.com", BearerToken: "token"},
		{BaseURL: "https://example.com/path", BearerToken: "token"},
		{BaseURL: "https://example.com", BearerToken: "token", ClientCertFile: "cert"},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("unsafe config accepted: %+v", config)
		}
	}
}
