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

type discoveryService struct {
	atosnativev1connect.UnimplementedCapabilityDiscoveryServiceHandler
	testing *testing.T
}

func (s discoveryService) ListCapabilities(_ context.Context, request *connect.Request[nativev1.ListCapabilitiesRequest]) (*connect.Response[nativev1.ListCapabilitiesResponse], error) {
	if request.Header().Get("Authorization") != "Bearer relay-secret" {
		s.testing.Fatal("Native discovery client omitted its bearer token")
	}
	return connect.NewResponse(&nativev1.ListCapabilitiesResponse{}), nil
}

func (s discoveryService) SearchCapabilities(_ context.Context, request *connect.Request[nativev1.SearchCapabilitiesRequest]) (*connect.Response[nativev1.SearchCapabilitiesResponse], error) {
	if request.Header().Get("Authorization") != "Bearer relay-secret" {
		s.testing.Fatal("Native discovery client omitted its bearer token")
	}
	return connect.NewResponse(&nativev1.SearchCapabilitiesResponse{}), nil
}

func (s nativeService) ResolveNativeState(_ context.Context, request *connect.Request[nativev1.ResolveNativeStateRequest]) (*connect.Response[nativev1.ResolveNativeStateResponse], error) {
	if request.Header().Get("Authorization") != "Bearer relay-secret" {
		s.testing.Fatal("Native client omitted its bearer token")
	}
	return connect.NewResponse(&nativev1.ResolveNativeStateResponse{}), nil
}

func TestClientRequiresExplicitPlaintextAndAuthenticates(t *testing.T) {
	path, handler := atosnativev1connect.NewNativeServiceHandler(nativeService{testing: t})
	discoveryPath, discoveryHandler := atosnativev1connect.NewCapabilityDiscoveryServiceHandler(discoveryService{testing: t})
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	mux.Handle(discoveryPath, discoveryHandler)
	server := httptest.NewServer(mux)
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
	if _, err := client.ListCapabilities(context.Background(), &nativev1.ListCapabilitiesRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.SearchCapabilities(context.Background(), &nativev1.SearchCapabilitiesRequest{}); err != nil {
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
