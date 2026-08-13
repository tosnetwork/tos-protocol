package atosrpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

type nativeStub struct {
	readyErr  error
	submitted int
	resolved  int
}

func (s *nativeStub) CheckReady(context.Context) error { return s.readyErr }
func (s *nativeStub) Submit(context.Context, *nativev1.SignedNativeActionV1, uint64) (string, error) {
	s.submitted++
	return "sha256:test", nil
}
func (s *nativeStub) ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error) {
	s.resolved++
	return &nativev1.NativeStateV1{}, true, nil
}

func TestOpenRequiresOnlyNativeDependencies(t *testing.T) {
	stub := &nativeStub{}
	server, err := Open(Config{BearerToken: "secret", NativeV1Relayer: stub, NativeV1Resolver: stub})
	if err != nil {
		t.Fatal(err)
	}
	if server == nil {
		t.Fatal("server is nil")
	}
}

func TestHandlerProtectsRPCButNotHealth(t *testing.T) {
	stub := &nativeStub{}
	server, err := Open(Config{BearerToken: "secret", NativeV1Relayer: stub, NativeV1Resolver: stub})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/livez", "/readyz", "/healthz"} {
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Fatalf("%s status = %d", path, response.Code)
		}
	}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/atos.native.v1.NativeService/ResolveNativeState", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("RPC status = %d", response.Code)
	}
}

func TestNativeRequestContextFailsClosed(t *testing.T) {
	server := &Server{now: func() time.Time { return time.Unix(100, 0) }}
	request := connect.NewRequest(&nativev1.ResolveNativeStateRequest{})
	if _, err := server.ResolveNativeState(context.Background(), request); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("error = %v", err)
	}
}
