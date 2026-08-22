package servicerpc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/publicerrors"
)

type nativeStub struct {
	readyErr  error
	submitted int
	resolved  int
}

type dnsAliasStub struct{ calls int }

func (s *dnsAliasStub) ResolveDNSAlias(_ context.Context, request *nativev1.ResolveDNSAliasRequest) (*nativev1.ResolveDNSAliasResponse, error) {
	s.calls++
	return &nativev1.ResolveDNSAliasResponse{CanonicalName: request.Name, Kind: request.Kind}, nil
}

func TestNativeProtocolErrorsCarryStableTypedDetail(t *testing.T) {
	cause := &nativecore.ProtocolError{Code: nativecore.ErrBadSequence, Message: "test diagnostic"}
	err := nativeConnectError(connect.CodeFailedPrecondition, cause, publicerrors.AmbiguousOutcome)
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) || len(connectErr.Details()) != 1 {
		t.Fatalf("error = %v", err)
	}
	value, detailErr := connectErr.Details()[0].Value()
	if detailErr != nil {
		t.Fatal(detailErr)
	}
	detail, ok := value.(*nativev1.NativeErrorV1)
	if !ok || detail.Code != nativev1.NativeErrorCodeV1_NATIVE_ERROR_CODE_V1_BAD_SEQUENCE ||
		detail.Identifier != "NATIVE_BAD_SEQUENCE" || detail.RetryDisposition != nativev1.RetryDispositionV1_RETRY_DISPOSITION_V1_NEVER {
		t.Fatalf("detail = %#v", value)
	}
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
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/tos.service.v1.NativeService/ResolveNativeState", nil))
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

func TestDNSAliasBoundaryRequiresAuthAndCompleteContext(t *testing.T) {
	native := &nativeStub{}
	dns := &dnsAliasStub{}
	server, err := Open(Config{BearerToken: "secret", NativeV1Relayer: native, NativeV1Resolver: native, DNSAliasResolver: dns,
		Now: func() time.Time { return time.Unix(100, 0) }})
	if err != nil {
		t.Fatal(err)
	}
	request := connect.NewRequest(&nativev1.ResolveDNSAliasRequest{Name: "alice.tos", Kind: nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT})
	if _, err := server.ResolveDNSAlias(context.Background(), request); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("incomplete context error = %v", err)
	}
	if dns.calls != 0 {
		t.Fatal("invalid DNS request reached resolver")
	}

	path := "/tos.service.v1.DNSAliasService/ResolveDNSAlias"
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated DNS RPC status = %d", response.Code)
	}
	if serverWithoutDNS, err := Open(Config{BearerToken: "secret", NativeV1Relayer: native, NativeV1Resolver: native}); err != nil {
		t.Fatal(err)
	} else {
		response = httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		serverWithoutDNS.Handler().ServeHTTP(response, req)
		if response.Code != http.StatusNotFound {
			t.Fatalf("unconfigured DNS service status = %d", response.Code)
		}
	}
}
