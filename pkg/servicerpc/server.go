// Package servicerpc exposes the private Native-only Connect boundary.
package servicerpc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1/tosservicev1connect"
)

type Relayer interface {
	CheckReady(context.Context) error
	Submit(context.Context, *nativev1.SignedNativeActionV1, uint64) (string, error)
}

type Resolver interface {
	CheckReady(context.Context) error
	ResolveState(context.Context, string, string) (*nativev1.NativeStateV1, bool, error)
}

type Config struct {
	BearerToken      string
	NativeV1Relayer  Relayer
	NativeV1Resolver Resolver
	MaxMessageBytes  int
	CallTimeout      time.Duration
	Now              func() time.Time
}

type Server struct {
	token            string
	nativeV1Relayer  Relayer
	nativeV1Resolver Resolver
	maxMessageBytes  int
	callTimeout      time.Duration
	now              func() time.Time
}

func Open(config Config) (*Server, error) {
	config.BearerToken = strings.TrimSpace(config.BearerToken)
	if config.BearerToken == "" {
		return nil, errors.New("TOS Service RPC bearer token is required")
	}
	if config.NativeV1Relayer == nil || config.NativeV1Resolver == nil {
		return nil, errors.New("tos_service_v1 relayer and resolver are required")
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = 16 << 20
	}
	if config.MaxMessageBytes <= 0 || config.MaxMessageBytes > 64<<20 {
		return nil, errors.New("invalid TOS Service RPC message limit")
	}
	if config.CallTimeout == 0 {
		config.CallTimeout = 30 * time.Second
	}
	if config.CallTimeout <= 0 || config.CallTimeout > 15*time.Minute {
		return nil, errors.New("invalid TOS Service RPC call timeout")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	server := &Server{token: config.BearerToken, nativeV1Relayer: config.NativeV1Relayer, nativeV1Resolver: config.NativeV1Resolver,
		maxMessageBytes: config.MaxMessageBytes, callTimeout: config.CallTimeout, now: config.Now}
	ctx, cancel := context.WithTimeout(context.Background(), config.CallTimeout)
	defer cancel()
	if err := server.checkReady(ctx); err != nil {
		return nil, fmtError("tos_service_v1 is not ready", err)
	}
	return server, nil
}

func (s *Server) Close() error { return nil }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	options := []connect.HandlerOption{connect.WithReadMaxBytes(s.maxMessageBytes), connect.WithSendMaxBytes(s.maxMessageBytes)}
	path, handler := tosservicev1connect.NewNativeServiceHandler(s, options...)
	mux.Handle(path, handler)
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) { jsonStatus(w, http.StatusOK, `{"status":"ok"}`) })
	ready := func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.callTimeout)
		defer cancel()
		if err := s.checkReady(ctx); err != nil {
			jsonStatus(w, http.StatusServiceUnavailable, `{"status":"unavailable"}`)
			return
		}
		jsonStatus(w, http.StatusOK, `{"status":"ready"}`)
	}
	mux.HandleFunc("GET /readyz", ready)
	mux.HandleFunc("GET /healthz", ready)
	return s.authenticate(mux)
}

func (s *Server) checkReady(ctx context.Context) error {
	if s == nil || s.nativeV1Relayer == nil || s.nativeV1Resolver == nil {
		return errors.New("Native service is not configured")
	}
	if err := s.nativeV1Resolver.CheckReady(ctx); err != nil {
		return err
	}
	return s.nativeV1Relayer.CheckReady(ctx)
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/livez" || r.URL.Path == "/readyz" || r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		value, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(value)), []byte(s.token)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func jsonStatus(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}

func fmtError(message string, err error) error { return errors.New(message + ": " + err.Error()) }
