package atosrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
)

// Server implements Identity, Capability, Trust, Settlement, Proof, and
// ExecutionGateway services over one authenticated durable Edge boundary.
type Server struct {
	config     Config
	store      *store
	authority  Authority
	worker     Worker
	router     Router
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	signerID   string
	now        func() time.Time
	mutationMu sync.Mutex
	jobLocks   sync.Map // job_id -> *sync.Mutex
}

func Open(config Config) (*Server, error) {
	config, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	state, err := openStore(config.StatePath, config.MaxRecordBytes)
	if err != nil {
		return nil, err
	}
	privateKey, err := state.signingKey()
	if err != nil {
		state.Close()
		return nil, err
	}
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(publicKey)
	return &Server{
		config: config, store: state, authority: config.Authority,
		worker: config.Worker, router: config.Router,
		privateKey: privateKey, publicKey: publicKey,
		signerID: "edge-signer-" + hex.EncodeToString(digest[:8]),
		now:      config.Now,
	}, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	return s.store.Close()
}

func (s *Server) jobLock(jobID string) *sync.Mutex {
	value, _ := s.jobLocks.LoadOrStore(jobID, &sync.Mutex{})
	return value.(*sync.Mutex)
}

// Handler mounts all six ConnectRPC services. Bearer authentication is
// enforced before request bytes are decoded, and message sizes are bounded.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	handlerOptions := []connect.HandlerOption{
		connect.WithReadMaxBytes(s.config.MaxMessageBytes),
		connect.WithSendMaxBytes(s.config.MaxMessageBytes),
	}
	for _, registered := range []struct {
		path    string
		handler http.Handler
	}{
		pair(atostosv1connect.NewIdentityServiceHandler(s, handlerOptions...)),
		pair(atostosv1connect.NewCapabilityServiceHandler(s, handlerOptions...)),
		pair(atostosv1connect.NewTrustServiceHandler(s, handlerOptions...)),
		pair(atostosv1connect.NewSettlementServiceHandler(s, handlerOptions...)),
		pair(atostosv1connect.NewProofServiceHandler(s, handlerOptions...)),
		pair(atostosv1connect.NewExecutionGatewayServiceHandler(s, handlerOptions...)),
	} {
		mux.Handle(registered.path, registered.handler)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	return s.authenticate(mux)
}

func pair(path string, handler http.Handler) struct {
	path    string
	handler http.Handler
} {
	return struct {
		path    string
		handler http.Handler
	}{path: path, handler: handler}
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	expected := []byte(s.config.BearerToken)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		authorization := strings.TrimSpace(r.Header.Get("Authorization"))
		provided := strings.TrimSpace(strings.TrimPrefix(authorization, "Bearer "))
		if len(provided) != len(expected) || subtle.ConstantTimeCompare([]byte(provided), expected) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) boundedContext(ctx context.Context, requestedDeadlineMS int64) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil RPC context")
	}
	deadline := s.now().Add(s.config.CallTimeout)
	if requestedDeadlineMS > 0 {
		requested := time.UnixMilli(requestedDeadlineMS)
		if requested.Before(deadline) {
			deadline = requested
		}
	}
	if !s.now().Before(deadline) {
		return nil, nil, rpcError(connect.CodeDeadlineExceeded, "DEADLINE_EXCEEDED", "request deadline has elapsed")
	}
	return context.WithDeadline(ctx, deadline)
}
