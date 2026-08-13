package atosrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"connectrpc.com/connect"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
)

// Server implements the ATOS trust/economic/proof/execution services,
// including the purpose-specific Managed financial-integrity anchor boundary,
// over one authenticated durable Edge boundary.
type Server struct {
	config           Config
	store            *store
	authority        Authority
	economy          economic.Driver
	worker           Worker
	router           Router
	thirdPartyWorker ThirdPartyWorker
	privateKey       ed25519.PrivateKey
	publicKey        ed25519.PublicKey
	signerID         string
	now              func() time.Time
	mutationMu       sync.Mutex
	jobLocks         sync.Map // job_id -> *sync.Mutex
	readinessMu      sync.Mutex
	readinessAt      time.Time
	readinessErr     error
}

func Open(config Config) (*Server, error) {
	config, err := config.withDefaults()
	if err != nil {
		return nil, err
	}
	readyContext, cancel := context.WithTimeout(context.Background(), config.CallTimeout)
	err = config.Authority.CheckReady(readyContext)
	cancel()
	if err != nil {
		_ = config.Authority.Close()
		if config.EconomicDriver != nil {
			_ = config.EconomicDriver.Close()
		}
		return nil, fmt.Errorf("ATOS RPC authority is not ready: %w", err)
	}
	if config.EconomicDriver != nil {
		readyContext, cancel = context.WithTimeout(context.Background(), config.CallTimeout)
		err = config.EconomicDriver.CheckReady(readyContext)
		cancel()
		if err != nil {
			_ = config.Authority.Close()
			_ = config.EconomicDriver.Close()
			return nil, fmt.Errorf("ATOS RPC economic driver is not ready: %w", err)
		}
	}
	state, err := openStore(config.StatePath, config.MaxRecordBytes)
	if err != nil {
		_ = config.Authority.Close()
		if config.EconomicDriver != nil {
			_ = config.EconomicDriver.Close()
		}
		return nil, err
	}
	privateKey, err := state.signingKey()
	if err != nil {
		_ = state.Close()
		_ = config.Authority.Close()
		if config.EconomicDriver != nil {
			_ = config.EconomicDriver.Close()
		}
		return nil, err
	}
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	digest := sha256.Sum256(publicKey)
	return &Server{
		config: config, store: state, authority: config.Authority,
		economy: config.EconomicDriver, worker: config.Worker, router: config.Router,
		thirdPartyWorker: config.ThirdPartyWorker,
		privateKey:       privateKey, publicKey: publicKey,
		signerID: "edge-signer-" + hex.EncodeToString(digest[:8]),
		now:      config.Now,
	}, nil
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var storeErr, authorityErr, economyErr error
	if s.store != nil {
		storeErr = s.store.Close()
	}
	if s.authority != nil {
		authorityErr = s.authority.Close()
	}
	if s.economy != nil {
		economyErr = s.economy.Close()
	}
	return errors.Join(storeErr, authorityErr, economyErr)
}

func (s *Server) supportsMode(mode TrustMode) bool {
	if s == nil || s.authority == nil || !s.authority.Supports(mode) {
		return false
	}
	switch mode {
	case TrustModeManaged:
		return true
	case TrustModeVerified:
		return s.economy != nil && s.economy.Supports(economic.TrustModeVerified)
	case TrustModeNative:
		return s.economy != nil && s.economy.Supports(economic.TrustModeNative)
	default:
		return false
	}
}

func (s *Server) ensureSupported(mode TrustMode) error {
	if !s.supportsMode(mode) {
		return failedPrecondition("TRUST_MODE_UNAVAILABLE", "requested trust mode is not active on this TOS authority and economic driver")
	}
	return nil
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
		pair(atostosv1connect.NewFinancialIntegrityServiceHandler(s, handlerOptions...)),
	} {
		mux.Handle(registered.path, registered.handler)
	}
	mux.HandleFunc("GET /livez", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	readiness := func(w http.ResponseWriter, r *http.Request) {
		// Client cancellation must not poison the shared readiness cache.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s.config.CallTimeout)
		defer cancel()
		if err := s.checkReady(ctx); err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	}
	mux.HandleFunc("GET /readyz", readiness)
	// /healthz remains the backwards-compatible readiness route used by ATOS.
	mux.HandleFunc("GET /healthz", readiness)
	return s.authenticate(mux)
}

func (s *Server) checkReady(ctx context.Context) error {
	if s == nil {
		return errors.New("server is not configured")
	}
	s.readinessMu.Lock()
	defer s.readinessMu.Unlock()
	now := time.Now()
	if !s.readinessAt.IsZero() && now.Sub(s.readinessAt) < 2*time.Second {
		return s.readinessErr
	}
	err := s.checkReadyUncached(ctx)
	if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		s.readinessAt, s.readinessErr = now, err
	}
	return err
}

func (s *Server) checkReadyUncached(ctx context.Context) error {
	if s.authority == nil {
		return errors.New("authority is not configured")
	}
	if err := s.authority.CheckReady(ctx); err != nil {
		return err
	}
	if s.economy != nil {
		if err := s.economy.CheckReady(ctx); err != nil {
			return err
		}
	}
	if s.worker != nil {
		if err := s.worker.CheckReady(ctx); err != nil {
			return err
		}
	}
	return nil
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
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" || r.URL.Path == "/livez" {
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
	bounded, cancel := context.WithDeadline(ctx, deadline)
	return bounded, cancel, nil
}
