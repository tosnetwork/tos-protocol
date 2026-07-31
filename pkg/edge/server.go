// Package edge provides the public, generic Edge Core HTTP surface. The
// bootstrap serves discovery only and intentionally has no invocation route.
package edge

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	readinessCheckTimeout = 8 * time.Second
	readinessCacheTTL     = time.Second
)

var errReadinessProbeBusy = errors.New("readiness probe already in progress")

// ReadinessChecker represents an external startup dependency. It must make no
// authorization decision; readiness is only an operational availability
// signal and is always rechecked by the real request path.
type ReadinessChecker interface {
	CheckReady(context.Context) error
}

type ServerDependencies struct {
	Core           *Core
	ChainReadiness ReadinessChecker
}

type readinessGate struct {
	checker ReadinessChecker
	mu      sync.Mutex
	running bool
	checked time.Time
	err     error
}

func newReadinessGate(checker ReadinessChecker) *readinessGate {
	if checker == nil {
		return nil
	}
	return &readinessGate{checker: checker}
}

func (gate *readinessGate) check(ctx context.Context, now time.Time) error {
	gate.mu.Lock()
	if !gate.checked.IsZero() && now.Sub(gate.checked) >= 0 &&
		now.Sub(gate.checked) < readinessCacheTTL {
		err := gate.err
		gate.mu.Unlock()
		return err
	}
	if gate.running {
		gate.mu.Unlock()
		return errReadinessProbeBusy
	}
	gate.running = true
	gate.mu.Unlock()

	err := gate.checker.CheckReady(ctx)
	gate.mu.Lock()
	gate.running = false
	gate.checked = now
	gate.err = err
	gate.mu.Unlock()
	return err
}

type Server struct {
	descriptor          []byte
	descriptorExpiresAt time.Time
	catalog             []byte
	now                 func() time.Time
	core                *Core
	chainReadiness      *readinessGate
}

func NewServer(descriptor protocol.ServiceDescriptor, catalog ard.Catalog, now time.Time) (*Server, error) {
	return newServer(descriptor, catalog, now, ServerDependencies{})
}

func NewServerWithCore(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	core *Core,
) (*Server, error) {
	if core == nil {
		return nil, errors.New("nil Edge Core")
	}
	return newServer(descriptor, catalog, now, ServerDependencies{Core: core})
}

func NewServerWithDependencies(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	dependencies ServerDependencies,
) (*Server, error) {
	return newServer(descriptor, catalog, now, dependencies)
}

func newServer(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	dependencies ServerDependencies,
) (*Server, error) {
	if err := descriptor.Validate(now); err != nil {
		return nil, err
	}
	if err := catalog.Validate(ard.DefaultLimits()); err != nil {
		return nil, err
	}
	descriptorJSON, err := json.Marshal(descriptor)
	if err != nil {
		return nil, err
	}
	catalogJSON, err := json.Marshal(catalog)
	if err != nil {
		return nil, err
	}
	if len(descriptorJSON) > 256<<10 {
		return nil, errors.New("descriptor exceeds byte limit")
	}
	return &Server{
		descriptor:          descriptorJSON,
		descriptorExpiresAt: descriptor.ExpiresAt,
		catalog:             catalogJSON,
		now:                 time.Now,
		core:                dependencies.Core,
		chainReadiness:      newReadinessGate(dependencies.ChainReadiness),
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		if !s.writeLiveness(writer) {
			return
		}
		writeDocument(
			writer, []byte(`{"status":"ok"}`),
			"application/json", "no-store", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /readyz", func(writer http.ResponseWriter, request *http.Request) {
		if !s.writeCoreReadiness(writer) {
			return
		}
		if s.chainReadiness != nil {
			ctx, cancel := context.WithTimeout(request.Context(), readinessCheckTimeout)
			err := s.chainReadiness.check(ctx, s.now())
			cancel()
			if err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"tos-chain"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		writeDocument(
			writer, []byte(`{"status":"ready"}`),
			"application/json", "no-store", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /.well-known/tos-service.json", func(writer http.ResponseWriter, _ *http.Request) {
		if !s.descriptorExpiresAt.After(s.now()) {
			writeDocument(
				writer, []byte(`{"error":"service descriptor expired"}`),
				"application/json", "no-store", http.StatusServiceUnavailable,
			)
			return
		}
		writeDocument(
			writer, s.descriptor, ard.TOSServiceDescriptorMediaType,
			"public, max-age=60, must-revalidate", http.StatusOK,
		)
	})
	mux.HandleFunc("GET /.well-known/ai-catalog.json", func(writer http.ResponseWriter, _ *http.Request) {
		writeDocument(
			writer, s.catalog, "application/json",
			"public, max-age=60, must-revalidate", http.StatusOK,
		)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(writer, request)
	})
}

func (s *Server) writeLiveness(writer http.ResponseWriter) bool {
	if s.core == nil {
		return true
	}
	if _, err := s.core.Liveness(); err != nil {
		writeDocument(
			writer,
			[]byte(`{"status":"degraded","component":"request-journal"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return false
	}
	return true
}

func (s *Server) writeCoreReadiness(writer http.ResponseWriter) bool {
	if s.core == nil {
		return true
	}
	if _, err := s.core.Health(); err != nil {
		writeDocument(
			writer,
			[]byte(`{"status":"degraded","component":"edge-core"}`),
			"application/json", "no-store", http.StatusServiceUnavailable,
		)
		return false
	}
	return true
}

func writeDocument(
	writer http.ResponseWriter,
	document []byte,
	contentType, cacheControl string,
	status int,
) {
	writer.Header().Set("Content-Type", contentType)
	writer.Header().Set("Cache-Control", cacheControl)
	writer.WriteHeader(status)
	_, _ = writer.Write(document)
}

func NewHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
