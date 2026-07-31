// Package edge provides the public, generic Edge Core HTTP surface. The
// bootstrap serves discovery only and intentionally has no invocation route.
package edge

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

type Server struct {
	descriptor          []byte
	descriptorExpiresAt time.Time
	catalog             []byte
	now                 func() time.Time
	core                *Core
}

func NewServer(descriptor protocol.ServiceDescriptor, catalog ard.Catalog, now time.Time) (*Server, error) {
	return newServer(descriptor, catalog, now, nil)
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
	return newServer(descriptor, catalog, now, core)
}

func newServer(
	descriptor protocol.ServiceDescriptor,
	catalog ard.Catalog,
	now time.Time,
	core *Core,
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
		core:                core,
	}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		if s.core != nil {
			if _, err := s.core.Health(); err != nil {
				writeDocument(
					writer,
					[]byte(`{"status":"degraded","component":"request-journal"}`),
					"application/json", "no-store", http.StatusServiceUnavailable,
				)
				return
			}
		}
		writeDocument(
			writer, []byte(`{"status":"ok"}`),
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
