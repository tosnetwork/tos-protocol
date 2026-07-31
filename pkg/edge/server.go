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
	descriptor []byte
	catalog    []byte
}

func NewServer(descriptor protocol.ServiceDescriptor, catalog ard.Catalog, now time.Time) (*Server, error) {
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
	return &Server{descriptor: descriptorJSON, catalog: catalogJSON}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeDocument(writer, []byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /.well-known/tos-service.json", func(writer http.ResponseWriter, _ *http.Request) {
		writeDocument(writer, s.descriptor)
	})
	mux.HandleFunc("GET /.well-known/ai-catalog.json", func(writer http.ResponseWriter, _ *http.Request) {
		writeDocument(writer, s.catalog)
	})
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(writer, request)
	})
}

func writeDocument(writer http.ResponseWriter, document []byte) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "public, max-age=60")
	writer.WriteHeader(http.StatusOK)
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
