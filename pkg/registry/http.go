package registry

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
)

const maxSearchBodyBytes = 64 << 10

type Handler struct {
	index          *Index
	registrySource string
	requests       chan struct{}
}

func NewHandler(index *Index, registrySource string) (*Handler, error) {
	if index == nil {
		return nil, errors.New("nil Registry index")
	}
	if registrySource == "" || len(registrySource) > 2048 || strings.ContainsRune(registrySource, '\x00') {
		return nil, errors.New("registry source URL is required")
	}
	return &Handler{
		index: index, registrySource: registrySource,
		requests: make(chan struct{}, index.limits.MaxConcurrentRequests),
	}, nil
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /search", h.limit(http.HandlerFunc(h.search)))
	mux.Handle("GET /agents", h.limit(http.HandlerFunc(h.list)))
	mux.HandleFunc("GET /healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
	})
	return securityHeaders(mux)
}

func (h *Handler) limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		select {
		case h.requests <- struct{}{}:
			defer func() { <-h.requests }()
			next.ServeHTTP(writer, request)
		default:
			writer.Header().Set("Retry-After", "1")
			writeError(
				writer, http.StatusServiceUnavailable, "RESOURCE_EXHAUSTED",
				"Registry request capacity exhausted",
			)
		}
	})
}

func (h *Handler) search(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", "search query parameters are not supported")
		return
	}
	if request.Header.Get("Content-Encoding") != "" {
		writeError(writer, http.StatusUnsupportedMediaType, "INVALID_ARGUMENT", "Content-Encoding is not supported")
		return
	}
	contentType, parameters, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	charset := strings.ToLower(parameters["charset"])
	if err != nil || contentType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) {
		writeError(writer, http.StatusUnsupportedMediaType, "INVALID_ARGUMENT", "Content-Type must be application/json")
		return
	}
	var input SearchRequest
	if err := decodeJSONBody(request.Body, &input); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	response, err := h.index.Search(input, h.registrySource)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func (h *Handler) list(writer http.ResponseWriter, request *http.Request) {
	if err := validateListQuery(request); err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	pageSize, err := ParsePageSize(request.URL.Query().Get("pageSize"))
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	response, err := h.index.ListQuery(ListRequest{
		Filter:    request.URL.Query().Get("filter"),
		OrderBy:   request.URL.Query().Get("orderBy"),
		PageSize:  pageSize,
		PageToken: request.URL.Query().Get("pageToken"),
	})
	if err != nil {
		writeError(writer, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	writeJSON(writer, http.StatusOK, response)
}

func validateListQuery(request *http.Request) error {
	allowed := map[string]struct{}{
		"filter": {}, "orderBy": {}, "pageSize": {}, "pageToken": {},
	}
	for key, values := range request.URL.Query() {
		if _, ok := allowed[key]; !ok {
			return errors.New("unsupported list query parameter")
		}
		if len(values) != 1 {
			return errors.New("duplicate list query parameter")
		}
	}
	return nil
}

func decodeJSONBody(reader io.Reader, output interface{}) error {
	limited := io.LimitReader(reader, maxSearchBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return errors.New("read request body")
	}
	if len(data) > maxSearchBodyBytes {
		return errors.New("request body too large")
	}
	if err := jsonstrict.Decode(data, output); err != nil {
		return errors.New("invalid JSON request")
	}
	return nil
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writeJSON(writer, status, map[string]string{"errorCode": code, "message": message})
}

func writeJSON(writer http.ResponseWriter, status int, value interface{}) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Cache-Control", "no-store")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(writer, request)
	})
}

func NewHTTPServer(address string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
}
