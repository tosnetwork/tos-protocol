package nativeregistrypublisher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
)

const (
	ActionPath          = "/v1/native/registry/action"
	ResolvePath         = "/v1/native/registry/action/resolve"
	HealthPath          = "/healthz"
	ProtocolVersion     = "tos.native.registry-publisher.v1"
	DefaultMaxBodyBytes = int64(256 << 10)
)

type Server struct {
	publisher *Publisher
	maxBody   int64
}
type wireRequest struct {
	ActionID       string                    `json:"action_id"`
	SemanticDigest string                    `json:"semantic_digest"`
	Submission     nativeregistry.Submission `json:"submission"`
}

func NewServer(publisher *Publisher, maxBody int64) (*Server, error) {
	if publisher == nil {
		return nil, errors.New("native registry publisher is required")
	}
	if maxBody == 0 {
		maxBody = DefaultMaxBodyBytes
	}
	if maxBody <= 0 || maxBody > 2<<20 {
		return nil, errors.New("invalid native registry body limit")
	}
	return &Server{publisher: publisher, maxBody: maxBody}, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(HealthPath, s.health)
	mux.HandleFunc(ActionPath, s.publish)
	mux.HandleFunc(ResolvePath, s.resolve)
	return mux
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.publisher.CheckReady(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unavailable"})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready", "version": ProtocolVersion, "path": ActionPath, "resolve_path": ResolvePath, "journal_identity": s.publisher.store.identity, "journal_binding": s.publisher.store.binding})
}
func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	request, ok := s.read(w, r)
	if !ok {
		return
	}
	if err := s.publisher.Publish(r.Context(), request.Submission, request.ActionID, request.SemanticDigest); err != nil {
		slog.Error("Native registry publisher mutation is ambiguous", "action_id", request.ActionID, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(s.boundResponse("action_outcome_uncertain", "", request.ActionID))
		return
	}
	_ = json.NewEncoder(w).Encode(s.boundResponse("", "accepted", request.ActionID))
}
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	request, ok := s.read(w, r)
	if !ok {
		return
	}
	err := s.publisher.Resolve(r.Context(), request.Submission, request.ActionID, request.SemanticDigest)
	if errors.Is(err, nativeregistry.ErrPublisherPending) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(s.boundResponse("action_pending", "", request.ActionID))
		return
	}
	if errors.Is(err, nativeregistry.ErrPublisherNotFound) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(s.boundResponse("action_not_found", "", request.ActionID))
		return
	}
	if err != nil {
		slog.Error("Native registry publisher resolution is ambiguous", "action_id", request.ActionID, "error", err)
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(s.boundResponse("action_outcome_uncertain", "", request.ActionID))
		return
	}
	_ = json.NewEncoder(w).Encode(s.boundResponse("", "completed", request.ActionID))
}
func (s *Server) boundResponse(code, status, actionID string) map[string]string {
	return map[string]string{
		"version":          ProtocolVersion,
		"code":             code,
		"status":           status,
		"action_id":        actionID,
		"journal_identity": s.publisher.store.identity,
		"journal_binding":  s.publisher.store.binding,
	}
}
func (s *Server) read(w http.ResponseWriter, r *http.Request) (wireRequest, bool) {
	jsonHeader(w)
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return wireRequest{}, false
	}
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return wireRequest{}, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
	if err != nil || int64(len(raw)) > s.maxBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return wireRequest{}, false
	}
	var request wireRequest
	if jsonstrict.Decode(raw, &request) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return wireRequest{}, false
	}
	id, digest, err := nativeregistry.ValidateSubmission(request.Submission)
	if err != nil || id != request.ActionID || digest != request.SemanticDigest {
		w.WriteHeader(http.StatusBadRequest)
		return wireRequest{}, false
	}
	return request, true
}
func jsonHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
}
