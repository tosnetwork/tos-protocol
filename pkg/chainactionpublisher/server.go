package chainactionpublisher

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
)

const ProtocolVersion = "1"
const statePending, stateCompleted = "pending", "completed"

type Backend interface {
	CheckReady(context.Context) error
	Publish(context.Context, chain.Action, bool) (chain.ActionReceipt, error)
	Close() error
}
type Config struct {
	Network, StatePath string
	Backend            Backend
	MaxBodyBytes       int64
	Logger             *slog.Logger
}
type Server struct {
	network string
	backend Backend
	journal *journal
	maxBody int64
	logger  *slog.Logger
	mu      sync.Mutex
	once    sync.Once
}

func Open(c Config) (*Server, error) {
	if c.Network == "" || c.Backend == nil {
		return nil, errors.New("publisher network and backend required")
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 256 << 10
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 1<<20 {
		return nil, errors.New("invalid publisher body limit")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	j, err := openJournal(c.StatePath)
	if err != nil {
		return nil, err
	}
	return &Server{network: c.Network, backend: c.Backend, journal: j, maxBody: c.MaxBodyBytes, logger: c.Logger}, nil
}
func (s *Server) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc(localrpc.ChainActionHealthPath, s.health)
	m.HandleFunc(localrpc.ChainActionPath, s.publish)
	m.HandleFunc(localrpc.ChainActionResolvePath, s.resolve)
	return m
}
func (s *Server) CheckReady(ctx context.Context) error {
	if s == nil || s.journal == nil || s.backend == nil {
		return errors.New("invalid publisher")
	}
	return s.backend.CheckReady(ctx)
}
func (s *Server) Close() (err error) {
	if s == nil {
		return nil
	}
	s.once.Do(func() { err = errors.Join(s.journal.close(), s.backend.Close()) })
	return
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonHeader(w)
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	if s.CheckReady(r.Context()) != nil {
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "unavailable", "version": ProtocolVersion})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"status": "ready", "version": ProtocolVersion, "network": s.network, "publishPath": localrpc.ChainActionPath, "resolvePath": localrpc.ChainActionResolvePath, "journalVersion": JournalVersion, "capabilities": []string{"durable_intent_before_publish", "typed_action_not_found", "read_only_resolve"}})
}
func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	action, ok := s.decode(w, r)
	if !ok {
		return
	}
	receipt, err := s.process(r.Context(), action)
	if err != nil {
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ProtocolVersion, "code": "publisher_unavailable"})
		return
	}
	_ = json.NewEncoder(w).Encode(receipt)
}
func (s *Server) resolve(w http.ResponseWriter, r *http.Request) {
	action, ok := s.decode(w, r)
	if !ok {
		return
	}
	digest, _ := semanticDigest(action)
	rec, err := s.journal.get(action.ActionID)
	if err != nil {
		w.WriteHeader(503)
		return
	}
	if rec == nil {
		w.WriteHeader(404)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ProtocolVersion, "code": "action_not_found", "actionId": action.ActionID})
		return
	}
	if rec.Digest != digest {
		w.WriteHeader(409)
		return
	}
	if rec.State != stateCompleted || rec.Receipt == nil {
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(map[string]string{"version": ProtocolVersion, "code": "action_outcome_uncertain", "actionId": action.ActionID})
		return
	}
	_ = json.NewEncoder(w).Encode(rec.Receipt)
}
func (s *Server) decode(w http.ResponseWriter, r *http.Request) (chain.Action, bool) {
	jsonHeader(w)
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return chain.Action{}, false
	}
	mt, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || mt != "application/json" {
		w.WriteHeader(415)
		return chain.Action{}, false
	}
	raw, e := io.ReadAll(io.LimitReader(r.Body, s.maxBody+1))
	if e != nil || int64(len(raw)) > s.maxBody {
		w.WriteHeader(413)
		return chain.Action{}, false
	}
	var a chain.Action
	if jsonstrict.Decode(raw, &a) != nil || validate(a, s.network) != nil {
		w.WriteHeader(400)
		return chain.Action{}, false
	}
	return a, true
}
func (s *Server) process(ctx context.Context, a chain.Action) (chain.ActionReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, _ := semanticDigest(a)
	rec, err := s.journal.get(a.ActionID)
	if err != nil {
		return chain.ActionReceipt{}, err
	}
	if rec == nil {
		stable := a
		stable.ExpiresUnixMillis = 0
		rec = &record{Version: JournalVersion, Digest: digest, State: statePending, Action: stable}
		if err = s.journal.put(rec); err != nil {
			return chain.ActionReceipt{}, err
		}
	} else if rec.Digest != digest {
		return chain.ActionReceipt{}, errors.New("action conflict")
	} else if rec.State == stateCompleted && rec.Receipt != nil {
		return *rec.Receipt, nil
	}
	rec.Attempts++
	if err = s.journal.put(rec); err != nil {
		return chain.ActionReceipt{}, err
	}
	receipt, err := s.backend.Publish(ctx, a, rec.Attempts > 1)
	if err != nil {
		return chain.ActionReceipt{}, err
	}
	if validateReceipt(a, receipt) != nil {
		return chain.ActionReceipt{}, errors.New("backend substituted receipt")
	}
	rec.State = stateCompleted
	rec.Receipt = &receipt
	if err = s.journal.put(rec); err != nil {
		return chain.ActionReceipt{}, err
	}
	return receipt, nil
}
func semanticDigest(a chain.Action) (string, error) {
	a.ExpiresUnixMillis = 0
	return codec.Digest("tos.chain-action.publisher.v1", a)
}
func validate(a chain.Action, network string) error {
	anchorDigest, ok := strings.CutPrefix(a.ActionID, "anchor-")
	if !ok || len(anchorDigest) != 64 || a.Comment != "atos:v1:"+anchorDigest ||
		a.Version != chain.ChainActionVersion || a.Network != network || a.Kind != chain.ActionKindAnchor ||
		a.ObjectID == "" || a.Digest == "" || a.Payer == "" || a.Payee == "" ||
		a.AmountNanoTOS == 0 || a.ExpiresUnixMillis <= time.Now().Add(-time.Minute).UnixMilli() {
		return errors.New("invalid action")
	}
	return nil
}
func validateReceipt(a chain.Action, r chain.ActionReceipt) error {
	if r.Version != a.Version || r.ActionID != a.ActionID || r.Network != a.Network || r.Kind != a.Kind || r.ObjectID != a.ObjectID || r.Digest != a.Digest || r.Payer != a.Payer || r.Payee != a.Payee || r.AmountNanoTOS != a.AmountNanoTOS || r.Comment != a.Comment || strings.TrimSpace(r.Reference) == "" {
		return errors.New("receipt mismatch")
	}
	return nil
}
func jsonHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
}
