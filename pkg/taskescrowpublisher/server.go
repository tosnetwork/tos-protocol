package taskescrowpublisher

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

const (
	ServerConfigVersion = "1"
	DefaultMaxBodyBytes = int64(512 << 10)
	maxBodyBytes        = int64(2 << 20)
)

type Config struct {
	Network      string
	StatePath    string
	Backend      Backend
	MaxBodyBytes int64
	Now          Clock
	Logger       *slog.Logger
}

type Server struct {
	network string
	backend Backend
	store   *actionStore
	maxBody int64
	now     Clock
	logger  *slog.Logger
	mu      sync.Mutex
	close   sync.Once
}

func Open(config Config) (*Server, error) {
	if strings.TrimSpace(config.Network) == "" || len(config.Network) > 64 || config.Backend == nil {
		return nil, errors.New("publisher network and backend are required")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if config.MaxBodyBytes <= 0 || config.MaxBodyBytes > maxBodyBytes {
		return nil, errors.New("publisher request size is outside bounds")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	state, err := openActionStore(config.StatePath)
	if err != nil {
		return nil, err
	}
	return &Server{
		network: config.Network, backend: config.Backend, store: state,
		maxBody: config.MaxBodyBytes, now: config.Now, logger: config.Logger,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(localrpc.TaskEscrowActionHealthPath, s.health)
	mux.HandleFunc(localrpc.TaskEscrowActionPath, s.publish)
	return mux
}

func (s *Server) CheckReady(ctx context.Context) error {
	if s == nil || s.backend == nil || s.store == nil {
		return errors.New("invalid task escrow publisher")
	}
	return s.backend.CheckReady(ctx)
}

func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	var result error
	s.close.Do(func() {
		result = errors.Join(s.store.close(), s.backend.Close())
	})
	return result
}

func (s *Server) health(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodGet {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
	defer cancel()
	if err := s.CheckReady(ctx); err != nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(writer).Encode(map[string]string{"status": "unavailable"})
		return
	}
	_ = json.NewEncoder(writer).Encode(map[string]string{
		"status": "ready", "version": chain.TaskEscrowActionVersion,
		"network": s.network, "path": localrpc.TaskEscrowActionPath,
	})
}

func (s *Server) publish(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !isJSONContentType(request.Header.Get("Content-Type")) {
		writePublisherError(writer, http.StatusUnsupportedMediaType)
		return
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, s.maxBody+1))
	if err != nil || int64(len(data)) > s.maxBody {
		writePublisherError(writer, http.StatusRequestEntityTooLarge)
		return
	}
	var action chain.TaskEscrowAction
	if err := jsonstrict.Decode(data, &action); err != nil {
		s.logger.Error("publisher rejected malformed action", "error", err)
		writePublisherError(writer, http.StatusBadRequest)
		return
	}
	if err := validateAction(action, s.network, s.now()); err != nil {
		s.logger.Error("publisher rejected invalid action", "action_id", action.ActionID, "kind", action.Kind, "error", err)
		writePublisherError(writer, http.StatusBadRequest)
		return
	}
	receipt, err := s.process(request.Context(), action)
	if err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, errActionConflict) {
			status = http.StatusConflict
		} else if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			status = http.StatusGatewayTimeout
		}
		s.logger.Error("publisher failed to process action", "action_id", action.ActionID, "kind", action.Kind, "error", err)
		writePublisherError(writer, status)
		return
	}
	_ = json.NewEncoder(writer).Encode(receipt)
}

var errActionConflict = errors.New("publisher action identity conflict")

func (s *Server) process(ctx context.Context, action chain.TaskEscrowAction) (chain.TaskEscrowActionReceipt, error) {
	// Key custody is intentionally serialized. Wallet seqno-based senders cannot
	// safely publish multiple independent mutations concurrently without a
	// separate nonce allocator.
	s.mu.Lock()
	defer s.mu.Unlock()

	stable := action
	stable.ExpiresUnixMillis = 0
	digest, err := codec.Digest("tos.task-escrow.publisher-action.v1", stable)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	record, err := s.store.get(action.ActionID)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	if record != nil {
		if record.SemanticDigest != digest {
			return chain.TaskEscrowActionReceipt{}, errActionConflict
		}
		if record.State == recordStateCompleted && record.Receipt != nil {
			return *record.Receipt, nil
		}
		if record.State != recordStatePending {
			return chain.TaskEscrowActionReceipt{}, errors.New("publisher state is invalid")
		}
	} else {
		prepared, prepareErr := s.backend.Prepare(ctx, action)
		if prepareErr != nil {
			return chain.TaskEscrowActionReceipt{}, prepareErr
		}
		now := s.now().UTC().UnixMilli()
		record = &actionRecord{
			Version: ServerConfigVersion, SemanticDigest: digest, State: recordStatePending,
			Action: stable, Prepared: prepared, CreatedAt: now, UpdatedAt: now,
		}
		if err := s.store.put(record); err != nil {
			return chain.TaskEscrowActionReceipt{}, err
		}
	}
	recovering := record.Attempts > 0
	record.Attempts++
	record.LastAttemptAt = s.now().UTC().UnixMilli()
	record.UpdatedAt = record.LastAttemptAt
	if err := s.store.put(record); err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	receipt, err := s.backend.Publish(ctx, action, record.Prepared, recovering)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID ||
		receipt.Network != action.Network || receipt.Kind != action.Kind ||
		receipt.EscrowID != action.EscrowID || receipt.ContractAddress != record.Prepared.ContractAddress ||
		strings.TrimSpace(receipt.Reference) == "" {
		return chain.TaskEscrowActionReceipt{}, errors.New("backend returned a substituted receipt")
	}
	record.State = recordStateCompleted
	record.Receipt = &receipt
	record.UpdatedAt = s.now().UTC().UnixMilli()
	if err := s.store.put(record); err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	return receipt, nil
}

func validateAction(action chain.TaskEscrowAction, network string, now time.Time) error {
	if action.Version != chain.TaskEscrowActionVersion || action.Network != network ||
		strings.TrimSpace(action.ActionID) == "" || len(action.ActionID) > 256 ||
		strings.TrimSpace(action.EscrowID) == "" || len(action.EscrowID) > 256 ||
		strings.TrimSpace(action.Creator) == "" || strings.TrimSpace(action.Agent) == "" ||
		strings.TrimSpace(action.Verifier) == "" || action.BudgetNanoTOS == 0 ||
		action.DeadlineUnix == 0 || action.ReviewPeriod < 3600 ||
		!validDigest(action.PolicyHash) || !validDigest(action.PermissionHash) ||
		action.ExpiresUnixMillis <= now.UTC().UnixMilli() {
		return errors.New("invalid task escrow action")
	}
	switch action.Kind {
	case chain.TaskEscrowActionDeploy:
		if action.ContractAddress != "" || action.FundingNanoTOS < action.BudgetNanoTOS {
			return errors.New("invalid deploy action")
		}
	case chain.TaskEscrowActionAccept, chain.TaskEscrowActionCancel,
		chain.TaskEscrowActionTimeout, chain.TaskEscrowActionReject:
		if action.ContractAddress == "" || action.QueryID == 0 || !validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid operation action")
		}
	case chain.TaskEscrowActionResult:
		if action.ContractAddress == "" || action.QueryID == 0 || !validDigest(action.ResultHash) ||
			!validDigest(action.EvidenceHash) || !validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid result action")
		}
	case chain.TaskEscrowActionDispute:
		if action.ContractAddress == "" || action.QueryID == 0 || !validDigest(action.DisputeHash) ||
			!validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid dispute action")
		}
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		if action.ContractAddress == "" || action.QueryID == 0 || action.PayoutNanoTOS > action.BudgetNanoTOS ||
			!validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid payout action")
		}
	default:
		return errors.New("unsupported task escrow action")
	}
	return nil
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func validCellHash(value string) bool {
	return strings.HasPrefix(value, "tvm-cell-sha256:") &&
		validDigest("sha256:"+strings.TrimPrefix(value, "tvm-cell-sha256:"))
}

func isJSONContentType(value string) bool {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || mediaType != "application/json" || len(params) > 1 {
		return false
	}
	charset := strings.ToLower(params["charset"])
	return len(params) == 0 || charset == "utf-8"
}

func writePublisherError(writer http.ResponseWriter, status int) {
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"error": http.StatusText(status)})
}
