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
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	ServerConfigVersion = "1"
	DefaultMaxBodyBytes = int64(512 << 10)
	maxBodyBytes        = int64(2 << 20)
)

type Config struct {
	Network         string
	StatePath       string
	JournalIdentity string
	Backend         Backend
	MaxBodyBytes    int64
	Now             Clock
	Logger          *slog.Logger
	Policy          PublisherPolicy
}

type PublisherPolicy struct {
	AllowedCreators     []string `json:"allowedCreators"`
	AllowedAgents       []string `json:"allowedAgents"`
	AllowedVerifiers    []string `json:"allowedVerifiers"`
	AllowedPolicyHashes []string `json:"allowedPolicyHashes"`
	AllowedCodeHashes   []string `json:"allowedCodeHashes"`
	MaxBudgetNanoTOS    uint64   `json:"maxBudgetNanoTOS"`
	MaxFundingNanoTOS   uint64   `json:"maxFundingNanoTOS"`
}

type Server struct {
	network string
	backend Backend
	store   *actionStore
	maxBody int64
	now     Clock
	logger  *slog.Logger
	policy  PublisherPolicy
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
	backendBinding := config.Backend.EnrollmentBinding()
	state, err := openActionStore(config.StatePath, config.JournalIdentity, config.Network, config.Policy, backendBinding)
	if err != nil {
		return nil, err
	}
	policy, err := validatePublisherPolicy(config.Policy)
	if err != nil {
		_ = state.close()
		return nil, err
	}
	return &Server{
		network: config.Network, backend: config.Backend, store: state,
		maxBody: config.MaxBodyBytes, now: config.Now, logger: config.Logger, policy: policy,
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(localrpc.TaskEscrowActionHealthPath, s.health)
	mux.HandleFunc(localrpc.TaskEscrowActionPath, s.publish)
	mux.HandleFunc(localrpc.TaskEscrowActionResolvePath, s.resolve)
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
		"resolvePath":     localrpc.TaskEscrowActionResolvePath,
		"journalVersion":  JournalVersion,
		"journalIdentity": s.store.identity, "journalBinding": s.store.binding,
	})
}

func (s *Server) resolve(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, s.maxBody+1))
	if err != nil || int64(len(data)) > s.maxBody {
		writePublisherError(writer, http.StatusRequestEntityTooLarge)
		return
	}
	var action chain.TaskEscrowAction
	if jsonstrict.Decode(data, &action) != nil || validateAction(action, s.network, s.now(), s.policy) != nil {
		writePublisherError(writer, http.StatusBadRequest)
		return
	}
	stable := action
	stable.ExpiresUnixMillis = 0
	digest, err := codec.Digest("tos.task-escrow.publisher-action.v1", stable)
	if err != nil {
		writePublisherError(writer, http.StatusServiceUnavailable)
		return
	}
	record, err := s.store.get(action.ActionID)
	if err != nil {
		writePublisherError(writer, http.StatusServiceUnavailable)
		return
	}
	if record == nil {
		writer.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(writer).Encode(map[string]string{"version": chain.TaskEscrowActionVersion, "code": "action_not_found", "actionId": action.ActionID, "journalIdentity": s.store.identity, "journalBinding": s.store.binding})
		return
	}
	if record.SemanticDigest != digest {
		writePublisherError(writer, http.StatusConflict)
		return
	}
	if record.State != recordStateCompleted || record.Receipt == nil {
		writer.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(writer).Encode(map[string]string{"version": chain.TaskEscrowActionVersion, "code": "action_outcome_uncertain", "actionId": action.ActionID})
		return
	}
	_ = json.NewEncoder(writer).Encode(record.Receipt)
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
	if err := validateAction(action, s.network, s.now(), s.policy); err != nil {
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
		if action.Kind == chain.TaskEscrowActionDeploy && !contains(s.policy.AllowedCodeHashes, prepared.CodeHash) {
			return chain.TaskEscrowActionReceipt{}, errors.New("prepared TaskEscrow code hash is not allowed")
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

func validateAction(action chain.TaskEscrowAction, network string, now time.Time, policy PublisherPolicy) error {
	expectedID, idErr := chain.TaskEscrowActionID(action)
	if action.Version != chain.TaskEscrowActionVersion || action.Network != network ||
		strings.TrimSpace(action.ActionID) == "" || len(action.ActionID) > 256 ||
		strings.TrimSpace(action.EscrowID) == "" || len(action.EscrowID) > 256 ||
		strings.TrimSpace(action.Creator) == "" || strings.TrimSpace(action.Agent) == "" || action.BudgetNanoTOS == 0 ||
		action.DeadlineUnix == 0 || action.ReviewPeriod < 3600 ||
		!validDigest(action.PolicyHash) || !validDigest(action.PermissionHash) ||
		action.ExpiresUnixMillis <= now.UTC().UnixMilli() || idErr != nil || action.ActionID != expectedID || !contains(policy.AllowedCreators, action.Creator) || !contains(policy.AllowedAgents, action.Agent) || (action.Verifier != "" && !contains(policy.AllowedVerifiers, action.Verifier)) || !contains(policy.AllowedPolicyHashes, action.PolicyHash) || action.BudgetNanoTOS > policy.MaxBudgetNanoTOS || action.FundingNanoTOS > policy.MaxFundingNanoTOS {
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
		if (action.Kind == chain.TaskEscrowActionCancel || action.Kind == chain.TaskEscrowActionTimeout || action.Kind == chain.TaskEscrowActionReject) && !validDigest(action.ReleaseDigest) {
			return errors.New("invalid release action digest")
		}
	case chain.TaskEscrowActionResult:
		if action.ContractAddress == "" || action.QueryID == 0 || !validDigest(action.ResultHash) ||
			!validDigest(action.EvidenceHash) || !validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid result action")
		}
	case chain.TaskEscrowActionDispute:
		if action.ContractAddress == "" || action.QueryID == 0 || !validNonZeroDigest(action.DisputeHash) ||
			!validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid dispute action")
		}
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		if action.ContractAddress == "" || action.QueryID == 0 || action.PayoutNanoTOS > action.BudgetNanoTOS ||
			!validCellHash(action.ExpectedBodyHash) {
			return errors.New("invalid payout action")
		}
		if action.Kind == chain.TaskEscrowActionResolve && !validNonZeroDigest(action.DisputeHash) {
			return errors.New("invalid resolution dispute commitment")
		}
	default:
		return errors.New("unsupported task escrow action")
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func validatePublisherPolicy(p PublisherPolicy) (PublisherPolicy, error) {
	if len(p.AllowedCreators) == 0 || len(p.AllowedAgents) == 0 || len(p.AllowedPolicyHashes) == 0 || len(p.AllowedCodeHashes) == 0 || p.MaxBudgetNanoTOS == 0 || p.MaxFundingNanoTOS < p.MaxBudgetNanoTOS {
		return p, errors.New("incomplete task escrow publisher policy")
	}
	canonicalize := func(values []string) ([]string, error) {
		out := make([]string, 0, len(values))
		seen := map[string]bool{}
		for _, v := range values {
			c, err := toschain.CanonicalAddress(strings.TrimSpace(v))
			if err != nil {
				return nil, err
			}
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
		return out, nil
	}
	var err error
	if p.AllowedCreators, err = canonicalize(p.AllowedCreators); err != nil {
		return p, errors.New("invalid allowed creator")
	}
	if p.AllowedAgents, err = canonicalize(p.AllowedAgents); err != nil {
		return p, errors.New("invalid allowed agent")
	}
	if len(p.AllowedVerifiers) > 0 {
		if p.AllowedVerifiers, err = canonicalize(p.AllowedVerifiers); err != nil {
			return p, errors.New("invalid allowed verifier")
		}
	}
	for _, v := range append(append([]string{}, p.AllowedPolicyHashes...), p.AllowedCodeHashes...) {
		if !validDigest(v) && !validCellHash(v) {
			return p, errors.New("invalid publisher digest policy")
		}
	}
	return p, nil
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

func validNonZeroDigest(value string) bool {
	return validDigest(value) && value != "sha256:"+strings.Repeat("0", 64)
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
