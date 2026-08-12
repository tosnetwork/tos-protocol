package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

const (
	TaskEscrowActionPath        = "/v1/economic/task-escrow/action"
	TaskEscrowActionResolvePath = "/v1/economic/task-escrow/action/resolve"
	TaskEscrowActionHealthPath  = "/healthz"
	// DefaultTaskEscrowActionTimeout must exceed the publisher's default
	// publish wait budget (taskescrowpublisher.DefaultPublishTimeout, 90s):
	// the server legitimately blocks the HTTP response until it observes the
	// published transaction on chain, so a shorter client timeout aborts
	// every slow-but-successful publish.
	DefaultTaskEscrowActionTimeout         = 100 * time.Second
	DefaultTaskEscrowActionMaxMessageBytes = 512 << 10
	DefaultTaskEscrowActionMaxConcurrent   = 8
	maxTaskEscrowActionTimeout             = 2 * time.Minute
	maxTaskEscrowActionMessageBytes        = 2 << 20
	maxTaskEscrowActionConcurrent          = 64
)

type TaskEscrowActionPublisherClientConfig struct {
	SocketPath      string
	Network         string
	JournalIdentity string
	JournalBinding  string
	Timeout         time.Duration
	MaxMessageBytes int
	MaxConcurrent   int
}

func DefaultTaskEscrowActionPublisherClientConfig(
	socketPath, network, journalIdentity, journalBinding string,
) TaskEscrowActionPublisherClientConfig {
	return TaskEscrowActionPublisherClientConfig{
		SocketPath: socketPath, Network: network, JournalIdentity: journalIdentity, JournalBinding: journalBinding,
		Timeout:         DefaultTaskEscrowActionTimeout,
		MaxMessageBytes: DefaultTaskEscrowActionMaxMessageBytes,
		MaxConcurrent:   DefaultTaskEscrowActionMaxConcurrent,
	}
}

type TaskEscrowActionPublisherClient struct {
	httpClient      *http.Client
	network         string
	journalIdentity string
	journalBinding  string
	maxMessageBytes int
	slots           chan struct{}

	mutex     sync.Mutex
	active    map[uint64]context.CancelFunc
	nextID    uint64
	closed    bool
	requests  sync.WaitGroup
	closeOnce sync.Once
}

type taskEscrowActionHealth struct {
	Status          string `json:"status"`
	Version         string `json:"version"`
	Network         string `json:"network"`
	Path            string `json:"path"`
	ResolvePath     string `json:"resolvePath"`
	JournalVersion  string `json:"journalVersion"`
	JournalIdentity string `json:"journalIdentity"`
	JournalBinding  string `json:"journalBinding"`
}

type taskEscrowActionNotFound struct {
	Version         string `json:"version"`
	Code            string `json:"code"`
	ActionID        string `json:"actionId"`
	JournalIdentity string `json:"journalIdentity"`
	JournalBinding  string `json:"journalBinding"`
}

func NewTaskEscrowActionPublisherClient(
	config TaskEscrowActionPublisherClientConfig,
) (*TaskEscrowActionPublisherClient, error) {
	if strings.TrimSpace(config.Network) == "" || len(config.Network) > 64 ||
		strings.TrimSpace(config.JournalIdentity) == "" || strings.TrimSpace(config.JournalBinding) == "" ||
		config.Timeout <= 0 || config.Timeout > maxTaskEscrowActionTimeout ||
		config.MaxMessageBytes <= 0 || config.MaxMessageBytes > maxTaskEscrowActionMessageBytes ||
		config.MaxConcurrent <= 0 || config.MaxConcurrent > maxTaskEscrowActionConcurrent {
		return nil, errors.New("invalid task escrow action publisher configuration")
	}
	httpClient, err := HTTPClient(config.SocketPath, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("configure task escrow publisher transport: %w", err)
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &TaskEscrowActionPublisherClient{
		httpClient: httpClient, network: config.Network, journalIdentity: config.JournalIdentity, journalBinding: config.JournalBinding,
		maxMessageBytes: config.MaxMessageBytes,
		slots:           make(chan struct{}, config.MaxConcurrent),
		active:          make(map[uint64]context.CancelFunc, config.MaxConcurrent),
	}, nil
}

func (c *TaskEscrowActionPublisherClient) Publish(
	ctx context.Context,
	action chain.TaskEscrowAction,
) (chain.TaskEscrowActionReceipt, error) {
	if c == nil || c.httpClient == nil || c.maxMessageBytes <= 0 ||
		c.slots == nil || c.active == nil {
		return chain.TaskEscrowActionReceipt{}, errors.New("invalid task escrow action publisher client")
	}
	if ctx == nil {
		return chain.TaskEscrowActionReceipt{}, errors.New("nil task escrow action context")
	}
	if err := validateTaskEscrowAction(action, c.network); err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	encoded, err := json.Marshal(action)
	if err != nil || len(encoded) > c.maxMessageBytes {
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action request exceeds message limit")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, "http://unix"+TaskEscrowActionPath,
		bytes.NewReader(encoded),
	)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, errors.New("construct task escrow action request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return chain.TaskEscrowActionReceipt{}, contextErr
		}
		if requestContext.Err() != nil {
			return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action publisher client is closed")
		}
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action publisher unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action publisher rejected request")
	}
	if err := requireTaskEscrowJSON(response.Header.Get("Content-Type")); err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if err != nil || len(data) > c.maxMessageBytes {
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action response exceeds message limit")
	}
	var receipt chain.TaskEscrowActionReceipt
	if err := jsonstrict.Decode(data, &receipt); err != nil {
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action publisher returned an invalid receipt")
	}
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID ||
		receipt.Network != action.Network || receipt.Kind != action.Kind ||
		receipt.EscrowID != action.EscrowID || strings.TrimSpace(receipt.ContractAddress) == "" ||
		strings.TrimSpace(receipt.Reference) == "" ||
		(action.ContractAddress != "" && receipt.ContractAddress != action.ContractAddress) {
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action publisher changed the immutable request")
	}
	return receipt, nil
}

func (c *TaskEscrowActionPublisherClient) Resolve(ctx context.Context, action chain.TaskEscrowAction) (chain.TaskEscrowActionReceipt, bool, error) {
	if c == nil || ctx == nil {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("invalid task escrow action resolver")
	}
	if err := validateTaskEscrowAction(action, c.network); err != nil {
		return chain.TaskEscrowActionReceipt{}, false, err
	}
	encoded, err := json.Marshal(action)
	if err != nil || len(encoded) > c.maxMessageBytes {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow lookup request exceeds message limit")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, false, err
	}
	defer finish()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "http://unix"+TaskEscrowActionResolvePath, bytes.NewReader(encoded))
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("construct task escrow lookup request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow action resolver unavailable")
	}
	defer response.Body.Close()
	data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if readErr != nil || len(data) > c.maxMessageBytes || requireTaskEscrowJSON(response.Header.Get("Content-Type")) != nil {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow action resolver returned an invalid response")
	}
	if response.StatusCode == http.StatusNotFound {
		var missing taskEscrowActionNotFound
		if jsonstrict.Decode(data, &missing) != nil || missing.Version != chain.TaskEscrowActionVersion || missing.Code != "action_not_found" || missing.ActionID != action.ActionID || missing.JournalIdentity != c.journalIdentity || missing.JournalBinding != c.journalBinding {
			return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow action resolver returned an untyped not-found")
		}
		return chain.TaskEscrowActionReceipt{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow action outcome is uncertain")
	}
	var receipt chain.TaskEscrowActionReceipt
	if jsonstrict.Decode(data, &receipt) != nil || receipt.Version != action.Version || receipt.ActionID != action.ActionID || receipt.Network != action.Network || receipt.Kind != action.Kind || receipt.EscrowID != action.EscrowID || strings.TrimSpace(receipt.ContractAddress) == "" || strings.TrimSpace(receipt.Reference) == "" || (action.ContractAddress != "" && receipt.ContractAddress != action.ContractAddress) {
		return chain.TaskEscrowActionReceipt{}, false, errors.New("task escrow action resolver returned an invalid receipt")
	}
	return receipt, true, nil
}

func (c *TaskEscrowActionPublisherClient) CheckReady(ctx context.Context) error {
	if c == nil || c.httpClient == nil || c.slots == nil || c.active == nil {
		return errors.New("invalid task escrow action publisher client")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, "http://unix"+TaskEscrowActionHealthPath, nil,
	)
	if err != nil {
		return errors.New("construct task escrow readiness request")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		return errors.New("task escrow action publisher unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("task escrow action publisher is not ready")
	}
	if err := requireTaskEscrowJSON(response.Header.Get("Content-Type")); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if err != nil || len(data) > c.maxMessageBytes {
		return errors.New("task escrow readiness response exceeds message limit")
	}
	var health taskEscrowActionHealth
	if err := jsonstrict.Decode(data, &health); err != nil ||
		health.Status != "ready" || health.Version != chain.TaskEscrowActionVersion ||
		health.Network != c.network || health.Path != TaskEscrowActionPath ||
		health.ResolvePath != TaskEscrowActionResolvePath || health.JournalVersion != "1" || health.JournalIdentity != c.journalIdentity || health.JournalBinding != c.journalBinding {
		return errors.New("task escrow action publisher returned an invalid readiness response")
	}
	return nil
}

func validateTaskEscrowAction(action chain.TaskEscrowAction, network string) error {
	if action.Version != chain.TaskEscrowActionVersion || action.Network != network ||
		strings.TrimSpace(action.ActionID) == "" || strings.TrimSpace(action.EscrowID) == "" ||
		strings.TrimSpace(action.Creator) == "" || strings.TrimSpace(action.Agent) == "" ||
		action.BudgetNanoTOS == 0 || action.DeadlineUnix == 0 || action.ReviewPeriod < 3600 ||
		strings.TrimSpace(action.PolicyHash) == "" || strings.TrimSpace(action.PermissionHash) == "" ||
		action.ExpiresUnixMillis <= 0 {
		return errors.New("invalid task escrow action")
	}
	switch action.Kind {
	case chain.TaskEscrowActionDeploy:
		if action.ContractAddress != "" || action.BudgetNanoTOS == 0 ||
			action.FundingNanoTOS < action.BudgetNanoTOS {
			return errors.New("invalid task escrow deployment action")
		}
	case chain.TaskEscrowActionAccept, chain.TaskEscrowActionCancel,
		chain.TaskEscrowActionTimeout, chain.TaskEscrowActionReject:
		if action.ContractAddress == "" || action.QueryID == 0 || action.ExpectedBodyHash == "" {
			return errors.New("invalid task escrow operation action")
		}
		if (action.Kind == chain.TaskEscrowActionCancel || action.Kind == chain.TaskEscrowActionTimeout || action.Kind == chain.TaskEscrowActionReject) && action.ReleaseDigest == "" {
			return errors.New("invalid task escrow release digest")
		}
	case chain.TaskEscrowActionResult:
		if action.ContractAddress == "" || action.QueryID == 0 || action.ResultHash == "" ||
			action.EvidenceHash == "" || action.ExpectedBodyHash == "" {
			return errors.New("invalid task escrow result action")
		}
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		if action.ContractAddress == "" || action.QueryID == 0 || action.ExpectedBodyHash == "" ||
			action.PayoutNanoTOS > action.BudgetNanoTOS {
			return errors.New("invalid task escrow payout action")
		}
		if action.Kind == chain.TaskEscrowActionResolve && !validNonZeroTaskEscrowDigest(action.DisputeHash) {
			return errors.New("invalid task escrow resolution dispute commitment")
		}
	case chain.TaskEscrowActionDispute:
		if action.ContractAddress == "" || action.QueryID == 0 || !validNonZeroTaskEscrowDigest(action.DisputeHash) ||
			action.ExpectedBodyHash == "" {
			return errors.New("invalid task escrow dispute action")
		}
	default:
		return errors.New("unsupported task escrow action")
	}
	return nil
}

func validNonZeroTaskEscrowDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 ||
		value == "sha256:"+strings.Repeat("0", 64) {
		return false
	}
	for _, char := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", char) {
			return false
		}
	}
	return true
}

func requireTaskEscrowJSON(value string) error {
	mediaType, parameters, err := mime.ParseMediaType(value)
	charset := strings.ToLower(parameters["charset"])
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) {
		return errors.New("task escrow action publisher returned an invalid content type")
	}
	return nil
}

func (c *TaskEscrowActionPublisherClient) beginRequest(
	ctx context.Context,
) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("nil task escrow request context")
	}
	select {
	case c.slots <- struct{}{}:
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	requestContext, cancel := context.WithCancel(ctx)
	c.mutex.Lock()
	if c.closed {
		c.mutex.Unlock()
		cancel()
		<-c.slots
		return nil, nil, errors.New("task escrow action publisher client is closed")
	}
	var id uint64
	for {
		c.nextID++
		if c.nextID == 0 {
			c.nextID++
		}
		id = c.nextID
		if _, exists := c.active[id]; !exists {
			break
		}
	}
	c.active[id] = cancel
	c.requests.Add(1)
	c.mutex.Unlock()
	var once sync.Once
	finish := func() {
		once.Do(func() {
			c.mutex.Lock()
			delete(c.active, id)
			c.mutex.Unlock()
			cancel()
			<-c.slots
			c.requests.Done()
		})
	}
	return requestContext, finish, nil
}

func (c *TaskEscrowActionPublisherClient) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		c.mutex.Lock()
		c.closed = true
		cancels := make([]context.CancelFunc, 0, len(c.active))
		for _, cancel := range c.active {
			cancels = append(cancels, cancel)
		}
		c.mutex.Unlock()
		for _, cancel := range cancels {
			cancel()
		}
		if c.httpClient != nil {
			c.httpClient.CloseIdleConnections()
		}
		c.requests.Wait()
	})
	return nil
}

var _ chain.TaskEscrowActionPublisher = (*TaskEscrowActionPublisherClient)(nil)
