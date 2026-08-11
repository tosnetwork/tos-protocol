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
	ChainActionPath                   = "/v1/chain/action"
	ChainActionResolvePath            = "/v1/chain/action/resolve"
	ChainActionHealthPath             = "/healthz"
	DefaultChainActionTimeout         = 15 * time.Second
	DefaultChainActionMaxMessageBytes = 256 << 10
	DefaultChainActionMaxConcurrent   = 8
	maxChainActionTimeout             = 2 * time.Minute
	maxChainActionMessageBytes        = 1 << 20
	maxChainActionConcurrent          = 64
)

// ChainActionPublisherClientConfig describes the private Unix-socket boundary
// to a key-custody/contract sidecar. The sidecar can publish transactions but
// cannot declare them finalized; the caller independently verifies every
// returned transaction through quorum-backed TOS observers.
type ChainActionPublisherClientConfig struct {
	SocketPath      string
	Network         string
	Timeout         time.Duration
	MaxMessageBytes int
	MaxConcurrent   int
}

func (c *ChainActionPublisherClient) Resolve(ctx context.Context, action chain.Action) (chain.ActionReceipt, bool, error) {
	if err := c.validateAction(ctx, action); err != nil {
		return chain.ActionReceipt{}, false, err
	}
	encoded, err := json.Marshal(action)
	if err != nil || len(encoded) > c.maxMessageBytes {
		return chain.ActionReceipt{}, false, errors.New("chain action lookup request exceeds message limit")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return chain.ActionReceipt{}, false, err
	}
	defer finish()
	request, err := http.NewRequestWithContext(requestContext, http.MethodPost, "http://unix"+ChainActionResolvePath, bytes.NewReader(encoded))
	if err != nil {
		return chain.ActionReceipt{}, false, errors.New("construct chain action lookup request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return chain.ActionReceipt{}, false, contextErr
		}
		return chain.ActionReceipt{}, false, errors.New("chain action resolver unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		if requireJSONContentType(response.Header.Get("Content-Type")) != nil {
			return chain.ActionReceipt{}, false, errors.New("chain action resolver returned an untyped not-found")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
		var missing chainActionNotFound
		if readErr != nil || len(data) > c.maxMessageBytes || jsonstrict.Decode(data, &missing) != nil || missing.Version != chain.ChainActionVersion || missing.Code != "action_not_found" || missing.ActionID != action.ActionID {
			return chain.ActionReceipt{}, false, errors.New("chain action resolver returned an untyped not-found")
		}
		return chain.ActionReceipt{}, false, nil
	}
	if response.StatusCode != http.StatusOK || requireJSONContentType(response.Header.Get("Content-Type")) != nil {
		return chain.ActionReceipt{}, false, errors.New("chain action resolver rejected request")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if err != nil || len(data) > c.maxMessageBytes {
		return chain.ActionReceipt{}, false, errors.New("chain action lookup response exceeds message limit")
	}
	var receipt chain.ActionReceipt
	if err := jsonstrict.Decode(data, &receipt); err != nil || validateActionReceipt(action, receipt) != nil {
		return chain.ActionReceipt{}, false, errors.New("chain action resolver returned an invalid receipt")
	}
	return receipt, true, nil
}

func (c *ChainActionPublisherClient) validateAction(ctx context.Context, action chain.Action) error {
	if c == nil || c.httpClient == nil || c.maxMessageBytes <= 0 || c.slots == nil || c.active == nil {
		return errors.New("invalid chain action publisher client")
	}
	if ctx == nil {
		return errors.New("nil chain action context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if action.Version != chain.ChainActionVersion || action.Network != c.network || strings.TrimSpace(action.ActionID) == "" || strings.TrimSpace(action.ObjectID) == "" || strings.TrimSpace(action.Digest) == "" || strings.TrimSpace(action.Payer) == "" || strings.TrimSpace(action.Payee) == "" || action.AmountNanoTOS == 0 || strings.TrimSpace(action.Comment) == "" || action.ExpiresUnixMillis <= 0 {
		return errors.New("invalid chain action")
	}
	return nil
}

func validateActionReceipt(action chain.Action, receipt chain.ActionReceipt) error {
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID || receipt.Network != action.Network || receipt.Kind != action.Kind || receipt.ObjectID != action.ObjectID || receipt.Digest != action.Digest || receipt.Payer != action.Payer || receipt.Payee != action.Payee || receipt.AmountNanoTOS != action.AmountNanoTOS || receipt.Comment != action.Comment || strings.TrimSpace(receipt.Reference) == "" {
		return errors.New("chain action receipt does not match immutable request")
	}
	return nil
}

func DefaultChainActionPublisherClientConfig(
	socketPath, network string,
) ChainActionPublisherClientConfig {
	return ChainActionPublisherClientConfig{
		SocketPath: socketPath, Network: network,
		Timeout: DefaultChainActionTimeout, MaxMessageBytes: DefaultChainActionMaxMessageBytes,
		MaxConcurrent: DefaultChainActionMaxConcurrent,
	}
}

type ChainActionPublisherClient struct {
	httpClient      *http.Client
	network         string
	maxMessageBytes int
	slots           chan struct{}

	mutex     sync.Mutex
	active    map[uint64]context.CancelFunc
	nextID    uint64
	closed    bool
	requests  sync.WaitGroup
	closeOnce sync.Once
}

type chainActionHealth struct {
	Status         string   `json:"status"`
	Version        string   `json:"version"`
	Network        string   `json:"network"`
	PublishPath    string   `json:"publishPath"`
	ResolvePath    string   `json:"resolvePath"`
	JournalVersion string   `json:"journalVersion"`
	Capabilities   []string `json:"capabilities"`
}
type chainActionNotFound struct {
	Version  string `json:"version"`
	Code     string `json:"code"`
	ActionID string `json:"actionId"`
}

func NewChainActionPublisherClient(
	config ChainActionPublisherClientConfig,
) (*ChainActionPublisherClient, error) {
	if strings.TrimSpace(config.Network) == "" || len(config.Network) > 64 ||
		config.Timeout <= 0 || config.Timeout > maxChainActionTimeout ||
		config.MaxMessageBytes <= 0 || config.MaxMessageBytes > maxChainActionMessageBytes ||
		config.MaxConcurrent <= 0 || config.MaxConcurrent > maxChainActionConcurrent {
		return nil, errors.New("invalid chain action publisher client configuration")
	}
	httpClient, err := HTTPClient(config.SocketPath, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("configure chain action publisher transport: %w", err)
	}
	httpClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &ChainActionPublisherClient{
		httpClient: httpClient, network: config.Network,
		maxMessageBytes: config.MaxMessageBytes,
		slots:           make(chan struct{}, config.MaxConcurrent),
		active:          make(map[uint64]context.CancelFunc, config.MaxConcurrent),
	}, nil
}

func (c *ChainActionPublisherClient) Publish(
	ctx context.Context,
	action chain.Action,
) (chain.ActionReceipt, error) {
	if c == nil || c.httpClient == nil || c.maxMessageBytes <= 0 ||
		c.slots == nil || c.active == nil {
		return chain.ActionReceipt{}, errors.New("invalid chain action publisher client")
	}
	if ctx == nil {
		return chain.ActionReceipt{}, errors.New("nil chain action context")
	}
	if err := ctx.Err(); err != nil {
		return chain.ActionReceipt{}, err
	}
	if action.Version != chain.ChainActionVersion || action.Network != c.network ||
		strings.TrimSpace(action.ActionID) == "" || strings.TrimSpace(action.ObjectID) == "" ||
		strings.TrimSpace(action.Digest) == "" || strings.TrimSpace(action.Payer) == "" ||
		strings.TrimSpace(action.Payee) == "" || action.AmountNanoTOS == 0 ||
		strings.TrimSpace(action.Comment) == "" || action.ExpiresUnixMillis <= 0 {
		return chain.ActionReceipt{}, errors.New("invalid chain action")
	}
	encoded, err := json.Marshal(action)
	if err != nil || len(encoded) > c.maxMessageBytes {
		return chain.ActionReceipt{}, errors.New("chain action request exceeds message limit")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return chain.ActionReceipt{}, err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, "http://unix"+ChainActionPath,
		bytes.NewReader(encoded),
	)
	if err != nil {
		return chain.ActionReceipt{}, errors.New("construct chain action request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return chain.ActionReceipt{}, contextErr
		}
		if requestContext.Err() != nil {
			return chain.ActionReceipt{}, errors.New("chain action publisher client is closed")
		}
		return chain.ActionReceipt{}, errors.New("chain action publisher unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return chain.ActionReceipt{}, errors.New("chain action publisher rejected request")
	}
	if err := requireJSONContentType(response.Header.Get("Content-Type")); err != nil {
		return chain.ActionReceipt{}, err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if err != nil || len(data) > c.maxMessageBytes {
		return chain.ActionReceipt{}, errors.New("chain action publisher response exceeds message limit")
	}
	var receipt chain.ActionReceipt
	if err := jsonstrict.Decode(data, &receipt); err != nil {
		return chain.ActionReceipt{}, errors.New("chain action publisher returned an invalid receipt")
	}
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID ||
		receipt.Network != action.Network || receipt.Kind != action.Kind ||
		receipt.ObjectID != action.ObjectID || receipt.Digest != action.Digest ||
		receipt.Payer != action.Payer || receipt.Payee != action.Payee ||
		receipt.AmountNanoTOS != action.AmountNanoTOS || receipt.Comment != action.Comment ||
		strings.TrimSpace(receipt.Reference) == "" {
		return chain.ActionReceipt{}, errors.New("chain action publisher changed the immutable request")
	}
	return receipt, nil
}

func (c *ChainActionPublisherClient) CheckReady(ctx context.Context) error {
	if c == nil || c.httpClient == nil || c.maxMessageBytes <= 0 ||
		c.slots == nil || c.active == nil {
		return errors.New("invalid chain action publisher client")
	}
	if ctx == nil {
		return errors.New("nil chain action readiness context")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, "http://unix"+ChainActionHealthPath, nil,
	)
	if err != nil {
		return errors.New("construct chain action readiness request")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return errors.New("chain action publisher unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("chain action publisher is not ready")
	}
	if err := requireJSONContentType(response.Header.Get("Content-Type")); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxMessageBytes)+1))
	if err != nil || len(data) > c.maxMessageBytes {
		return errors.New("chain action publisher returned an invalid readiness response")
	}
	var health chainActionHealth
	if err := jsonstrict.Decode(data, &health); err != nil ||
		health.Status != "ready" || health.Version != chain.ChainActionVersion || health.Network != c.network || health.PublishPath != ChainActionPath || health.ResolvePath != ChainActionResolvePath || health.JournalVersion != "1" || !sameStrings(health.Capabilities, []string{"durable_intent_before_publish", "typed_action_not_found", "read_only_resolve"}) {
		return errors.New("chain action publisher returned an invalid readiness response")
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func requireJSONContentType(value string) error {
	mediaType, parameters, err := mime.ParseMediaType(value)
	charset := strings.ToLower(parameters["charset"])
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) {
		return errors.New("chain action publisher returned an invalid content type")
	}
	return nil
}

func (c *ChainActionPublisherClient) beginRequest(
	ctx context.Context,
) (context.Context, func(), error) {
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
		return nil, nil, errors.New("chain action publisher client is closed")
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

func (c *ChainActionPublisherClient) Close() error {
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
		if c.httpClient != nil {
			c.httpClient.CloseIdleConnections()
		}
	})
	return nil
}

var _ chain.ActionPublisher = (*ChainActionPublisherClient)(nil)
