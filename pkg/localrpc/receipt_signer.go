package localrpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	ReceiptSignerPath                   = "/v1/receipt/sign"
	QuoteSignerPath                     = "/v1/quote/sign"
	SessionSignerPath                   = "/v1/session/sign"
	ReceiptSignerHealthPath             = "/healthz"
	DefaultReceiptSignerTimeout         = 5 * time.Second
	DefaultReceiptSignerMaxMessageBytes = 2 << 20
	DefaultReceiptSignerMaxConcurrent   = 16
	maxReceiptSignerTimeout             = time.Minute
	maxReceiptSignerMessageBytes        = 4 << 20
	maxReceiptSignerConcurrent          = 128
)

// ReceiptSignerClientConfig describes the private Unix-socket key-custody
// boundary. The client performs one bounded request and never retries signing.
type ReceiptSignerClientConfig struct {
	SocketPath        string
	Timeout           time.Duration
	MaxMessageBytes   int
	MaxConcurrent     int
	ExpectedKeyID     string
	ExpectedPublicKey string
}

// QuoteSignerClientConfig uses the same bounded private transport policy as
// receipt signing, but NewQuoteSignerClient fixes it to the quote operation.
type QuoteSignerClientConfig = ReceiptSignerClientConfig

// SessionSignerClientConfig uses the same bounded private transport policy,
// fixed to authenticate-role session grants.
type SessionSignerClientConfig = ReceiptSignerClientConfig

func DefaultReceiptSignerClientConfig(socketPath string) ReceiptSignerClientConfig {
	return ReceiptSignerClientConfig{
		SocketPath: socketPath, Timeout: DefaultReceiptSignerTimeout,
		MaxMessageBytes: DefaultReceiptSignerMaxMessageBytes,
		MaxConcurrent:   DefaultReceiptSignerMaxConcurrent,
	}
}

func DefaultQuoteSignerClientConfig(socketPath string) QuoteSignerClientConfig {
	return DefaultReceiptSignerClientConfig(socketPath)
}

func DefaultSessionSignerClientConfig(socketPath string) SessionSignerClientConfig {
	return DefaultReceiptSignerClientConfig(socketPath)
}

// ReceiptSignerClient implements authorization.ReceiptSigner without loading
// receipt private keys into Edge. A separate same-user, private-socket sidecar
// owns key selection and signing; Edge still verifies every returned envelope
// against the current manifest before accepting it.
type ReceiptSignerClient struct {
	httpClient        *http.Client
	maxMessageBytes   int
	slots             chan struct{}
	expectedKeyID     string
	expectedPublicKey ed25519.PublicKey
	domain            string
	path              string

	mutex     sync.Mutex
	active    map[uint64]context.CancelFunc
	nextID    uint64
	closed    bool
	requests  sync.WaitGroup
	closeOnce sync.Once
}

type receiptSignerRequest struct {
	Version           string `json:"version"`
	Payload           []byte `json:"payload"`
	IssuedUnixMillis  int64  `json:"issuedUnixMillis"`
	ExpiresUnixMillis int64  `json:"expiresUnixMillis"`
}

type receiptSignerHealth struct {
	Status    string `json:"status"`
	KeyID     string `json:"keyId"`
	PublicKey string `json:"publicKey"`
	Domain    string `json:"domain"`
	Path      string `json:"path"`
}

func NewReceiptSignerClient(
	config ReceiptSignerClientConfig,
) (*ReceiptSignerClient, error) {
	return newPurposeSignerClient(
		config, protocol.ReceiptDomain, ReceiptSignerPath,
	)
}

func newPurposeSignerClient(
	config ReceiptSignerClientConfig,
	domain string,
	path string,
) (*ReceiptSignerClient, error) {
	if config.Timeout <= 0 || config.Timeout > maxReceiptSignerTimeout ||
		config.MaxMessageBytes <= 0 ||
		config.MaxMessageBytes > maxReceiptSignerMessageBytes ||
		config.MaxConcurrent <= 0 ||
		config.MaxConcurrent > maxReceiptSignerConcurrent ||
		(config.ExpectedKeyID == "") != (config.ExpectedPublicKey == "") ||
		len(config.ExpectedKeyID) > 512 ||
		strings.ContainsRune(config.ExpectedKeyID, '\x00') ||
		(domain != protocol.ReceiptDomain && domain != protocol.QuoteDomain &&
			domain != protocol.SessionGrantDomain) ||
		(path != ReceiptSignerPath && path != QuoteSignerPath &&
			path != SessionSignerPath) {
		return nil, errors.New("invalid receipt signer client configuration")
	}
	var expectedPublicKey ed25519.PublicKey
	if config.ExpectedPublicKey != "" {
		decoded, err := base64.RawURLEncoding.DecodeString(config.ExpectedPublicKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize || allZeroBytes(decoded) {
			return nil, errors.New("invalid expected receipt signer public key")
		}
		expectedPublicKey = append(ed25519.PublicKey(nil), decoded...)
	}
	httpClient, err := HTTPClient(config.SocketPath, config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("configure receipt signer transport: %w", err)
	}
	httpClient.CheckRedirect = func(
		_ *http.Request,
		_ []*http.Request,
	) error {
		return http.ErrUseLastResponse
	}
	return &ReceiptSignerClient{
		httpClient: httpClient, maxMessageBytes: config.MaxMessageBytes,
		slots:             make(chan struct{}, config.MaxConcurrent),
		expectedKeyID:     config.ExpectedKeyID,
		expectedPublicKey: expectedPublicKey,
		active:            make(map[uint64]context.CancelFunc, config.MaxConcurrent),
		domain:            domain,
		path:              path,
	}, nil
}

func (c *ReceiptSignerClient) SignReceipt(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	if c == nil || c.domain != protocol.ReceiptDomain || c.path != ReceiptSignerPath {
		return identity.Envelope{}, errors.New("invalid receipt signer client")
	}
	return c.signPurpose(ctx, payload, issuedAt, expiresAt)
}

func (c *ReceiptSignerClient) signPurpose(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	if c == nil || nilHTTPClient(c.httpClient) || c.maxMessageBytes <= 0 ||
		c.slots == nil || c.active == nil || c.domain == "" || c.path == "" {
		return identity.Envelope{}, errors.New("invalid receipt signer client")
	}
	if ctx == nil {
		return identity.Envelope{}, errors.New("nil receipt signing context")
	}
	if err := ctx.Err(); err != nil {
		return identity.Envelope{}, err
	}
	issuedAt = issuedAt.UTC()
	expiresAt = expiresAt.UTC()
	if issuedAt.IsZero() || !expiresAt.After(issuedAt) ||
		expiresAt.Sub(issuedAt) > identity.MaxLifetime ||
		len(payload) > identity.MaxPayloadBytes {
		return identity.Envelope{}, errors.New("invalid receipt signing request")
	}
	encoded, err := json.Marshal(receiptSignerRequest{
		Version: "1", Payload: append([]byte(nil), payload...),
		IssuedUnixMillis:  issuedAt.UnixMilli(),
		ExpiresUnixMillis: expiresAt.UnixMilli(),
	})
	if err != nil {
		return identity.Envelope{}, errors.New("encode receipt signing request")
	}
	if len(encoded) > c.maxMessageBytes {
		return identity.Envelope{}, errors.New("receipt signing request exceeds message limit")
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return identity.Envelope{}, err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, "http://unix"+c.path,
		bytes.NewReader(encoded),
	)
	if err != nil {
		return identity.Envelope{}, errors.New("construct receipt signing request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return identity.Envelope{}, contextErr
		}
		if requestContext.Err() != nil {
			return identity.Envelope{}, errors.New("receipt signer client is closed")
		}
		return identity.Envelope{}, errors.New("receipt signer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return identity.Envelope{}, errors.New("receipt signer rejected request")
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	charset := strings.ToLower(parameters["charset"])
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) {
		return identity.Envelope{}, errors.New("receipt signer returned an invalid content type")
	}
	responseData, err := io.ReadAll(io.LimitReader(
		response.Body, int64(c.maxMessageBytes)+1,
	))
	if err != nil {
		return identity.Envelope{}, errors.New("read receipt signer response")
	}
	if len(responseData) > c.maxMessageBytes {
		return identity.Envelope{}, errors.New("receipt signer response exceeds message limit")
	}
	var envelope identity.Envelope
	if err := jsonstrict.Decode(responseData, &envelope); err != nil {
		return identity.Envelope{}, errors.New("receipt signer returned an invalid envelope")
	}
	if envelope.Domain != c.domain ||
		envelope.IssuedAt != issuedAt.UnixMilli() ||
		envelope.ExpiresAt != expiresAt.UnixMilli() ||
		!bytes.Equal(envelope.Payload, payload) {
		return identity.Envelope{}, errors.New("receipt signer changed the signing request")
	}
	if _, err := envelope.Fingerprint(); err != nil {
		return identity.Envelope{}, errors.New("receipt signer returned a malformed envelope")
	}
	if c.expectedKeyID != "" {
		if envelope.KeyID != c.expectedKeyID ||
			envelope.Verify(c.expectedPublicKey, c.domain, issuedAt) != nil {
			return identity.Envelope{}, errors.New(
				"receipt signer response does not match startup identity",
			)
		}
	}
	return cloneIdentityEnvelope(envelope), nil
}

// QuoteSignerClient implements authorization.QuoteSigner using the same
// bounded private transport while fixing the operation to the quote domain
// and path. It intentionally does not expose SignReceipt.
type QuoteSignerClient struct {
	client *ReceiptSignerClient
}

func NewQuoteSignerClient(
	config QuoteSignerClientConfig,
) (*QuoteSignerClient, error) {
	client, err := newPurposeSignerClient(
		config, protocol.QuoteDomain, QuoteSignerPath,
	)
	if err != nil {
		return nil, err
	}
	return &QuoteSignerClient{client: client}, nil
}

func (c *QuoteSignerClient) SignQuote(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	if c == nil || c.client == nil ||
		c.client.domain != protocol.QuoteDomain || c.client.path != QuoteSignerPath {
		return identity.Envelope{}, errors.New("invalid quote signer client")
	}
	return c.client.signPurpose(ctx, payload, issuedAt, expiresAt)
}

func (c *QuoteSignerClient) CheckReady(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("invalid quote signer client")
	}
	return c.client.CheckReady(ctx)
}

func (c *QuoteSignerClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

// SessionSignerClient implements authorization.SessionSigner using a
// purpose-fixed authenticate-role sidecar. It cannot sign Quotes or Receipts.
type SessionSignerClient struct {
	client *ReceiptSignerClient
}

func NewSessionSignerClient(
	config SessionSignerClientConfig,
) (*SessionSignerClient, error) {
	client, err := newPurposeSignerClient(
		config, protocol.SessionGrantDomain, SessionSignerPath,
	)
	if err != nil {
		return nil, err
	}
	return &SessionSignerClient{client: client}, nil
}

func (c *SessionSignerClient) SignSession(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	if c == nil || c.client == nil ||
		c.client.domain != protocol.SessionGrantDomain ||
		c.client.path != SessionSignerPath {
		return identity.Envelope{}, errors.New("invalid session signer client")
	}
	return c.client.signPurpose(ctx, payload, issuedAt, expiresAt)
}

func (c *SessionSignerClient) CheckReady(ctx context.Context) error {
	if c == nil || c.client == nil {
		return errors.New("invalid session signer client")
	}
	return c.client.CheckReady(ctx)
}

func (c *SessionSignerClient) Close() error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Close()
}

// CheckReady verifies the private transport and signer process without asking
// it to create a signature. It shares the fixed client admission semaphore
// with signing calls and never retries.
func (c *ReceiptSignerClient) CheckReady(ctx context.Context) error {
	if c == nil || nilHTTPClient(c.httpClient) || c.maxMessageBytes <= 0 ||
		c.slots == nil || c.active == nil {
		return errors.New("invalid receipt signer client")
	}
	if ctx == nil {
		return errors.New("nil receipt signer readiness context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	requestContext, finish, err := c.beginRequest(ctx)
	if err != nil {
		return err
	}
	defer finish()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodGet, "http://unix"+ReceiptSignerHealthPath, nil,
	)
	if err != nil {
		return errors.New("construct receipt signer readiness request")
	}
	request.Header.Set("Accept", "application/json")
	response, err := c.httpClient.Do(request)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		if requestContext.Err() != nil {
			return errors.New("receipt signer client is closed")
		}
		return errors.New("receipt signer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("receipt signer is not ready")
	}
	mediaType, parameters, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	charset := strings.ToLower(parameters["charset"])
	if err != nil || mediaType != "application/json" ||
		(len(parameters) > 1 || (len(parameters) == 1 && charset != "utf-8")) {
		return errors.New("receipt signer returned an invalid readiness content type")
	}
	data, err := io.ReadAll(io.LimitReader(
		response.Body, int64(c.maxMessageBytes)+1,
	))
	if err != nil || len(data) > c.maxMessageBytes {
		return errors.New("receipt signer returned an invalid readiness response")
	}
	var health receiptSignerHealth
	if err := jsonstrict.Decode(data, &health); err != nil || health.Status != "ready" ||
		health.KeyID == "" || len(health.KeyID) > 512 ||
		strings.ContainsRune(health.KeyID, '\x00') ||
		health.Domain != c.domain || health.Path != c.path {
		return errors.New("receipt signer returned an invalid readiness response")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(health.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize || allZeroBytes(publicKey) {
		return errors.New("receipt signer returned an invalid readiness identity")
	}
	if c.expectedKeyID != "" &&
		(health.KeyID != c.expectedKeyID ||
			!bytes.Equal(publicKey, c.expectedPublicKey)) {
		return errors.New("receipt signer identity does not match startup policy")
	}
	return nil
}

func (c *ReceiptSignerClient) beginRequest(
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
		return nil, nil, errors.New("receipt signer client is closed")
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

// Close rejects new operations, cancels active Unix-socket requests, waits for
// them to leave the bounded client admission set, and closes idle transports.
// It is safe to call more than once.
func (c *ReceiptSignerClient) Close() error {
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

func allZeroBytes(value []byte) bool {
	var combined byte
	for _, current := range value {
		combined |= current
	}
	return combined == 0
}

func cloneIdentityEnvelope(envelope identity.Envelope) identity.Envelope {
	envelope.Payload = append([]byte(nil), envelope.Payload...)
	return envelope
}

func nilHTTPClient(client *http.Client) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client.Transport)
	return client.Transport == nil ||
		(value.Kind() == reflect.Pointer && value.IsNil())
}
