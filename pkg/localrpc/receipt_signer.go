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
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	ReceiptSignerPath                   = "/v1/receipt/sign"
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

func DefaultReceiptSignerClientConfig(socketPath string) ReceiptSignerClientConfig {
	return ReceiptSignerClientConfig{
		SocketPath: socketPath, Timeout: DefaultReceiptSignerTimeout,
		MaxMessageBytes: DefaultReceiptSignerMaxMessageBytes,
		MaxConcurrent:   DefaultReceiptSignerMaxConcurrent,
	}
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
}

func NewReceiptSignerClient(
	config ReceiptSignerClientConfig,
) (*ReceiptSignerClient, error) {
	if config.Timeout <= 0 || config.Timeout > maxReceiptSignerTimeout ||
		config.MaxMessageBytes <= 0 ||
		config.MaxMessageBytes > maxReceiptSignerMessageBytes ||
		config.MaxConcurrent <= 0 ||
		config.MaxConcurrent > maxReceiptSignerConcurrent ||
		(config.ExpectedKeyID == "") != (config.ExpectedPublicKey == "") ||
		len(config.ExpectedKeyID) > 512 ||
		strings.ContainsRune(config.ExpectedKeyID, '\x00') {
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
	}, nil
}

func (c *ReceiptSignerClient) SignReceipt(
	ctx context.Context,
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	if c == nil || nilHTTPClient(c.httpClient) || c.maxMessageBytes <= 0 ||
		c.slots == nil {
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
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return identity.Envelope{}, ctx.Err()
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, "http://unix"+ReceiptSignerPath,
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
		return identity.Envelope{}, errors.New("receipt signer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return identity.Envelope{}, errors.New("receipt signer rejected request")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
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
	if envelope.Domain != protocol.ReceiptDomain ||
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
			envelope.Verify(
				c.expectedPublicKey, protocol.ReceiptDomain, issuedAt,
			) != nil {
			return identity.Envelope{}, errors.New(
				"receipt signer response does not match startup identity",
			)
		}
	}
	return cloneIdentityEnvelope(envelope), nil
}

// CheckReady verifies the private transport and signer process without asking
// it to create a signature. It shares the fixed client admission semaphore
// with signing calls and never retries.
func (c *ReceiptSignerClient) CheckReady(ctx context.Context) error {
	if c == nil || nilHTTPClient(c.httpClient) || c.maxMessageBytes <= 0 ||
		c.slots == nil {
		return errors.New("invalid receipt signer client")
	}
	if ctx == nil {
		return errors.New("nil receipt signer readiness context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	case <-ctx.Done():
		return ctx.Err()
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodGet, "http://unix"+ReceiptSignerHealthPath, nil,
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
		return errors.New("receipt signer unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("receipt signer is not ready")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
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
		strings.ContainsRune(health.KeyID, '\x00') {
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
