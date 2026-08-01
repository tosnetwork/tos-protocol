// Package receiptsigner implements the local, purpose-specific receipt key
// service. It deliberately exposes only the fixed receipt-signing operation.
package receiptsigner

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/protocol"
)

const (
	DefaultMaxMessageBytes = 2 << 20
	DefaultMaxConcurrent   = 16
	MaxMessageBytes        = 4 << 20
	MaxConcurrent          = 128
)

type Config struct {
	KeyID           string
	PrivateKey      ed25519.PrivateKey
	MaxMessageBytes int
	MaxConcurrent   int
}

type Handler struct {
	mutex           sync.RWMutex
	keyID           string
	privateKey      ed25519.PrivateKey
	maxMessageBytes int64
	slots           chan struct{}
	publicKey       string
	closed          bool
}

type signRequest struct {
	Version           string `json:"version"`
	Payload           []byte `json:"payload"`
	IssuedUnixMillis  int64  `json:"issuedUnixMillis"`
	ExpiresUnixMillis int64  `json:"expiresUnixMillis"`
}

func NewHandler(config Config) (*Handler, error) {
	if len(config.PrivateKey) != ed25519.PrivateKeySize ||
		config.MaxMessageBytes <= 0 || config.MaxMessageBytes > MaxMessageBytes ||
		config.MaxConcurrent <= 0 || config.MaxConcurrent > MaxConcurrent ||
		config.KeyID == "" || len(config.KeyID) > 512 ||
		strings.ContainsRune(config.KeyID, '\x00') {
		return nil, errors.New("invalid receipt signer configuration")
	}
	return &Handler{
		keyID:           config.KeyID,
		privateKey:      append(ed25519.PrivateKey(nil), config.PrivateKey...),
		maxMessageBytes: int64(config.MaxMessageBytes),
		slots:           make(chan struct{}, config.MaxConcurrent),
		publicKey: base64.RawURLEncoding.EncodeToString(
			config.PrivateKey.Public().(ed25519.PublicKey),
		),
	}, nil
}

func (h *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	if request.URL.Path == localrpc.ReceiptSignerHealthPath {
		if request.Method != http.MethodGet {
			response.Header().Set("Allow", http.MethodGet)
			http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if request.URL.RawQuery != "" || request.ContentLength != 0 {
			http.Error(response, "invalid health request", http.StatusBadRequest)
			return
		}
		keyID, publicKey, ready := h.identity()
		if !ready {
			http.Error(response, "signer unavailable", http.StatusServiceUnavailable)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(struct {
			Status    string `json:"status"`
			KeyID     string `json:"keyId"`
			PublicKey string `json:"publicKey"`
		}{Status: "ready", KeyID: keyID, PublicKey: publicKey})
		return
	}
	if request.URL.Path != localrpc.ReceiptSignerPath {
		http.Error(response, "not found", http.StatusNotFound)
		return
	}
	if request.Method != http.MethodPost {
		response.Header().Set("Allow", http.MethodPost)
		http.Error(response, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	mediaType, _, err := mime.ParseMediaType(request.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(response, "unsupported media type", http.StatusUnsupportedMediaType)
		return
	}
	if request.ContentLength > h.maxMessageBytes {
		http.Error(response, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	case <-request.Context().Done():
		return
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, h.maxMessageBytes+1))
	if err != nil || int64(len(body)) > h.maxMessageBytes {
		http.Error(response, "invalid request", http.StatusRequestEntityTooLarge)
		return
	}
	var input signRequest
	if err := jsonstrict.Decode(body, &input); err != nil ||
		input.Version != "1" || len(input.Payload) > identity.MaxPayloadBytes {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	issuedAt := time.UnixMilli(input.IssuedUnixMillis).UTC()
	expiresAt := time.UnixMilli(input.ExpiresUnixMillis).UTC()
	if !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > identity.MaxLifetime {
		http.Error(response, "invalid request", http.StatusBadRequest)
		return
	}
	envelope, err := h.sign(
		append([]byte(nil), input.Payload...), issuedAt, expiresAt,
	)
	if errors.Is(err, errSignerClosed) {
		http.Error(response, "signer unavailable", http.StatusServiceUnavailable)
		return
	}
	if err != nil {
		http.Error(response, "signing failed", http.StatusInternalServerError)
		return
	}
	encoded, err := json.Marshal(envelope)
	if err != nil || int64(len(encoded)) > h.maxMessageBytes {
		http.Error(response, "signing failed", http.StatusInternalServerError)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	_, _ = response.Write(encoded)
}

var errSignerClosed = errors.New("receipt signer is closed")

func (h *Handler) sign(
	payload []byte,
	issuedAt time.Time,
	expiresAt time.Time,
) (identity.Envelope, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.closed || len(h.privateKey) != ed25519.PrivateKeySize {
		return identity.Envelope{}, errSignerClosed
	}
	return identity.Sign(
		h.privateKey, protocol.ReceiptDomain, h.keyID,
		payload, issuedAt, expiresAt,
	)
}

// Close waits for active signatures to leave the key read-side critical
// section, clears the software private-key buffer, and permanently disables
// both readiness and signing. It is safe to call more than once.
func (h *Handler) Close() error {
	if h == nil {
		return nil
	}
	h.mutex.Lock()
	defer h.mutex.Unlock()
	if h.closed {
		return nil
	}
	for index := range h.privateKey {
		h.privateKey[index] = 0
	}
	h.privateKey = nil
	h.closed = true
	return nil
}

func (h *Handler) identity() (string, string, bool) {
	if h == nil {
		return "", "", false
	}
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	if h.closed || len(h.privateKey) != ed25519.PrivateKeySize {
		return "", "", false
	}
	return h.keyID, h.publicKey, true
}
