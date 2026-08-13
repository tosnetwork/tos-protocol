package localrpc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistrypublisher"
)

type NativeRegistryPublisherClientConfig struct {
	SocketPath, JournalIdentity, JournalBinding string
	Timeout                                     time.Duration
	MaxMessageBytes                             int
}
type NativeRegistryPublisherClient struct {
	client                          *http.Client
	journalIdentity, journalBinding string
	maxBytes                        int
}
type nativeRegistryWireRequest struct {
	ActionID       string                    `json:"action_id"`
	SemanticDigest string                    `json:"semantic_digest"`
	Submission     nativeregistry.Submission `json:"submission"`
}
type nativeRegistryResponse struct{ Version, Code, Status, ActionID, JournalIdentity, JournalBinding string }

func NewNativeRegistryPublisherClient(config NativeRegistryPublisherClientConfig) (*NativeRegistryPublisherClient, error) {
	if config.Timeout == 0 {
		config.Timeout = 100 * time.Second
	}
	if config.MaxMessageBytes == 0 {
		config.MaxMessageBytes = 256 << 10
	}
	if strings.TrimSpace(config.JournalIdentity) == "" || strings.TrimSpace(config.JournalBinding) == "" || config.Timeout <= 0 || config.Timeout > 2*time.Minute || config.MaxMessageBytes <= 0 || config.MaxMessageBytes > 2<<20 {
		return nil, errors.New("invalid Native registry publisher client configuration")
	}
	client, err := HTTPClient(config.SocketPath, config.Timeout)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &NativeRegistryPublisherClient{client: client, journalIdentity: config.JournalIdentity, journalBinding: config.JournalBinding, maxBytes: config.MaxMessageBytes}, nil
}
func (c *NativeRegistryPublisherClient) CheckReady(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://unix"+nativeregistrypublisher.HealthPath, nil)
	if err != nil {
		return err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return errors.New("Native registry publisher unavailable")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxBytes)+1))
	if err != nil || len(raw) > c.maxBytes || response.StatusCode != http.StatusOK {
		return errors.New("Native registry publisher is not ready")
	}
	var value map[string]string
	if jsonstrict.Decode(raw, &value) != nil || value["version"] != nativeregistrypublisher.ProtocolVersion || value["journal_identity"] != c.journalIdentity || value["journal_binding"] != c.journalBinding {
		return errors.New("Native registry publisher readiness binding mismatch")
	}
	return nil
}
func (c *NativeRegistryPublisherClient) Resolve(ctx context.Context, submission nativeregistry.Submission, actionID, digest string) error {
	return c.callBound(ctx, nativeregistrypublisher.ResolvePath, nativeRegistryWireRequest{ActionID: actionID, SemanticDigest: digest, Submission: submission}, true)
}
func (c *NativeRegistryPublisherClient) Publish(ctx context.Context, submission nativeregistry.Submission, actionID, digest string) error {
	return c.callBound(ctx, nativeregistrypublisher.ActionPath, nativeRegistryWireRequest{ActionID: actionID, SemanticDigest: digest, Submission: submission}, false)
}
func (c *NativeRegistryPublisherClient) callBound(ctx context.Context, path string, wire nativeRegistryWireRequest, allowNotFound bool) error {
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) > c.maxBytes {
		return errors.New("Native registry publisher request exceeds limit")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return errors.New("Native registry publisher unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(c.maxBytes)+1))
	if err != nil || len(body) > c.maxBytes {
		return errors.New("Native registry publisher response exceeds limit")
	}
	var value map[string]string
	if jsonstrict.Decode(body, &value) != nil || value["version"] != nativeregistrypublisher.ProtocolVersion || value["action_id"] != wire.ActionID {
		return errors.New("Native registry publisher returned malformed evidence")
	}
	bound := value["journal_identity"] == c.journalIdentity && value["journal_binding"] == c.journalBinding
	if response.StatusCode == http.StatusNotFound && allowNotFound && value["code"] == "action_not_found" && bound {
		return nativeregistry.ErrPublisherNotFound
	}
	if response.StatusCode != http.StatusOK {
		if value["code"] == "action_pending" && bound {
			return nativeregistry.ErrPublisherPending
		}
		return nativeregistry.ErrAmbiguous
	}
	expectedStatus := "accepted"
	if allowNotFound {
		expectedStatus = "completed"
	}
	if !bound || value["status"] != expectedStatus || value["code"] != "" {
		return errors.New("Native registry publisher returned unbound success evidence")
	}
	return nil
}
