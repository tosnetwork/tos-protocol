// Package chain contains the stable, bounded boundary to TOS JSON-RPC. It
// deliberately exposes no validator-private implementation details.
package chain

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("TOS JSON-RPC error %d: %s", e.Code, e.Message)
}

type Client struct {
	endpoint string
	client   *http.Client
	maxBody  int64
	nextID   atomic.Uint64
}

func NewClient(endpoint string, timeout time.Duration, maxBody int64) (*Client, error) {
	if endpoint == "" || timeout <= 0 || maxBody <= 0 {
		return nil, errors.New("invalid JSON-RPC client configuration")
	}
	return &Client{
		endpoint: endpoint,
		client:   &http.Client{Timeout: timeout},
		maxBody:  maxBody,
	}, nil
}

func (c *Client) Call(ctx context.Context, method string, params, result interface{}) error {
	if method == "" || len(method) > 128 {
		return errors.New("invalid JSON-RPC method")
	}
	requestBody := struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      uint64      `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params,omitempty"`
	}{
		JSONRPC: "2.0",
		ID:      c.nextID.Add(1),
		Method:  method,
		Params:  params,
	}
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("encode JSON-RPC request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create JSON-RPC request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("execute JSON-RPC request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("JSON-RPC HTTP status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, c.maxBody+1))
	if err != nil {
		return fmt.Errorf("read JSON-RPC response: %w", err)
	}
	if int64(len(body)) > c.maxBody {
		return errors.New("JSON-RPC response exceeds byte limit")
	}
	var envelope struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      uint64          `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *RPCError       `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("decode JSON-RPC response: %w", err)
	}
	if envelope.Error != nil {
		return envelope.Error
	}
	if envelope.JSONRPC != "2.0" {
		return errors.New("invalid JSON-RPC version")
	}
	if result == nil {
		return nil
	}
	if len(envelope.Result) == 0 {
		return errors.New("JSON-RPC response has no result")
	}
	if err := json.Unmarshal(envelope.Result, result); err != nil {
		return fmt.Errorf("decode JSON-RPC result: %w", err)
	}
	return nil
}
