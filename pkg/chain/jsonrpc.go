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
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/tosnetwork/tos-service-protocol/internal/jsonstrict"
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
	dialTimeout := timeout
	if dialTimeout > 10*time.Second {
		dialTimeout = 10 * time.Second
	}
	transport := &http.Transport{
		// Chain endpoints are an owner-pinned authority boundary. Ambient proxy
		// variables must not silently redirect signed transactions, account
		// state, or finality reads to another origin.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		MaxConnsPerHost:       32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
	}
	return &Client{
		endpoint: endpoint,
		client: &http.Client{
			Timeout: timeout, Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		maxBody: maxBody,
	}, nil
}

func (c *Client) Call(ctx context.Context, method string, params, result interface{}) error {
	if method == "" || len(method) > 128 {
		return errors.New("invalid JSON-RPC method")
	}
	requestID := c.nextID.Add(1)
	requestBody := struct {
		JSONRPC string      `json:"jsonrpc"`
		ID      uint64      `json:"id"`
		Method  string      `json:"method"`
		Params  interface{} `json:"params,omitempty"`
	}{
		JSONRPC: "2.0",
		ID:      requestID,
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
		JSONRPC string `json:"jsonrpc"`
		ID      uint64 `json:"id"`
		// TOS JSON-RPC includes an explicit success discriminator in addition
		// to the standard result/error members. Keep it optional so the client
		// remains compatible with strict JSON-RPC 2.0 servers.
		OK     *bool           `json:"ok,omitempty"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
		// TOS currently emits its numeric error code beside a string-valued
		// error. Standard JSON-RPC servers put both fields in an error object.
		Code *int `json:"code,omitempty"`
	}
	if err := jsonstrict.Decode(body, &envelope); err != nil {
		return fmt.Errorf("decode JSON-RPC response: %w", err)
	}
	if envelope.JSONRPC != "2.0" {
		return errors.New("invalid JSON-RPC version")
	}
	if envelope.ID != requestID {
		return errors.New("JSON-RPC response ID does not match request")
	}
	rpcError, err := decodeRPCError(envelope.Error, envelope.Code)
	if err != nil {
		return err
	}
	if envelope.OK != nil && !*envelope.OK && rpcError == nil {
		return errors.New("TOS JSON-RPC response reports failure without an error")
	}
	hasResult := len(envelope.Result) != 0
	if rpcError != nil && hasResult {
		return errors.New("JSON-RPC response contains both result and error")
	}
	if rpcError != nil {
		return rpcError
	}
	if !hasResult {
		return errors.New("JSON-RPC response has no result")
	}
	if result == nil {
		return nil
	}
	if err := jsonstrict.Decode(envelope.Result, result); err != nil {
		return fmt.Errorf("decode JSON-RPC result: %w", err)
	}
	return nil
}

func decodeRPCError(raw json.RawMessage, tosCode *int) (*RPCError, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		if tosCode != nil {
			return nil, errors.New("TOS JSON-RPC response has an error code without an error")
		}
		return nil, nil
	}
	if raw[0] == '"' {
		if tosCode == nil {
			return nil, errors.New("TOS JSON-RPC string error has no numeric code")
		}
		var message string
		if err := jsonstrict.Decode(raw, &message); err != nil {
			return nil, fmt.Errorf("decode TOS JSON-RPC error: %w", err)
		}
		if message == "" {
			return nil, errors.New("TOS JSON-RPC error message is empty")
		}
		return &RPCError{Code: *tosCode, Message: message}, nil
	}
	if tosCode != nil {
		return nil, errors.New("JSON-RPC response mixes standard and TOS error formats")
	}
	var rpcError RPCError
	if err := jsonstrict.Decode(raw, &rpcError); err != nil {
		return nil, fmt.Errorf("decode JSON-RPC error: %w", err)
	}
	if rpcError.Message == "" {
		return nil, errors.New("JSON-RPC error message is empty")
	}
	return &rpcError, nil
}
