// Package localrpc configures ConnectRPC clients for private Unix sockets.
package localrpc

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"time"
)

func HTTPClient(socketPath string, timeout time.Duration) (*http.Client, error) {
	if !filepath.IsAbs(socketPath) || timeout <= 0 {
		return nil, errors.New("absolute Unix socket path and positive timeout are required")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: timeout}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:    true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
