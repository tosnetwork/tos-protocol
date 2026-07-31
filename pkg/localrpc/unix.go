// Package localrpc configures ConnectRPC clients for private Unix sockets.
package localrpc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func HTTPClient(socketPath string, timeout time.Duration) (*http.Client, error) {
	if !filepath.IsAbs(socketPath) || timeout <= 0 {
		return nil, errors.New("absolute Unix socket path and positive timeout are required")
	}
	return httpClient(socketPath, timeout, timeout)
}

func httpClient(
	socketPath string,
	dialTimeout, requestTimeout time.Duration,
) (*http.Client, error) {
	if !filepath.IsAbs(socketPath) || filepath.Clean(socketPath) != socketPath ||
		dialTimeout <= 0 || requestTimeout <= 0 {
		return nil, errors.New("invalid private Unix socket client configuration")
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := validatePrivateSocket(socketPath); err != nil {
				return nil, err
			}
			dialer := net.Dialer{Timeout: dialTimeout}
			return dialer.DialContext(ctx, "unix", socketPath)
		},
		DisableCompression:    true,
		MaxIdleConns:          8,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
	}
	return &http.Client{Transport: transport, Timeout: requestTimeout}, nil
}

func validatePrivateSocket(socketPath string) error {
	parent := filepath.Dir(socketPath)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect private Unix socket directory: %w", err)
	}
	if !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 ||
		parentInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("Unix socket directory is not private")
	}
	if err := requireCurrentOwner(parentInfo); err != nil {
		return fmt.Errorf("Unix socket directory: %w", err)
	}

	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("inspect private Unix socket: %w", err)
	}
	if socketInfo.Mode()&os.ModeSocket == 0 ||
		socketInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("Unix socket is not a private socket")
	}
	if err := requireCurrentOwner(socketInfo); err != nil {
		return fmt.Errorf("Unix socket: %w", err)
	}
	return nil
}

func requireCurrentOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine owner")
	}
	if int(stat.Uid) != os.Geteuid() {
		return errors.New("owner does not match current process")
	}
	return nil
}
