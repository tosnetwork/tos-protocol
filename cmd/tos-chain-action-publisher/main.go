// Command tos-chain-action-publisher runs the durable private chain anchor
// publisher used by the chain-backed ATOS Authority.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/files"
	"github.com/tosnetwork/tos-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
)

type config struct {
	Version         string                                   `json:"version"`
	Network         string                                   `json:"network"`
	SocketPath      string                                   `json:"socketPath"`
	StatePath       string                                   `json:"statePath"`
	JournalIdentity string                                   `json:"journalIdentity"`
	Policy          chainactionpublisher.SpendingPolicy      `json:"policy"`
	Backend         chainactionpublisher.TosctlBackendConfig `json:"backend"`
	MaxBodyBytes    int64                                    `json:"maxBodyBytes,omitempty"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	path := strings.TrimSpace(os.Getenv("TOS_CHAIN_ACTION_PUBLISHER_CONFIG"))
	if path == "" {
		logger.Error("TOS_CHAIN_ACTION_PUBLISHER_CONFIG is required")
		os.Exit(2)
	}
	c, err := loadConfig(path)
	if err != nil {
		logger.Error("invalid publisher config", "error", err)
		os.Exit(2)
	}
	backend, err := chainactionpublisher.NewTosctlBackend(c.Backend)
	if err != nil {
		logger.Error("invalid backend", "error", err)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "init-journal" {
		defer backend.Close()
		if err := chainactionpublisher.InitializeJournal(c.StatePath, c.JournalIdentity, c.Network, c.Policy, backend.EnrollmentBinding()); err != nil {
			logger.Error("initialize publisher journal", "error", err)
			os.Exit(1)
		}
		logger.Info("publisher journal initialized", "identity", c.JournalIdentity)
		return
	}
	if len(os.Args) != 1 {
		logger.Error("usage: tos-chain-action-publisher [init-journal]")
		os.Exit(2)
	}
	publisher, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: c.Network, StatePath: c.StatePath, JournalIdentity: c.JournalIdentity, Policy: c.Policy, Backend: backend, MaxBodyBytes: c.MaxBodyBytes, Logger: logger})
	if err != nil {
		logger.Error("open publisher", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	err = publisher.CheckReady(ctx)
	cancel()
	if err != nil {
		logger.Error("backend not ready", "error", err)
		os.Exit(1)
	}
	listener, err := receiptsigner.ListenPrivateUnix(c.SocketPath)
	if err != nil {
		logger.Error("listen", "error", err)
		os.Exit(1)
	}
	defer os.Remove(c.SocketPath)
	server := &http.Server{Handler: publisher.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute}
	runCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-runCtx.Done():
		shutdown, c := context.WithTimeout(context.Background(), 15*time.Second)
		defer c()
		_ = server.Shutdown(shutdown)
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server failed", "error", err)
			os.Exit(1)
		}
	}
}

func loadConfig(path string) (config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return config{}, errors.New("config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return config{}, errors.New("config must be an owner-private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return config{}, errors.New("config must be owned by the current process user")
	}
	var c config
	if err := files.DecodeJSON(path, 256<<10, &c); err != nil {
		return config{}, err
	}
	if c.Version != "1" || strings.TrimSpace(c.Network) == "" || !filepath.IsAbs(c.SocketPath) ||
		filepath.Clean(c.SocketPath) != c.SocketPath || !filepath.IsAbs(c.StatePath) ||
		filepath.Clean(c.StatePath) != c.StatePath || strings.TrimSpace(c.JournalIdentity) == "" ||
		c.Backend.Network != c.Network || c.Backend.Payer != c.Policy.Payer {
		return config{}, fmt.Errorf("publisher configuration is inconsistent")
	}
	return c, nil
}
