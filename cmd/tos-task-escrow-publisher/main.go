// Command tos-task-escrow-publisher runs the private TaskEscrow key-custody
// sidecar used by tos-protocol's contract-backed Economic Driver.
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
	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
	"github.com/tosnetwork/tos-protocol/pkg/taskescrowpublisher"
)

const (
	configVersion           = "1"
	maxConfigBytes          = int64(256 << 10)
	backendReadinessTimeout = 30 * time.Second
)

type startupConfig struct {
	Version         string                                  `json:"version"`
	Network         string                                  `json:"network"`
	SocketPath      string                                  `json:"socketPath"`
	StatePath       string                                  `json:"statePath"`
	JournalIdentity string                                  `json:"journalIdentity"`
	MaxBodyBytes    int64                                   `json:"maxBodyBytes,omitempty"`
	Backend         taskescrowpublisher.TosctlBackendConfig `json:"backend"`
	Policy          taskescrowpublisher.PublisherPolicy     `json:"policy"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	configPath := strings.TrimSpace(os.Getenv("TOS_TASK_ESCROW_PUBLISHER_CONFIG"))
	if configPath == "" {
		logger.Error("TOS_TASK_ESCROW_PUBLISHER_CONFIG is required")
		os.Exit(2)
	}
	config, err := loadConfig(configPath)
	if err != nil {
		logger.Error("invalid publisher configuration", "error", err)
		os.Exit(2)
	}
	backend, err := taskescrowpublisher.NewTosctlBackend(config.Backend)
	if err != nil {
		logger.Error("configure tosctl backend", "error", err)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "init-journal" {
		defer backend.Close()
		readyCtx, cancel := context.WithTimeout(context.Background(), backendReadinessTimeout)
		err := initializeJournal(readyCtx, config, backend)
		cancel()
		if err != nil {
			logger.Error("initialize TaskEscrow publisher journal", "error", err)
			os.Exit(1)
		}
		binding, _ := taskescrowpublisher.JournalBinding(config.Network, config.Policy, backend.EnrollmentBinding())
		logger.Info("TaskEscrow publisher journal initialized", "identity", config.JournalIdentity, "binding", binding)
		return
	}
	if len(os.Args) != 1 {
		logger.Error("usage: tos-task-escrow-publisher [init-journal]")
		os.Exit(2)
	}
	publisher, err := taskescrowpublisher.Open(taskescrowpublisher.Config{
		Network: config.Network, StatePath: config.StatePath,
		JournalIdentity: config.JournalIdentity,
		Backend:         backend, MaxBodyBytes: config.MaxBodyBytes, Logger: logger,
		Policy: config.Policy,
	})
	if err != nil {
		_ = backend.Close()
		logger.Error("open publisher", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()
	readyCtx, cancel := context.WithTimeout(context.Background(), backendReadinessTimeout)
	err = publisher.CheckReady(readyCtx)
	cancel()
	if err != nil {
		logger.Error("publisher backend is not ready", "error", err)
		os.Exit(1)
	}
	listener, err := receiptsigner.ListenPrivateUnix(config.SocketPath)
	if err != nil {
		logger.Error("listen on private publisher socket", "error", err)
		os.Exit(1)
	}
	defer func() {
		_ = listener.Close()
		_ = os.Remove(config.SocketPath)
	}()
	server := &http.Server{
		Handler: publisher.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	logger.Info("TaskEscrow publisher ready", "network", config.Network, "socket", config.SocketPath)
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logger.Error("publisher shutdown failed", "error", err)
		}
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("publisher server failed", "error", err)
			os.Exit(1)
		}
	}
}

func initializeJournal(ctx context.Context, config startupConfig, backend taskescrowpublisher.Backend) error {
	if ctx == nil || backend == nil {
		return errors.New("journal initialization requires a backend readiness context")
	}
	// Enrollment is permanent for this journal identity. Prove that the exact
	// backend being bound can reach the pinned chain, validate genesis, resolve
	// every configured wallet, and execute the required CLI surface first.
	if err := backend.CheckReady(ctx); err != nil {
		return fmt.Errorf("publisher backend is not ready: %w", err)
	}
	return taskescrowpublisher.InitializeJournal(
		config.StatePath, config.JournalIdentity, config.Network, config.Policy,
		backend.EnrollmentBinding(),
	)
}

func loadConfig(path string) (startupConfig, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return startupConfig{}, errors.New("config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o077 != 0 {
		return startupConfig{}, errors.New("config must be an owner-private regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return startupConfig{}, errors.New("config must be owned by the current process user")
	}
	var config startupConfig
	if err := files.DecodeJSON(path, maxConfigBytes, &config); err != nil {
		return startupConfig{}, err
	}
	if config.Version != configVersion || strings.TrimSpace(config.Network) == "" ||
		config.Backend.Network != config.Network || !filepath.IsAbs(config.SocketPath) ||
		!filepath.IsAbs(config.StatePath) || strings.TrimSpace(config.JournalIdentity) == "" {
		return startupConfig{}, fmt.Errorf("publisher configuration is inconsistent")
	}
	return config, nil
}
