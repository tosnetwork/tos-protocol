// Command tos-native-registry-publisher runs the enrolled Native Registry
// mutation sidecar. It holds only the relayer wallet; Native authority remains
// in the signed action and finalized Registry contracts.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistrypublisher"
	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	configVersion  = "1"
	maxConfigBytes = int64(2 << 20)
	readyTimeout   = 30 * time.Second
)

type startupConfig struct {
	Version                  string                                   `json:"version"`
	SocketPath               string                                   `json:"socket_path"`
	StatePath                string                                   `json:"state_path"`
	JournalIdentity          string                                   `json:"journal_identity"`
	MaxBodyBytes             int64                                    `json:"max_body_bytes,omitempty"`
	Network                  nativeprotocol.NetworkDomain             `json:"network"`
	Endpoints                []string                                 `json:"endpoints"`
	Quorum                   int                                      `json:"quorum"`
	QueryTimeoutMillis       uint64                                   `json:"query_timeout_millis,omitempty"`
	MaxResponseBytes         int64                                    `json:"max_response_bytes,omitempty"`
	RegistryWorkchain        int32                                    `json:"registry_workchain"`
	ContractCodeBOCBase64    string                                   `json:"contract_code_boc_base64"`
	ContractCodeHash         string                                   `json:"contract_code_hash"`
	FundingNanoTOS           uint64                                   `json:"funding_nanotos"`
	ObservationPollMillis    uint64                                   `json:"observation_poll_millis,omitempty"`
	ObservationTimeoutMillis uint64                                   `json:"observation_timeout_millis,omitempty"`
	Sender                   chainactionpublisher.TosctlBackendConfig `json:"sender"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	path := strings.TrimSpace(os.Getenv("TOS_NATIVE_REGISTRY_PUBLISHER_CONFIG"))
	config, err := loadConfig(path)
	if err != nil {
		logger.Error("invalid Native Registry publisher configuration", "error", err)
		os.Exit(2)
	}
	backend, err := buildBackend(config)
	if err != nil {
		logger.Error("configure Native Registry publisher backend", "error", err)
		os.Exit(2)
	}
	if len(os.Args) == 2 && os.Args[1] == "init-journal" {
		defer backend.Close()
		ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
		err := nativeregistrypublisher.Enroll(ctx, config.StatePath, config.JournalIdentity, policy(config, backend), backend)
		cancel()
		if err != nil {
			logger.Error("initialize Native Registry publisher journal", "error", err)
			os.Exit(1)
		}
		logger.Info("Native Registry publisher journal initialized", "identity", config.JournalIdentity)
		return
	}
	if len(os.Args) != 1 {
		logger.Error("usage: tos-native-registry-publisher [init-journal]")
		os.Exit(2)
	}
	publisher, err := nativeregistrypublisher.Open(config.StatePath, config.JournalIdentity, policy(config, backend), backend)
	if err != nil {
		_ = backend.Close()
		logger.Error("open Native Registry publisher", "error", err)
		os.Exit(1)
	}
	defer publisher.Close()
	ctx, cancel := context.WithTimeout(context.Background(), readyTimeout)
	err = publisher.CheckReady(ctx)
	cancel()
	if err != nil {
		logger.Error("Native Registry publisher is not ready", "error", err)
		os.Exit(1)
	}
	api, err := nativeregistrypublisher.NewServer(publisher, config.MaxBodyBytes)
	if err != nil {
		logger.Error("configure Native Registry publisher API", "error", err)
		os.Exit(1)
	}
	listener, err := receiptsigner.ListenPrivateUnix(config.SocketPath)
	if err != nil {
		logger.Error("listen on Native Registry publisher socket", "error", err)
		os.Exit(1)
	}
	defer func() { _ = listener.Close(); _ = os.Remove(config.SocketPath) }()
	httpServer := &http.Server{Handler: api.Handler(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	stopCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	logger.Info("Native Registry publisher ready", "network", config.Network.NetworkID, "socket", config.SocketPath)
	select {
	case <-stopCtx.Done():
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("Native Registry publisher shutdown failed", "error", err)
		}
	case err := <-done:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Native Registry publisher server failed", "error", err)
			os.Exit(1)
		}
	}
}

func buildBackend(config startupConfig) (*nativeregistrypublisher.ChainBackend, error) {
	queryTimeout := time.Duration(config.QueryTimeoutMillis) * time.Millisecond
	chain, err := toschain.New(toschain.Config{Network: config.Network.NetworkID, Endpoints: config.Endpoints,
		Quorum: config.Quorum, QueryTimeout: queryTimeout, MaxResponseBytes: config.MaxResponseBytes})
	if err != nil {
		return nil, err
	}
	locator, err := nativeexecution.NewObjectLocator(config.Network, config.RegistryWorkchain,
		config.ContractCodeBOCBase64, config.ContractCodeHash)
	if err != nil {
		return nil, err
	}
	resolver, err := toschain.NewNativeRegistryResolver(chain, config.Network, locator)
	if err != nil {
		return nil, err
	}
	sender, err := chainactionpublisher.NewTosctlBackend(config.Sender)
	if err != nil {
		return nil, err
	}
	poll := time.Duration(config.ObservationPollMillis) * time.Millisecond
	timeout := time.Duration(config.ObservationTimeoutMillis) * time.Millisecond
	backend, err := nativeregistrypublisher.NewChainBackend(locator, resolver, sender, config.FundingNanoTOS, poll, timeout)
	if err != nil {
		_ = sender.Close()
		return nil, err
	}
	return backend, nil
}

func policy(config startupConfig, backend *nativeregistrypublisher.ChainBackend) nativeregistrypublisher.Policy {
	return nativeregistrypublisher.Policy{NetworkID: config.Network.NetworkID,
		GenesisRootHash: config.Network.GenesisRootHash, GenesisFileHash: config.Network.GenesisFileHash,
		RegistryWorkchain: config.RegistryWorkchain, ContractCodeHash: config.ContractCodeHash,
		LocatorVersion: nativeexecution.LocatorVersion, ActionVersion: nativeexecution.Version,
		PayerIdentity: backend.PayerIdentity()}
}

func loadConfig(path string) (startupConfig, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return startupConfig{}, errors.New("config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
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
	if config.Version != configVersion || config.Network.Validate() != nil || config.Sender.Network != config.Network.NetworkID ||
		!sameGenesisHash(config.Sender.GenesisRootHash, config.Network.GenesisRootHash) ||
		!sameGenesisHash(config.Sender.GenesisFileHash, config.Network.GenesisFileHash) ||
		!filepath.IsAbs(config.SocketPath) || !filepath.IsAbs(config.StatePath) || strings.TrimSpace(config.JournalIdentity) == "" ||
		config.FundingNanoTOS < nativeregistrypublisher.MinimumFundingNanoTOS || config.FundingNanoTOS > 100_000_000_000 || config.ContractCodeBOCBase64 == "" || config.ContractCodeHash == "" {
		return startupConfig{}, fmt.Errorf("Native Registry publisher configuration is inconsistent")
	}
	return config, nil
}

// The JSON-RPC wire exposes genesis hashes as padded standard Base64, while
// the frozen Native network domain uses sha256:<lowercase hex>. Decode both
// representations before comparison so the startup gate is strict without
// making a valid configuration impossible to express.
func sameGenesisHash(chainBase64, nativeDigest string) bool {
	raw, err := base64.StdEncoding.DecodeString(chainBase64)
	if err != nil || len(raw) != 32 {
		return false
	}
	return nativeDigest == "sha256:"+hex.EncodeToString(raw)
}
