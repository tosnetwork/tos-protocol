package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

type nativeV1GatewayConfig struct {
	Protocol              string                                   `json:"protocol"`
	Network               *nativev1.NetworkDomain                  `json:"network"`
	Endpoints             []string                                 `json:"endpoints"`
	Quorum                int                                      `json:"quorum"`
	QueryTimeoutMillis    uint64                                   `json:"query_timeout_millis,omitempty"`
	MaxResponseBytes      int64                                    `json:"max_response_bytes,omitempty"`
	RegistryWorkchain     int32                                    `json:"registry_workchain"`
	ContractCodeBOCBase64 string                                   `json:"contract_code_boc_base64"`
	ContractCodeHash      string                                   `json:"contract_code_hash"`
	FundingNanoTOS        uint64                                   `json:"funding_nanotos"`
	RelayWindowSeconds    uint64                                   `json:"relay_window_seconds"`
	MaxActionsPerTarget   uint64                                   `json:"max_actions_per_target"`
	MaxFundingPerTarget   uint64                                   `json:"max_funding_per_target_nanotos"`
	MaxActionsPerWallet   uint64                                   `json:"max_actions_per_wallet"`
	MaxFundingPerWallet   uint64                                   `json:"max_funding_per_wallet_nanotos"`
	StateDirectory        string                                   `json:"state_directory"`
	Sender                chainactionpublisher.TosctlBackendConfig `json:"sender"`
}

func buildNativeV1(path string) (*nativecore.Relayer, *toschain.SimplifiedNativeResolver, func(), error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil, nil, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, nil, nil, errors.New("atos_native_v1 config path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, nil, errors.New("atos_native_v1 config file is unavailable")
	}
	stat, ownerOK := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || !ownerOK || stat.Uid != uint32(os.Geteuid()) || info.Size() <= 0 || info.Size() > 2<<20 {
		return nil, nil, nil, errors.New("atos_native_v1 config file is outside bounds")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	var config nativeV1GatewayConfig
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, nil, nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, nil, errors.New("atos_native_v1 config contains trailing JSON")
	}
	if config.Protocol != nativecore.Protocol || config.Network == nil || config.Network.NetworkId == "" || config.ContractCodeBOCBase64 == "" || config.ContractCodeHash == "" ||
		!filepath.IsAbs(config.StateDirectory) || filepath.Clean(config.StateDirectory) != config.StateDirectory ||
		config.FundingNanoTOS < nativecore.MinimumRelayFundingNanoTOS || config.FundingNanoTOS > nativecore.MaximumRelayFundingNanoTOS ||
		config.RelayWindowSeconds < 60 || config.RelayWindowSeconds > 31*24*60*60 ||
		config.MaxActionsPerTarget == 0 || config.MaxActionsPerTarget > config.MaxActionsPerWallet ||
		config.MaxFundingPerTarget < config.FundingNanoTOS || config.MaxFundingPerTarget > config.MaxFundingPerWallet ||
		config.Sender.Network != config.Network.NetworkId || !matchesNativeGenesis(config.Sender.GenesisRootHash, config.Network.GenesisRootHash) ||
		!matchesNativeGenesis(config.Sender.GenesisFileHash, config.Network.GenesisFileHash) {
		return nil, nil, nil, errors.New("invalid atos_native_v1 config")
	}
	chain, err := toschain.New(toschain.Config{Network: config.Network.NetworkId, Endpoints: config.Endpoints, Quorum: config.Quorum,
		QueryTimeout: time.Duration(config.QueryTimeoutMillis) * time.Millisecond, MaxResponseBytes: config.MaxResponseBytes})
	if err != nil {
		return nil, nil, nil, err
	}
	locator, err := nativecore.NewLocator(config.Network, config.RegistryWorkchain, config.ContractCodeBOCBase64, config.ContractCodeHash)
	if err != nil {
		return nil, nil, nil, err
	}
	stateInfo, err := os.Lstat(config.StateDirectory)
	if err != nil || !stateInfo.IsDir() || stateInfo.Mode().Perm()&0o077 != 0 {
		return nil, nil, nil, errors.New("Native state directory must be owner-private")
	}
	checkpointIdentity := sha256.Sum256([]byte(config.Network.NetworkId + "\x00" + config.Network.GenesisRootHash + "\x00" + config.Network.GenesisFileHash))
	resolver, err := toschain.NewSimplifiedNativeResolver(chain, locator,
		filepath.Join(config.StateDirectory, "finalized-checkpoint-"+hex.EncodeToString(checkpointIdentity[:])))
	if err != nil {
		return nil, nil, nil, err
	}
	sender, err := chainactionpublisher.NewTosctlBackend(config.Sender)
	if err != nil {
		return nil, nil, nil, err
	}
	journal, err := nativecore.NewFileRelayJournal(config.StateDirectory)
	if err != nil {
		_ = sender.Close()
		return nil, nil, nil, err
	}
	limits := nativecore.RelaySpendLimits{Window: time.Duration(config.RelayWindowSeconds) * time.Second,
		MaxActionsPerTarget: config.MaxActionsPerTarget, MaxFundingPerTargetNanoTOS: config.MaxFundingPerTarget,
		MaxActionsPerWallet: config.MaxActionsPerWallet, MaxFundingPerWalletNanoTOS: config.MaxFundingPerWallet}
	relayer := &nativecore.Relayer{Locator: locator, Sender: sender, FundingNanoTOS: config.FundingNanoTOS,
		Journal: journal, Resolver: resolver, Limits: limits}
	return relayer, resolver, func() { _ = sender.Close() }, nil
}

func matchesNativeGenesis(chainBase64, nativeDigest string) bool {
	raw, err := base64.StdEncoding.DecodeString(chainBase64)
	return err == nil && len(raw) == 32 && nativeDigest == "sha256:"+hex.EncodeToString(raw)
}
