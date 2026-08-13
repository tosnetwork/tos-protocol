package main

import (
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
		config.FundingNanoTOS < nativecore.MinimumRelayFundingNanoTOS || config.FundingNanoTOS > nativecore.MaximumRelayFundingNanoTOS ||
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
	resolver, err := toschain.NewSimplifiedNativeResolver(chain, locator)
	if err != nil {
		return nil, nil, nil, err
	}
	sender, err := chainactionpublisher.NewTosctlBackend(config.Sender)
	if err != nil {
		return nil, nil, nil, err
	}
	relayer := &nativecore.Relayer{Locator: locator, Sender: sender, FundingNanoTOS: config.FundingNanoTOS}
	return relayer, resolver, func() { _ = sender.Close() }, nil
}

func matchesNativeGenesis(chainBase64, nativeDigest string) bool {
	raw, err := base64.StdEncoding.DecodeString(chainBase64)
	return err == nil && len(raw) == 32 && nativeDigest == "sha256:"+hex.EncodeToString(raw)
}
