package chainactionpublisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-service-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-service-protocol/pkg/chain"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// TosctlBackendConfig is the concrete TOS wallet backend. Exact nanoTOS and
// non-interactive flags require the coordinated Phase 4B-1 tosctl build.
type TosctlBackendConfig struct {
	Network         string `json:"network"`
	Binary          string `json:"binary"`
	ConfigPath      string `json:"configPath"`
	VaultURL        string `json:"vaultUrl"`
	RPCURL          string `json:"rpcUrl"`
	GenesisRootHash string `json:"genesisRootHash"`
	GenesisFileHash string `json:"genesisFileHash"`
	WalletName      string `json:"walletName"`
	Payer           string `json:"payer"`
}
type TosctlBackend struct {
	network, binary, vaultURL, walletName, payer string
	binaryIdentity                               chainExecutableIdentity
	configFile                                   *os.File
	client                                       *chain.Client
	genesisRootHash, genesisFileHash             string
	enrollmentBinding                            string
	configMu                                     sync.Mutex
}

const PreparedContractCellVersion = "tosctl.wallet-prepared-send.v1"

type preparedContractCell struct {
	Version          string `json:"version"`
	MessageBOCBase64 string `json:"message_boc_base64"`
	Wallet           string `json:"wallet"`
	Payer            string `json:"payer"`
	Destination      string `json:"destination"`
	AmountNanoTOS    uint64 `json:"amount_nanotos"`
	BodyHash         string `json:"body_hash"`
	StateInitHash    string `json:"state_init_hash"`
}

func NewTosctlBackend(c TosctlBackendConfig) (*TosctlBackend, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("production tosctl chain publisher is supported only on Linux")
	}
	if c.Network == "" || c.WalletName == "" || c.VaultURL == "" || !filepath.IsAbs(c.Binary) || filepath.Clean(c.Binary) != c.Binary || !filepath.IsAbs(c.ConfigPath) || filepath.Clean(c.ConfigPath) != c.ConfigPath {
		return nil, errors.New("invalid tosctl chain publisher config")
	}
	binaryIdentity, err := captureChainExecutableIdentity(c.Binary)
	if err != nil {
		return nil, fmt.Errorf("tosctl binary: %w", err)
	}
	configInfo, err := os.Lstat(c.ConfigPath)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("tosctl config must be an owner-private regular file")
	}
	stat, ok := configInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("tosctl config owner mismatch")
	}
	rawConfig, err := os.ReadFile(c.ConfigPath)
	if err != nil || len(rawConfig) > 2<<20 {
		return nil, errors.New("read tosctl RPC config")
	}
	configuredRPC, err := tosctlRPCURL(rawConfig)
	if err != nil || configuredRPC != c.RPCURL {
		return nil, errors.New("tosctl send RPC does not match recovery RPC")
	}
	if !validBase64Hash(c.GenesisRootHash) || !validBase64Hash(c.GenesisFileHash) {
		return nil, errors.New("invalid expected TOS genesis identity")
	}
	payer, err := toschain.CanonicalAddress(c.Payer)
	if err != nil {
		return nil, err
	}
	client, err := chain.NewClient(c.RPCURL, 20*time.Second, 8<<20)
	if err != nil {
		return nil, err
	}
	configFile, err := pinnedConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	bindingBytes, _ := json.Marshal(struct {
		Version, Network, RPCURL, GenesisRootHash, GenesisFileHash, WalletName, Payer, ConfigDigest, BinaryDigest, VaultDigest string
	}{"tos-service-sender-v1", c.Network, c.RPCURL, c.GenesisRootHash, c.GenesisFileHash, c.WalletName, payer, sha256Text(rawConfig), binaryIdentity.digest, sha256Text([]byte(strings.TrimSpace(c.VaultURL)))})
	return &TosctlBackend{network: c.Network, binary: c.Binary, binaryIdentity: binaryIdentity, configFile: configFile, vaultURL: c.VaultURL, walletName: c.WalletName, payer: payer, client: client, genesisRootHash: c.GenesisRootHash, genesisFileHash: c.GenesisFileHash, enrollmentBinding: sha256Text(bindingBytes)}, nil
}

func (b *TosctlBackend) EnrollmentBinding() string { return b.enrollmentBinding }
func (b *TosctlBackend) PayerIdentity() string {
	if b == nil {
		return ""
	}
	return b.payer
}

// SendContractCell exposes the already hardened wallet boundary for
// production contract publishers. Callers supply exact canonical BOCs; the
// executable/config/wallet/network identity remains pinned by this backend.
func (b *TosctlBackend) SendContractCell(ctx context.Context, destination string, amountNanoTOS uint64, bodyBOCBase64, stateInitBOCBase64 string) error {
	messageBOC, digest, err := b.PrepareContractCell(ctx, destination, amountNanoTOS, bodyBOCBase64, stateInitBOCBase64)
	if err != nil {
		return err
	}
	return b.BroadcastPreparedContractCell(ctx, messageBOC, digest)
}

func (b *TosctlBackend) PrepareContractCell(ctx context.Context, destination string, amountNanoTOS uint64, bodyBOCBase64, stateInitBOCBase64 string) (string, string, error) {
	if b == nil || amountNanoTOS == 0 || !validBOC(bodyBOCBase64) || (stateInitBOCBase64 != "" && !validBOC(stateInitBOCBase64)) {
		return "", "", errors.New("invalid contract-cell send")
	}
	destination, err := toschain.CanonicalAddress(destination)
	if err != nil {
		return "", "", err
	}
	bodyHash, err := cellHash(bodyBOCBase64)
	if err != nil {
		return "", "", errors.New("invalid contract body BOC")
	}
	stateInitHash := ""
	if stateInitBOCBase64 != "" {
		stateInitHash, err = cellHash(stateInitBOCBase64)
		if err != nil {
			return "", "", errors.New("invalid contract StateInit BOC")
		}
	}
	args := []string{"wallet", "send", "--from", b.walletName, "--to", destination,
		"--amount-nanotos", strconv.FormatUint(amountNanoTOS, 10), "--body-boc", bodyBOCBase64}
	if stateInitBOCBase64 != "" {
		args = append(args, "--state-init-boc", stateInitBOCBase64)
	}
	args = append(args, "--build-only")
	out, err := b.run(ctx, args...)
	if err != nil {
		return "", "", err
	}
	return validatePreparedContractCell(out, b.walletName, b.payer, destination, amountNanoTOS, bodyHash, stateInitHash)
}

func validatePreparedContractCell(out []byte, wallet, payer, destination string, amountNanoTOS uint64, bodyHash, stateInitHash string) (string, string, error) {
	var response preparedContractCell
	if jsonstrict.Decode(out, &response) != nil || response.Version != PreparedContractCellVersion ||
		response.Wallet != wallet || response.Payer != payer || response.Destination != destination ||
		response.AmountNanoTOS != amountNanoTOS || response.BodyHash != bodyHash || response.StateInitHash != stateInitHash {
		return "", "", errors.New("tosctl returned invalid prepared contract message")
	}
	raw, err := base64.StdEncoding.DecodeString(response.MessageBOCBase64)
	if err != nil || len(raw) == 0 || len(raw) > 256<<10 || base64.StdEncoding.EncodeToString(raw) != response.MessageBOCBase64 {
		return "", "", errors.New("tosctl returned invalid prepared contract BOC")
	}
	return response.MessageBOCBase64, sha256Text(raw), nil
}

func cellHash(value string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	root, err := cell.FromBOC(raw)
	if err != nil || root == nil {
		return "", errors.New("invalid Cell BOC")
	}
	return "tvm-cell-sha256:" + hex.EncodeToString(root.Hash()), nil
}

func validBOC(value string) bool {
	raw, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(raw) > 0 && len(raw) <= 256<<10 && base64.StdEncoding.EncodeToString(raw) == value
}

func (b *TosctlBackend) BroadcastPreparedContractCell(ctx context.Context, messageBOCBase64, messageDigest string) error {
	if b == nil {
		return errors.New("invalid prepared contract message")
	}
	raw, err := base64.StdEncoding.DecodeString(messageBOCBase64)
	if err != nil || len(raw) == 0 || len(raw) > 256<<10 || base64.StdEncoding.EncodeToString(raw) != messageBOCBase64 || sha256Text(raw) != messageDigest {
		return errors.New("prepared contract message digest mismatch")
	}
	var response struct {
		Status int `json:"status"`
	}
	if err := b.client.Call(ctx, "sendBoc", struct {
		BOC string `json:"boc"`
	}{messageBOCBase64}, &response); err != nil {
		return err
	}
	if response.Status != 1 {
		return errors.New("TOS rejected prepared contract message")
	}
	return nil
}

func sha256Text(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}

type tosctlWallet struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Balance    any    `json:"balance"`
	State      any    `json:"state"`
	WalletType any    `json:"wallet_type"`
	Seqno      any    `json:"seqno"`
}

func (b *TosctlBackend) CheckReady(ctx context.Context) error {
	if b == nil || b.client == nil {
		return errors.New("invalid tosctl backend")
	}
	var master struct {
		Type string `json:"@type"`
		Last struct {
			Type      string `json:"@type"`
			Workchain int32  `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     uint64 `json:"seqno"`
			RootHash  string `json:"root_hash"`
			FileHash  string `json:"file_hash"`
		} `json:"last"`
		StateRootHash string `json:"state_root_hash"`
		Init          struct {
			Type      string `json:"@type"`
			Workchain int32  `json:"workchain"`
			Shard     string `json:"shard"`
			Seqno     uint64 `json:"seqno"`
			RootHash  string `json:"root_hash"`
			FileHash  string `json:"file_hash"`
		} `json:"init"`
	}
	if err := b.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return err
	}
	if master.Init.RootHash != b.genesisRootHash || master.Init.FileHash != b.genesisFileHash {
		return errors.New("TOS genesis identity mismatch")
	}
	out, err := b.run(ctx, "wallet", "ls", "--format", "json")
	if err != nil {
		return err
	}
	var wallets []tosctlWallet
	if json.Unmarshal(out, &wallets) != nil {
		return errors.New("invalid tosctl wallet list")
	}
	found := false
	for _, wallet := range wallets {
		address, e := toschain.NormalizeAddress(wallet.Address)
		if e == nil && wallet.Name == b.walletName && address == b.payer {
			found = true
		}
	}
	if !found {
		return errors.New("configured tosctl payer wallet is unavailable")
	}
	return nil
}

func (b *TosctlBackend) CheckContractCellReady(ctx context.Context) error {
	if err := b.CheckReady(ctx); err != nil {
		return err
	}
	help, err := b.run(ctx, "wallet", "send", "--help")
	if err != nil {
		return errors.New("tosctl contract-cell send capability is unavailable")
	}
	for _, required := range []string{"--amount-nanotos", "--body-boc", "--state-init-boc", "--build-only", "--config-fd", "--config-format"} {
		if !bytes.Contains(help, []byte(required)) {
			return errors.New("tosctl contract-cell send capability mismatch")
		}
	}
	return nil
}
func (b *TosctlBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	if b == nil {
		return nil, errors.New("tosctl backend is closed")
	}
	b.configMu.Lock()
	defer b.configMu.Unlock()
	if b.configFile == nil {
		return nil, errors.New("tosctl backend is closed")
	}
	executable, err := openVerifiedChainExecutable(b.binary, b.binaryIdentity)
	if err != nil {
		return nil, err
	}
	defer executable.Close()
	if _, err := b.configFile.Seek(0, 0); err != nil {
		return nil, errors.New("seek pinned tosctl config")
	}
	args = append(args, "--config-fd", "3", "--config-format", "json")
	command := exec.CommandContext(ctx, "/proc/self/fd/4", args...)
	command.ExtraFiles = []*os.File{b.configFile, executable}
	command.Env = backendEnvironment(b.vaultURL)
	stdout := chainLimitedBuffer{limit: 2 << 20}
	stderr := chainLimitedBuffer{limit: 2 << 20}
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		if stdout.overflow || stderr.overflow {
			return nil, errors.New("tosctl output too large")
		}
		return nil, fmt.Errorf("tosctl failed: %s", strings.TrimSpace(string(stderr.Bytes())))
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("tosctl output too large")
	}
	return stdout.Bytes(), nil
}

type chainLimitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *chainLimitedBuffer) Write(data []byte) (int, error) {
	if b.limit <= 0 {
		return 0, errors.New("invalid output limit")
	}
	original := len(data)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.overflow = true
		return original, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(data)
	return original, nil
}

func (b *chainLimitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

type chainExecutableIdentity struct {
	device uint64
	inode  uint64
	size   int64
	digest string
}

func captureChainExecutableIdentity(path string) (chainExecutableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 {
		return chainExecutableIdentity{}, errors.New("executable is not a regular executable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return chainExecutableIdentity{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		return chainExecutableIdentity{}, errors.New("executable changed while its identity was captured")
	}
	if err := validateChainExecutablePath(path, info); err != nil {
		return chainExecutableIdentity{}, err
	}
	return chainExecutableIdentityFromFile(file, info)
}

func validateChainExecutablePath(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || os.Geteuid() == 0 || info.Mode().Perm()&0o022 != 0 {
		return errors.New("executable must be root-owned, non-group-writable, and used by an unprivileged publisher")
	}
	for directory := filepath.Dir(path); ; directory = filepath.Dir(directory) {
		directoryInfo, err := os.Lstat(directory)
		if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm()&0o022 != 0 {
			return errors.New("executable path contains an untrusted directory")
		}
		directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
		if !ok || directoryStat.Uid != 0 {
			return errors.New("executable path is not rooted in root-owned directories")
		}
		if directory == string(filepath.Separator) {
			break
		}
	}
	return nil
}

func chainExecutableIdentityFromFile(file *os.File, info os.FileInfo) (chainExecutableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return chainExecutableIdentity{}, errors.New("executable identity is unavailable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return chainExecutableIdentity{}, err
	}
	return chainExecutableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), digest: "sha256:" + hex.EncodeToString(hash.Sum(nil))}, nil
}

func openVerifiedChainExecutable(path string, expected chainExecutableIdentity) (*os.File, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("enrolled tosctl executable path is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		file.Close()
		return nil, errors.New("enrolled tosctl executable changed while opening")
	}
	if err := validateChainExecutablePath(path, info); err != nil {
		file.Close()
		return nil, err
	}
	actual, err := chainExecutableIdentityFromFile(file, info)
	if err != nil || actual != expected {
		file.Close()
		return nil, errors.New("enrolled tosctl executable identity changed")
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}
func (b *TosctlBackend) Close() error {
	if b == nil {
		return nil
	}
	b.configMu.Lock()
	defer b.configMu.Unlock()
	if b.configFile == nil {
		return nil
	}
	err := b.configFile.Close()
	b.configFile = nil
	return err
}

func backendEnvironment(vaultURL string) []string {
	// The publisher is a key-custody boundary. Inheriting the service process
	// environment would allow loader, proxy, certificate, HOME, and PATH
	// injection to change behavior after enrollment. tosctl receives only the
	// value already committed by EnrollmentBinding.
	return []string{"VAULT_URL=" + vaultURL}
}

func validBase64Hash(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func tosctlRPCURL(raw []byte) (string, error) {
	var config struct {
		ChainRPC struct {
			URLs   []json.RawMessage `json:"urls"`
			URL    string            `json:"url"`
			APIKey *string           `json:"api_key"`
		} `json:"chain_rpc"`
	}
	if err := json.Unmarshal(raw, &config); err != nil {
		return "", errors.New("decode tosctl RPC config")
	}
	if config.ChainRPC.APIKey != nil {
		return "", errors.New("publisher recovery does not support tosctl RPC API keys")
	}
	resolved := make([]string, 0, len(config.ChainRPC.URLs)+1)
	seen := make(map[string]struct{}, len(config.ChainRPC.URLs)+1)
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			if _, ok := seen[value]; !ok {
				seen[value] = struct{}{}
				resolved = append(resolved, value)
			}
		}
	}
	add(config.ChainRPC.URL)
	for _, raw := range config.ChainRPC.URLs {
		var direct string
		if json.Unmarshal(raw, &direct) == nil {
			add(direct)
			continue
		}
		var entry struct {
			URL    string  `json:"url"`
			APIKey *string `json:"api_key"`
		}
		if json.Unmarshal(raw, &entry) != nil || entry.URL == "" || entry.APIKey != nil {
			return "", errors.New("invalid or keyed tosctl RPC endpoint")
		}
		add(entry.URL)
	}
	if len(resolved) != 1 {
		return "", errors.New("tosctl must resolve to exactly one pinned RPC endpoint")
	}
	return resolved[0], nil
}

func pinnedConfig(raw []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "tos-chain-publisher-config-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err := os.Remove(path); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Write(raw); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
