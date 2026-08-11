package chainactionpublisher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

// TosctlBackendConfig is the concrete TOS wallet backend. Exact nanoTOS and
// non-interactive flags require the coordinated Phase 4B-1 tosctl build.
type TosctlBackendConfig struct {
	Network            string `json:"network"`
	Binary             string `json:"binary"`
	ConfigPath         string `json:"configPath"`
	VaultURL           string `json:"vaultUrl"`
	RPCURL             string `json:"rpcUrl"`
	GenesisRootHash    string `json:"genesisRootHash"`
	GenesisFileHash    string `json:"genesisFileHash"`
	WalletName         string `json:"walletName"`
	Payer              string `json:"payer"`
	Lookback           int    `json:"lookback,omitempty"`
	RecoveryWaitMillis uint64 `json:"recoveryWaitMillis,omitempty"`
	PollMillis         uint64 `json:"pollMillis,omitempty"`
}
type TosctlBackend struct {
	network, binary, configPath, vaultURL, walletName, payer string
	client                                                   *chain.Client
	genesisRootHash, genesisFileHash                         string
	lookback                                                 int
	recoveryWait, poll                                       time.Duration
	mu                                                       sync.Mutex
}

func NewTosctlBackend(c TosctlBackendConfig) (*TosctlBackend, error) {
	if c.Network == "" || c.WalletName == "" || c.VaultURL == "" || !filepath.IsAbs(c.Binary) || filepath.Clean(c.Binary) != c.Binary || !filepath.IsAbs(c.ConfigPath) || filepath.Clean(c.ConfigPath) != c.ConfigPath {
		return nil, errors.New("invalid tosctl chain publisher config")
	}
	if info, err := os.Stat(c.Binary); err != nil || !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
		return nil, errors.New("tosctl binary is unavailable")
	}
	configInfo, err := os.Lstat(c.ConfigPath)
	if err != nil || !configInfo.Mode().IsRegular() || configInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("tosctl config must be an owner-private regular file")
	}
	stat, ok := configInfo.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("tosctl config owner mismatch")
	}
	configuredRPC, err := tosctlRPCURL(c.ConfigPath)
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
	if c.Lookback == 0 {
		c.Lookback = 64
	}
	if c.Lookback < 1 || c.Lookback > 100 {
		return nil, errors.New("invalid tosctl recovery lookback")
	}
	recovery := time.Duration(c.RecoveryWaitMillis) * time.Millisecond
	if recovery == 0 {
		recovery = 30 * time.Second
	}
	if recovery > 2*time.Minute {
		return nil, errors.New("invalid tosctl recovery wait")
	}
	poll := time.Duration(c.PollMillis) * time.Millisecond
	if poll == 0 {
		poll = time.Second
	}
	if poll < 100*time.Millisecond || poll > 5*time.Second {
		return nil, errors.New("invalid tosctl recovery poll")
	}
	return &TosctlBackend{network: c.Network, binary: c.Binary, configPath: c.ConfigPath, vaultURL: c.VaultURL, walletName: c.WalletName, payer: payer, client: client, genesisRootHash: c.GenesisRootHash, genesisFileHash: c.GenesisFileHash, lookback: c.Lookback, recoveryWait: recovery, poll: poll}, nil
}

type tosctlWallet struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Balance    any    `json:"balance"`
	State      any    `json:"state"`
	WalletType any    `json:"wallet_type"`
	Seqno      any    `json:"seqno"`
}

func (b *TosctlBackend) CheckReady(ctx context.Context) (BackendCapabilities, error) {
	if b == nil || b.client == nil {
		return BackendCapabilities{}, errors.New("invalid tosctl backend")
	}
	var master struct {
		Init struct {
			RootHash string `json:"root_hash"`
			FileHash string `json:"file_hash"`
		} `json:"init"`
	}
	if err := b.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return BackendCapabilities{}, err
	}
	if master.Init.RootHash != b.genesisRootHash || master.Init.FileHash != b.genesisFileHash {
		return BackendCapabilities{}, errors.New("TOS genesis identity mismatch")
	}
	out, err := b.run(ctx, "wallet", "ls", "--format", "json")
	if err != nil {
		return BackendCapabilities{}, err
	}
	var wallets []tosctlWallet
	if json.Unmarshal(out, &wallets) != nil {
		return BackendCapabilities{}, errors.New("invalid tosctl wallet list")
	}
	found := false
	for _, wallet := range wallets {
		address, e := toschain.CanonicalAddress(wallet.Address)
		if e == nil && wallet.Name == b.walletName && address == b.payer {
			found = true
		}
	}
	if !found {
		return BackendCapabilities{}, errors.New("configured tosctl payer wallet is unavailable")
	}
	return BackendCapabilities{Version: ProtocolVersion, Network: b.network, RecoverByActionID: true, SearchBeforeBroadcast: true}, nil
}
func (b *TosctlBackend) Publish(ctx context.Context, a chain.Action, recovering bool) (chain.ActionReceipt, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ref, found, err := b.find(ctx, a); err != nil {
		return chain.ActionReceipt{}, err
	} else if found {
		return receiptFor(a, ref), nil
	}
	if recovering {
		return chain.ActionReceipt{}, errors.New("uncertain action is outside authoritative recovery visibility")
	}
	_, commandErr := b.run(ctx, "wallet", "send", "--from", b.walletName, "--to", a.Payee, "--amount-nanotos", strconv.FormatUint(a.AmountNanoTOS, 10), "--message", a.Comment, "--yes")
	deadline := time.Now().Add(b.recoveryWait)
	for {
		ref, found, err := b.find(ctx, a)
		if err == nil && found {
			return receiptFor(a, ref), nil
		}
		if ctx.Err() != nil {
			return chain.ActionReceipt{}, ctx.Err()
		}
		if !time.Now().Before(deadline) {
			if commandErr != nil {
				return chain.ActionReceipt{}, fmt.Errorf("tosctl publish failed and recovery found no transaction: %w", commandErr)
			}
			return chain.ActionReceipt{}, errors.New("published transaction was not discovered")
		}
		timer := time.NewTimer(b.poll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return chain.ActionReceipt{}, ctx.Err()
		case <-timer.C:
		}
	}
}
func (b *TosctlBackend) find(ctx context.Context, a chain.Action) (string, bool, error) {
	return toschain.FindExactPayment(ctx, b.client, a.Payer, a.Payee, a.AmountNanoTOS, a.Comment, b.lookback)
}
func receiptFor(a chain.Action, ref string) chain.ActionReceipt {
	return chain.ActionReceipt{Version: a.Version, ActionID: a.ActionID, Network: a.Network, Kind: a.Kind, CommitmentKind: a.CommitmentKind, ObjectID: a.ObjectID, Digest: a.Digest, Reference: ref, Payer: a.Payer, Payee: a.Payee, AmountNanoTOS: a.AmountNanoTOS, Comment: a.Comment}
}
func (b *TosctlBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	args = append(args, "-c", b.configPath)
	command := exec.CommandContext(ctx, b.binary, args...)
	command.Env = backendEnvironment(b.vaultURL)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		return nil, fmt.Errorf("tosctl failed: %s", strings.TrimSpace(stderr.String()))
	}
	if stdout.Len() > 2<<20 {
		return nil, errors.New("tosctl output too large")
	}
	return stdout.Bytes(), nil
}
func (*TosctlBackend) Close() error { return nil }

func backendEnvironment(vaultURL string) []string {
	environment := make([]string, 0, len(os.Environ())+1)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "VAULT_URL=") {
			environment = append(environment, value)
		}
	}
	return append(environment, "VAULT_URL="+vaultURL)
}

func validBase64Hash(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

func tosctlRPCURL(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 2<<20 {
		return "", errors.New("read tosctl RPC config")
	}
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
