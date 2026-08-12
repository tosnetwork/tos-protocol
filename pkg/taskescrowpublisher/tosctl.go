package taskescrowpublisher

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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/address"
)

const (
	taskEscrowCLISchemaVersion    = "tosctl.task-escrow-cli.v1"
	taskEscrowCLIActionEncoding   = "tos.task-escrow.action.v1"
	DefaultOperationAmountNanoTOS = uint64(10_000_000)
	DefaultPublishTimeout         = 90 * time.Second
	DefaultRecoveryWait           = 30 * time.Second
	DefaultPollInterval           = time.Second
	DefaultTransactionLookback    = 32
	maxCommandOutputBytes         = 2 << 20
)

type taskEscrowCLICapabilities struct {
	SchemaVersion  string   `json:"schema_version"`
	ActionEncoding string   `json:"action_encoding"`
	Commands       []string `json:"commands"`
	CreateFlags    []string `json:"create_flags"`
	SendFlags      []string `json:"send_flags"`
	SendOperations []string `json:"send_operations"`
}

// TosctlBackendConfig identifies operator-owned wallet profiles. Wallets maps
// canonical raw TOS addresses to their tosctl wallet names; it contains no key
// material. VAULT_URL is passed only to the child process.
type TosctlBackendConfig struct {
	Network                string            `json:"network"`
	TosctlBinary           string            `json:"tosctlBinary"`
	TosctlConfig           string            `json:"tosctlConfig"`
	VaultURL               string            `json:"vaultUrl"`
	RPCURL                 string            `json:"rpcUrl"`
	GenesisRootHash        string            `json:"genesisRootHash"`
	GenesisFileHash        string            `json:"genesisFileHash"`
	Wallets                map[string]string `json:"wallets"`
	ExecutorWallet         string            `json:"executorWallet"`
	Workchain              int32             `json:"workchain"`
	OperationAmountNanoTOS uint64            `json:"operationAmountNanoTOS,omitempty"`
	CommandTimeoutMillis   uint64            `json:"commandTimeoutMillis,omitempty"`
	PublishTimeoutMillis   uint64            `json:"publishTimeoutMillis,omitempty"`
	RecoveryWaitMillis     uint64            `json:"recoveryWaitMillis,omitempty"`
	PollIntervalMillis     uint64            `json:"pollIntervalMillis,omitempty"`
	TransactionLookback    int               `json:"transactionLookback,omitempty"`
	AdditionalEnvironment  map[string]string `json:"additionalEnvironment,omitempty"`
}

type TosctlBackend struct {
	network           string
	binary            string
	binaryIdentity    executableIdentity
	configFile        *os.File
	vaultURL          string
	wallets           map[string]string
	executorWallet    string
	workchain         int32
	operationValue    uint64
	commandTimeout    time.Duration
	publishTimeout    time.Duration
	recoveryWait      time.Duration
	locator           *transactionLocator
	environment       []string
	mu                sync.Mutex
	configMu          sync.Mutex
	genesisRootHash   string
	genesisFileHash   string
	enrollmentBinding string
}

func NewTosctlBackend(config TosctlBackendConfig) (*TosctlBackend, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("production tosctl TaskEscrow publisher is supported only on Linux")
	}
	if strings.TrimSpace(config.Network) == "" || len(config.Network) > 64 ||
		strings.TrimSpace(config.VaultURL) == "" || strings.TrimSpace(config.ExecutorWallet) == "" ||
		len(config.Wallets) == 0 || len(config.Wallets) > 256 {
		return nil, errors.New("invalid tosctl publisher configuration")
	}
	binary, err := validateExecutable(config.TosctlBinary)
	if err != nil {
		return nil, err
	}
	configPath, err := validateRegularPath(config.TosctlConfig, false)
	if err != nil {
		return nil, fmt.Errorf("tosctl config: %w", err)
	}
	rawConfig, err := os.ReadFile(configPath)
	if err != nil || len(rawConfig) > 2<<20 {
		return nil, errors.New("read tosctl configuration snapshot")
	}
	configuredRPC, err := taskEscrowTosctlRPCURL(rawConfig)
	if err != nil || configuredRPC != config.RPCURL {
		return nil, errors.New("tosctl send RPC does not match recovery RPC")
	}
	if !validBase64Hash(config.GenesisRootHash) || !validBase64Hash(config.GenesisFileHash) {
		return nil, errors.New("invalid expected TOS genesis identity")
	}
	configFile, err := pinnedTaskEscrowConfig(rawConfig)
	if err != nil {
		return nil, err
	}
	wallets := make(map[string]string, len(config.Wallets))
	for rawAddress, name := range config.Wallets {
		addressValue, err := toschain.CanonicalAddress(strings.TrimSpace(rawAddress))
		if err != nil || strings.TrimSpace(name) == "" || len(name) > 128 {
			return nil, errors.New("invalid tosctl wallet binding")
		}
		if _, duplicate := wallets[addressValue]; duplicate {
			return nil, errors.New("duplicate tosctl wallet address")
		}
		wallets[addressValue] = strings.TrimSpace(name)
	}
	operationValue := config.OperationAmountNanoTOS
	if operationValue == 0 {
		operationValue = DefaultOperationAmountNanoTOS
	}
	commandTimeout, err := boundedDuration(config.CommandTimeoutMillis, 2*time.Minute, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("command timeout: %w", err)
	}
	publishTimeout, err := boundedDuration(config.PublishTimeoutMillis, DefaultPublishTimeout, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("publish timeout: %w", err)
	}
	recoveryWait, err := boundedDuration(config.RecoveryWaitMillis, DefaultRecoveryWait, 2*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("recovery wait: %w", err)
	}
	pollInterval, err := boundedDuration(config.PollIntervalMillis, DefaultPollInterval, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("poll interval: %w", err)
	}
	lookback := config.TransactionLookback
	if lookback == 0 {
		lookback = DefaultTransactionLookback
	}
	locator, err := newTransactionLocator(config.RPCURL, minDuration(commandTimeout, 20*time.Second), pollInterval, lookback)
	if err != nil {
		return nil, fmt.Errorf("configure transaction locator: %w", err)
	}
	environment, err := buildEnvironment(config.VaultURL, config.AdditionalEnvironment)
	if err != nil {
		return nil, err
	}
	binaryIdentity, err := captureExecutableIdentity(binary)
	if err != nil {
		configFile.Close()
		return nil, err
	}
	binaryDigest := binaryIdentity.digest
	configSum := sha256.Sum256(rawConfig)
	vaultSum := sha256.Sum256([]byte(strings.TrimSpace(config.VaultURL)))
	environmentSum, err := codec.Digest("tos.task-escrow.publisher-environment.v1", config.AdditionalEnvironment)
	if err != nil {
		configFile.Close()
		return nil, err
	}
	binding, err := codec.Digest("tos.task-escrow.publisher-backend.v1", struct {
		Version, ActionVersion, Network, Binary, Config, RPC, GenesisRoot, GenesisFile, Executor, Vault, Environment string
		Wallets                                                                                                      map[string]string
		Workchain                                                                                                    int32
		Operation                                                                                                    uint64
	}{"tosctl-v1", chain.TaskEscrowActionVersion, config.Network, binaryDigest, "sha256:" + hex.EncodeToString(configSum[:]), configuredRPC, config.GenesisRootHash, config.GenesisFileHash, config.ExecutorWallet, "sha256:" + hex.EncodeToString(vaultSum[:]), environmentSum, wallets, config.Workchain, operationValue})
	if err != nil {
		configFile.Close()
		return nil, err
	}
	return &TosctlBackend{
		network: config.Network, binary: binary, binaryIdentity: binaryIdentity, configFile: configFile,
		vaultURL: config.VaultURL, wallets: wallets, executorWallet: config.ExecutorWallet,
		workchain: config.Workchain, operationValue: operationValue,
		commandTimeout: commandTimeout, publishTimeout: publishTimeout,
		recoveryWait: recoveryWait, locator: locator, environment: environment, genesisRootHash: config.GenesisRootHash, genesisFileHash: config.GenesisFileHash,
		enrollmentBinding: binding,
	}, nil
}

func (b *TosctlBackend) EnrollmentBinding() string {
	if b == nil {
		return ""
	}
	return b.enrollmentBinding
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// walletLsEntry mirrors every field tosctl's `wallet ls --format json` emits.
// jsonstrict.Decode rejects unknown fields, so this must stay in sync with
// tosctl's WalletLsView even though CheckReady only reads Name and Address.
type walletLsEntry struct {
	Name       string `json:"name"`
	Address    string `json:"address"`
	Balance    any    `json:"balance"`
	State      any    `json:"state"`
	WalletType any    `json:"wallet_type"`
	Seqno      any    `json:"seqno"`
}

func (b *TosctlBackend) CheckReady(ctx context.Context, policy PublisherPolicy) error {
	if b == nil || b.locator == nil || b.locator.client == nil {
		return errors.New("invalid tosctl publisher backend")
	}
	var master masterchainInformation
	if err := b.locator.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return fmt.Errorf("TOS JSON-RPC is unavailable: %w", err)
	}
	if master.Init.RootHash != b.genesisRootHash || master.Init.FileHash != b.genesisFileHash {
		return errors.New("TOS genesis identity mismatch")
	}
	// Chain/genesis readiness is checked above through the pinned Go client.
	// Resolve wallet custody identities offline so readiness cannot be delayed
	// by unrelated per-wallet balance/state queries.
	output, err := b.run(ctx, "wallet", "ls", "--format", "json", "--offline")
	if err != nil {
		return fmt.Errorf("list tosctl wallets: %w", err)
	}
	var listed []walletLsEntry
	if err := jsonstrict.Decode(output, &listed); err != nil {
		return errors.New("tosctl wallet list is not valid JSON")
	}
	actual := make(map[string]string, len(listed))
	for _, wallet := range listed {
		if strings.TrimSpace(wallet.Address) == "" {
			continue
		}
		canonical, err := canonicalWalletAddress(wallet.Address)
		if err == nil {
			actual[canonical] = wallet.Name
		}
	}
	for addressValue, name := range b.wallets {
		if actual[addressValue] != name {
			return fmt.Errorf("tosctl wallet %q does not resolve to %s", name, addressValue)
		}
	}
	foundExecutor := false
	for _, name := range actual {
		if name == b.executorWallet {
			foundExecutor = true
			break
		}
	}
	if !foundExecutor {
		return errors.New("executor wallet is unavailable")
	}
	capabilityOutput, err := b.run(ctx, "agent", "task", "capabilities", "--format", "json")
	if err != nil {
		return fmt.Errorf("query tosctl TaskEscrow capabilities: %w", err)
	}
	if err := validateTaskEscrowCLICapabilities(capabilityOutput); err != nil {
		return err
	}
	// Exercise the deterministic, side-effect-free implementation as well as
	// its declared schema. This catches binaries that advertise the contract
	// but cannot parse or build the exact StateInit used by the publisher.
	addresses := make([]string, 0, len(b.wallets))
	for addressValue := range b.wallets {
		addresses = append(addresses, addressValue)
	}
	sort.Strings(addresses)
	probe := chain.TaskEscrowAction{
		Kind: chain.TaskEscrowActionDeploy, Creator: addresses[0], Agent: addresses[0],
		Verifier: addresses[0], BudgetNanoTOS: 1, FundingNanoTOS: 1,
		DeadlineUnix: uint64(time.Now().UTC().Add(time.Hour).Truncate(time.Second).Unix()),
		ReviewPeriod: 3600, PolicyHash: "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	}
	stateOutput, err := b.run(ctx, b.buildStateArgs(probe)...)
	if err != nil {
		return fmt.Errorf("exercise tosctl TaskEscrow build-state: %w", err)
	}
	var state taskStateView
	validatedPolicy, policyErr := validatePublisherPolicy(policy)
	if err := jsonstrict.Decode(stateOutput, &state); err != nil ||
		normalizeDigest(state.PolicyHash) != probe.PolicyHash ||
		normalizeDigest(state.PermissionHash) != probe.PermissionHash ||
		strings.TrimSpace(state.Address) == "" {
		return errors.New("tosctl TaskEscrow build-state readiness probe is incompatible")
	}
	codeHash := normalizeCellDigest(state.CodeHash)
	if !validCellHash(codeHash) {
		return errors.New("tosctl TaskEscrow build-state returned an invalid code hash")
	}
	if policyErr != nil || !contains(validatedPolicy.AllowedCodeHashes, codeHash) {
		return errors.New("tosctl TaskEscrow build-state code hash is not enrolled in publisher policy")
	}
	return nil
}

func validateTaskEscrowCLICapabilities(output []byte) error {
	var got taskEscrowCLICapabilities
	if err := jsonstrict.Decode(output, &got); err != nil {
		return errors.New("tosctl TaskEscrow capabilities are not valid JSON")
	}
	if got.SchemaVersion != taskEscrowCLISchemaVersion || got.ActionEncoding != taskEscrowCLIActionEncoding ||
		!sameStringSet(got.Commands, []string{"agent task build-state", "agent task create", "agent task send"}) ||
		!sameStringSet(got.CreateFlags, []string{"--name", "--creator", "--agent", "--verifier", "--budget-nanotos", "--deadline", "--review-period", "--policy-hash", "--permission-hash", "--from", "--amount-nanotos", "--workchain", "--yes", "--format"}) ||
		!sameStringSet(got.SendFlags, []string{"--operation", "--address", "--from", "--query-id", "--amount-nanotos", "--yes", "--result-hash", "--evidence-hash", "--dispute-hash", "--payout-nanotos"}) ||
		!sameStringSet(got.SendOperations, []string{"accept", "reject", "result", "dispute", "resolve", "settle", "cancel", "timeout", "claim"}) {
		return errors.New("tosctl TaskEscrow CLI capability contract mismatch")
	}
	return nil
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	l := append([]string(nil), left...)
	r := append([]string(nil), right...)
	sort.Strings(l)
	sort.Strings(r)
	return slices.Equal(l, r)
}

// taskStateView mirrors every field tosctl's `agent task build-state
// --format json` emits. jsonstrict.Decode rejects unknown fields, so this
// must stay in sync with tosctl's AgentTaskStateView even though Prepare
// only reads Address, PermissionHash, and PolicyHash.
type taskStateView struct {
	Creator        string `json:"creator"`
	AssignedAgent  any    `json:"assigned_agent"`
	Verifier       any    `json:"verifier"`
	PermissionID   any    `json:"permission_id"`
	PermissionHash string `json:"permission_hash"`
	Budget         string `json:"budget"`
	Deadline       uint64 `json:"deadline"`
	ReviewPeriod   uint32 `json:"review_period"`
	Workchain      int32  `json:"workchain"`
	Address        string `json:"address"`
	PolicyHash     string `json:"policy_hash"`
	StateInitBOC   string `json:"state_init_boc"`
	CodeHash       string `json:"code_hash"`
	DataHash       string `json:"data_hash"`
}

func (b *TosctlBackend) Prepare(ctx context.Context, action chain.TaskEscrowAction) (PreparedAction, error) {
	if b == nil || action.Network != b.network {
		return PreparedAction{}, errors.New("task escrow action network mismatch")
	}
	if wallet := b.walletForAction(action); strings.TrimSpace(wallet) == "" {
		return PreparedAction{}, errors.New("task escrow action signer wallet is unavailable")
	}
	contractAddress := action.ContractAddress
	codeHash := ""
	if action.Kind == chain.TaskEscrowActionDeploy {
		output, err := b.run(ctx, b.buildStateArgs(action)...)
		if err != nil {
			return PreparedAction{}, fmt.Errorf("derive TaskEscrow address: %w", err)
		}
		var state taskStateView
		if err := jsonstrict.Decode(output, &state); err != nil {
			return PreparedAction{}, errors.New("tosctl build-state returned invalid JSON")
		}
		contractAddress, err = toschain.CanonicalAddress(state.Address)
		if err != nil || normalizeDigest(state.PermissionHash) != action.PermissionHash ||
			normalizeDigest(state.PolicyHash) != action.PolicyHash {
			return PreparedAction{}, errors.New("tosctl build-state changed immutable escrow fields")
		}
		codeHash = normalizeCellDigest(state.CodeHash)
	} else {
		var err error
		contractAddress, err = toschain.CanonicalAddress(contractAddress)
		if err != nil {
			return PreparedAction{}, err
		}
	}
	baseline, err := b.locator.latest(ctx, contractAddress)
	if err != nil {
		return PreparedAction{}, fmt.Errorf("read TaskEscrow baseline: %w", err)
	}
	return PreparedAction{
		ContractAddress: contractAddress, BaselineLT: baseline.LT,
		BaselineHash: baseline.Hash, PreparedAt: time.Now().UTC().UnixMilli(), CodeHash: codeHash,
	}, nil
}

func (b *TosctlBackend) Publish(
	ctx context.Context,
	action chain.TaskEscrowAction,
	prepared PreparedAction,
	recovering bool,
) (chain.TaskEscrowActionReceipt, error) {
	if b == nil || prepared.ContractAddress == "" {
		return chain.TaskEscrowActionReceipt{}, errors.New("invalid prepared TaskEscrow action")
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if recovering {
		if reference, found, err := b.locator.waitFor(ctx, action, prepared, b.recoveryWait); err != nil {
			return chain.TaskEscrowActionReceipt{}, err
		} else if found {
			return taskEscrowReceipt(action, prepared.ContractAddress, reference), nil
		}
		// The configured lookup is bounded and therefore cannot prove the
		// original broadcast absent. Never send again from an uncertain intent.
		return chain.TaskEscrowActionReceipt{}, errors.New("task escrow action outcome remains uncertain after bounded recovery")
	}
	if _, err := b.run(ctx, b.publishArgs(action, prepared.ContractAddress)...); err != nil {
		// A process can lose the CLI response after the chain accepted the action.
		// Search the contract history before exposing the command error.
		if reference, found, locateErr := b.locator.waitFor(ctx, action, prepared, minDuration(b.recoveryWait, 15*time.Second)); locateErr == nil && found {
			return taskEscrowReceipt(action, prepared.ContractAddress, reference), nil
		}
		return chain.TaskEscrowActionReceipt{}, fmt.Errorf("publish TaskEscrow action: %w", err)
	}
	reference, found, err := b.locator.waitFor(ctx, action, prepared, b.publishTimeout)
	if err != nil {
		return chain.TaskEscrowActionReceipt{}, err
	}
	if !found {
		return chain.TaskEscrowActionReceipt{}, errors.New("published TaskEscrow transaction was not observed")
	}
	return taskEscrowReceipt(action, prepared.ContractAddress, reference), nil
}

func (b *TosctlBackend) Close() error {
	b.configMu.Lock()
	defer b.configMu.Unlock()
	if b.configFile == nil {
		return nil
	}
	err := b.configFile.Close()
	b.configFile = nil
	return err
}

func (b *TosctlBackend) buildStateArgs(action chain.TaskEscrowAction) []string {
	return []string{
		"agent", "task", "build-state",
		"--creator", action.Creator, "--agent", action.Agent,
		"--verifier", action.Verifier,
		"--budget-nanotos", strconv.FormatUint(action.BudgetNanoTOS, 10),
		"--deadline", strconv.FormatUint(action.DeadlineUnix, 10),
		"--review-period", strconv.FormatUint(uint64(action.ReviewPeriod), 10),
		"--policy-hash", bareDigest(action.PolicyHash),
		"--permission-hash", bareDigest(action.PermissionHash),
		"--workchain", strconv.FormatInt(int64(b.workchain), 10),
		"--format", "json",
	}
}

func (b *TosctlBackend) publishArgs(action chain.TaskEscrowAction, contractAddress string) []string {
	if action.Kind == chain.TaskEscrowActionDeploy {
		args := []string{
			"agent", "task", "create", "--name", recordName(action.ActionID),
			"--creator", action.Creator, "--agent", action.Agent,
			"--verifier", action.Verifier,
			"--budget-nanotos", strconv.FormatUint(action.BudgetNanoTOS, 10),
			"--deadline", strconv.FormatUint(action.DeadlineUnix, 10),
			"--review-period", strconv.FormatUint(uint64(action.ReviewPeriod), 10),
			"--policy-hash", bareDigest(action.PolicyHash),
			"--permission-hash", bareDigest(action.PermissionHash),
			"--from", b.mustWallet(action.Creator),
			"--amount-nanotos", strconv.FormatUint(action.FundingNanoTOS, 10),
			"--workchain", strconv.FormatInt(int64(b.workchain), 10), "--yes", "--format", "json",
		}
		return args
	}
	args := []string{
		"agent", "task", "send", "--operation", string(action.Kind),
		"--address", contractAddress, "--from", b.walletForAction(action),
		"--query-id", strconv.FormatUint(action.QueryID, 10),
		"--amount-nanotos", strconv.FormatUint(b.operationValue, 10), "--yes",
	}
	switch action.Kind {
	case chain.TaskEscrowActionResult:
		args = append(args, "--result-hash", bareDigest(action.ResultHash),
			"--evidence-hash", bareDigest(action.EvidenceHash))
	case chain.TaskEscrowActionDispute:
		args = append(args, "--dispute-hash", bareDigest(action.DisputeHash))
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		args = append(args, "--payout-nanotos", strconv.FormatUint(action.PayoutNanoTOS, 10))
	}
	return args
}

func (b *TosctlBackend) walletForAction(action chain.TaskEscrowAction) string {
	switch action.Kind {
	case chain.TaskEscrowActionDeploy, chain.TaskEscrowActionCancel, chain.TaskEscrowActionDispute:
		return b.mustWallet(action.Creator)
	case chain.TaskEscrowActionAccept, chain.TaskEscrowActionResult, chain.TaskEscrowActionReject:
		return b.mustWallet(action.Agent)
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		return b.mustWallet(action.Verifier)
	case chain.TaskEscrowActionTimeout:
		return b.executorWallet
	default:
		return ""
	}
}

func (b *TosctlBackend) mustWallet(addressValue string) string {
	canonical, _ := toschain.CanonicalAddress(addressValue)
	return b.wallets[canonical]
}

func (b *TosctlBackend) run(ctx context.Context, args ...string) ([]byte, error) {
	if ctx == nil {
		return nil, errors.New("nil tosctl command context")
	}
	commandContext, cancel := context.WithTimeout(ctx, b.commandTimeout)
	defer cancel()
	b.configMu.Lock()
	defer b.configMu.Unlock()
	if b.configFile == nil {
		return nil, errors.New("tosctl backend is closed")
	}
	executable, err := openVerifiedExecutable(b.binary, b.binaryIdentity)
	if err != nil {
		return nil, err
	}
	defer executable.Close()
	if _, err := b.configFile.Seek(0, 0); err != nil {
		return nil, errors.New("seek pinned tosctl config")
	}
	dir, err := os.MkdirTemp("", "tos-task-escrow-config-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	target := "/proc/self/fd/3"
	if runtime.GOOS == "darwin" {
		target = "/dev/fd/3"
	}
	snapshotPath := filepath.Join(dir, "config.json")
	if err = os.Symlink(target, snapshotPath); err != nil {
		return nil, err
	}
	args = append(args, "-c", snapshotPath)
	command := exec.CommandContext(commandContext, "/proc/self/fd/4", args...)
	command.ExtraFiles = []*os.File{b.configFile, executable}
	command.Env = append([]string(nil), b.environment...)
	var stdout, stderr limitedBuffer
	stdout.limit, stderr.limit = maxCommandOutputBytes, maxCommandOutputBytes
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		if commandContext.Err() != nil {
			return nil, commandContext.Err()
		}
		return nil, fmt.Errorf("tosctl failed: %s", safeCommandError(stderr.Bytes()))
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("tosctl output exceeded byte limit")
	}
	return bytes.TrimSpace(stdout.Bytes()), nil
}

func taskEscrowTosctlRPCURL(raw []byte) (string, error) {
	var config struct {
		ChainRPC struct {
			URLs   []json.RawMessage `json:"urls"`
			URL    string            `json:"url"`
			APIKey *string           `json:"api_key"`
		} `json:"chain_rpc"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return "", errors.New("decode tosctl RPC config")
	}
	if config.ChainRPC.APIKey != nil {
		return "", errors.New("RPC API keys are unsupported")
	}
	var out []string
	seen := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(config.ChainRPC.URL)
	for _, rawValue := range config.ChainRPC.URLs {
		var direct string
		if json.Unmarshal(rawValue, &direct) == nil {
			add(direct)
			continue
		}
		var entry struct {
			URL    string  `json:"url"`
			APIKey *string `json:"api_key"`
		}
		if json.Unmarshal(rawValue, &entry) != nil || entry.APIKey != nil {
			return "", errors.New("invalid tosctl RPC endpoint")
		}
		add(entry.URL)
	}
	if len(out) != 1 {
		return "", errors.New("tosctl must resolve to exactly one RPC endpoint")
	}
	return out[0], nil
}
func pinnedTaskEscrowConfig(raw []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "tos-task-escrow-pinned-*")
	if err != nil {
		return nil, err
	}
	path := file.Name()
	if err = os.Remove(path); err != nil {
		file.Close()
		return nil, err
	}
	if err = file.Chmod(0600); err != nil {
		file.Close()
		return nil, err
	}
	if _, err = file.Write(raw); err != nil {
		file.Close()
		return nil, err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	_, err = file.Seek(0, 0)
	return file, err
}
func validBase64Hash(value string) bool {
	decoded, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(decoded) == 32
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
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

func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func taskEscrowReceipt(action chain.TaskEscrowAction, contractAddress, reference string) chain.TaskEscrowActionReceipt {
	return chain.TaskEscrowActionReceipt{
		Version: action.Version, ActionID: action.ActionID, Network: action.Network,
		Kind: action.Kind, EscrowID: action.EscrowID,
		ContractAddress: contractAddress, Reference: reference,
	}
}

func recordName(actionID string) string {
	digest := sha256.Sum256([]byte(actionID))
	return "atos-" + hex.EncodeToString(digest[:8])
}

func bareDigest(value string) string {
	return strings.TrimPrefix(value, "sha256:")
}

func normalizeDigest(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	value = strings.TrimPrefix(value, "sha256:")
	return "sha256:" + strings.ToLower(value)
}
func normalizeCellDigest(value string) string {
	value = strings.TrimPrefix(strings.TrimSpace(value), "0x")
	value = strings.TrimPrefix(value, "sha256:")
	value = strings.TrimPrefix(value, "tvm-cell-sha256:")
	return "tvm-cell-sha256:" + strings.ToLower(value)
}

func boundedDuration(valueMillis uint64, defaultValue, maximum time.Duration) (time.Duration, error) {
	if valueMillis == 0 {
		return defaultValue, nil
	}
	if valueMillis > uint64(maximum/time.Millisecond) {
		return 0, errors.New("duration outside bounds")
	}
	return time.Duration(valueMillis) * time.Millisecond, nil
}

func minDuration(left, right time.Duration) time.Duration {
	if left < right {
		return left
	}
	return right
}

// canonicalWalletAddress normalizes the local tosctl presentation format to
// the raw address used for immutable action bindings. Public chain references
// remain strict: toschain.CanonicalAddress still rejects non-raw addresses.
func canonicalWalletAddress(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return "", errors.New("invalid tosctl wallet address")
	}
	parsed, err := address.ParseAddr(value)
	if err != nil {
		parsed, err = address.ParseRawAddr(value)
	}
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 {
		return "", errors.New("invalid standard tosctl wallet address")
	}
	return parsed.StringRaw(), nil
}

func validateExecutable(path string) (string, error) {
	path, err := validateRegularPath(path, true)
	if err != nil {
		return "", fmt.Errorf("tosctl binary: %w", err)
	}
	if _, err := captureExecutableIdentity(path); err != nil {
		return "", fmt.Errorf("tosctl binary: %w", err)
	}
	return path, nil
}

type executableIdentity struct {
	device uint64
	inode  uint64
	size   int64
	digest string
}

func captureExecutableIdentity(path string) (executableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 {
		return executableIdentity{}, errors.New("executable is not a regular executable file")
	}
	file, err := os.Open(path)
	if err != nil {
		return executableIdentity{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) {
		return executableIdentity{}, errors.New("executable changed while its identity was captured")
	}
	if err := validateTrustedExecutablePath(path, info); err != nil {
		return executableIdentity{}, err
	}
	return executableIdentityFromFile(file, info)
}

func validateTrustedExecutablePath(path string, info os.FileInfo) error {
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

func executableIdentityFromFile(file *os.File, info os.FileInfo) (executableIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return executableIdentity{}, errors.New("executable identity is unavailable")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return executableIdentity{}, err
	}
	digest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	return executableIdentity{device: uint64(stat.Dev), inode: stat.Ino, size: info.Size(), digest: digest}, nil
}

func openVerifiedExecutable(path string, expected executableIdentity) (*os.File, error) {
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
		_ = file.Close()
		return nil, errors.New("enrolled tosctl executable changed while opening")
	}
	if err := validateTrustedExecutablePath(path, info); err != nil {
		_ = file.Close()
		return nil, err
	}
	actual, err := executableIdentityFromFile(file, info)
	if err != nil || actual != expected {
		_ = file.Close()
		return nil, errors.New("enrolled tosctl executable identity changed")
	}
	if _, err := file.Seek(0, 0); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func verifyExecutableIdentity(path string, expected executableIdentity) error {
	actual, err := captureExecutableIdentity(path)
	if err != nil {
		return fmt.Errorf("verify enrolled tosctl executable: %w", err)
	}
	if actual != expected {
		return errors.New("enrolled tosctl executable identity changed")
	}
	return nil
}

func validateRegularPath(path string, executable bool) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("path is not a regular file")
	}
	if executable && info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("file is not executable")
	}
	return path, nil
}

func buildEnvironment(vaultURL string, additional map[string]string) ([]string, error) {
	if strings.ContainsRune(vaultURL, '\x00') || len(vaultURL) > 4096 {
		return nil, errors.New("invalid vault URL")
	}
	overrides := make(map[string]string, len(additional)+1)
	overrides["VAULT_URL"] = vaultURL
	for key, value := range additional {
		if key == "" || strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') ||
			len(key) > 128 || len(value) > 4096 {
			return nil, errors.New("invalid child environment override")
		}
		overrides[key] = value
	}
	base := os.Environ()
	result := make([]string, 0, len(base)+len(overrides))
	seen := make(map[string]struct{}, len(overrides))
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if value, replace := overrides[key]; replace {
			result = append(result, key+"="+value)
			seen[key] = struct{}{}
		} else {
			result = append(result, entry)
		}
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result, nil
}

func safeCommandError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 512 {
		text = text[:512]
	}
	if text == "" {
		return "command rejected request"
	}
	return text
}

var _ Backend = (*TosctlBackend)(nil)
var _ io.Writer = (*limitedBuffer)(nil)
