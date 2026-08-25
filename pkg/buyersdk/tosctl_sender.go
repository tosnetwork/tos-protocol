package buyersdk

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
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

const stablecoinTransferOpcode = 0x0f8a7ea5

type TOSCTLFundingSenderConfig struct {
	BinaryPath      string
	ConfigPath      string
	WalletName      string
	AttachedNanoTOS uint64
	ForwardNanoTOS  uint64
	Timeout         time.Duration
	VaultURL        string
}

type commandRunner interface {
	run(context.Context, string, ...string) ([]byte, error)
}

type TOSCTLFundingSender struct {
	binary, config, wallet string
	attached, forward      uint64
	timeout                time.Duration
	runner                 commandRunner
}

func NewTOSCTLFundingSender(c TOSCTLFundingSenderConfig) (*TOSCTLFundingSender, error) {
	if !secureExecutable(c.BinaryPath) || !secureConfigFile(c.ConfigPath) ||
		c.WalletName == "" || strings.TrimSpace(c.WalletName) != c.WalletName || len(c.WalletName) > 128 {
		return nil, errors.New("invalid tosctl stablecoin sender configuration")
	}
	if c.AttachedNanoTOS == 0 {
		c.AttachedNanoTOS = 100_000_000
	}
	if c.ForwardNanoTOS == 0 {
		c.ForwardNanoTOS = 50_000_000
	}
	if c.ForwardNanoTOS >= c.AttachedNanoTOS || c.AttachedNanoTOS > 1_000_000_000 {
		return nil, errors.New("invalid stablecoin transfer fee budget")
	}
	if c.Timeout == 0 {
		c.Timeout = 90 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return nil, errors.New("invalid tosctl sender timeout")
	}
	runner, err := newPinnedExecRunnerWithVault(c.BinaryPath, c.ConfigPath, c.VaultURL)
	if err != nil {
		return nil, err
	}
	return &TOSCTLFundingSender{binary: c.BinaryPath, config: c.ConfigPath, wallet: c.WalletName,
		attached: c.AttachedNanoTOS, forward: c.ForwardNanoTOS, timeout: c.Timeout, runner: runner}, nil
}

// BuildStablecoinFundingBody builds the exact TOS-network stablecoin transfer
// that causes the recipient wallet to notify the canonical escrow.
func BuildStablecoinFundingBody(intent FundingIntent, forwardNanoTOS uint64) (*cell.Cell, error) {
	if intent.QueryID == 0 || forwardNanoTOS == 0 || !validFundingIntent(intent) {
		return nil, errors.New("invalid stablecoin funding intent")
	}
	escrow, err := parseRawAddress(intent.EscrowAddress)
	if err != nil {
		return nil, err
	}
	buyer, err := parseRawAddress(intent.BuyerAddress)
	if err != nil {
		return nil, err
	}
	amount, ok := new(big.Int).SetString(intent.AmountAtomic, 10)
	if !ok || amount.Sign() <= 0 || amount.BitLen() > 120 {
		return nil, errors.New("invalid stablecoin atomic amount")
	}
	return cell.BeginCell().MustStoreUInt(stablecoinTransferOpcode, 32).
		MustStoreUInt(intent.QueryID, 64).MustStoreBigCoins(amount).
		MustStoreAddr(escrow).MustStoreAddr(buyer).
		MustStoreBoolBit(false).MustStoreCoins(forwardNanoTOS).
		MustStoreBoolBit(false).EndCell(), nil
}

func (s *TOSCTLFundingSender) PrepareStablecoinFunding(ctx context.Context, intent FundingIntent) (*PreparedFunding, error) {
	if s == nil || ctx == nil || !validFundingIntent(intent) {
		return nil, errors.New("invalid tosctl stablecoin funding request")
	}
	body, err := BuildStablecoinFundingBody(intent, s.forward)
	if err != nil {
		return nil, err
	}
	bodyBOC := base64.StdEncoding.EncodeToString(body.ToBOCWithOptions(cell.BOCSerializeOptions{}))
	bodyHash := fmt.Sprintf("tvm-cell-sha256:%x", body.Hash())
	baseArgs := []string{"wallet", "send", "--from", s.wallet,
		"--to", intent.BuyerWallet, "--amount-nanotos", fmt.Sprint(s.attached), "--body-boc", bodyBOC}

	preparedRaw, err := s.run(ctx, append(baseArgs, "--build-only")...)
	if err != nil {
		return nil, errors.New("tosctl could not prepare stablecoin funding")
	}
	var prepared struct {
		Version       string `json:"version"`
		Wallet        string `json:"wallet"`
		Payer         string `json:"payer"`
		Destination   string `json:"destination"`
		AmountNanoTOS uint64 `json:"amount_nanotos"`
		BodyHash      string `json:"body_hash"`
		StateInitHash string `json:"state_init_hash"`
		MessageBOC    string `json:"message_boc_base64"`
	}
	decoder := json.NewDecoder(bytes.NewReader(preparedRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&prepared) != nil || prepared.Version != "tosctl.wallet-prepared-send.v1" ||
		prepared.Wallet != s.wallet || !sameAddress(prepared.Payer, intent.BuyerAddress) ||
		!sameAddress(prepared.Destination, intent.BuyerWallet) ||
		prepared.AmountNanoTOS != s.attached || prepared.BodyHash != bodyHash || prepared.StateInitHash != "" || prepared.MessageBOC == "" {
		return nil, errors.New("tosctl prepared a conflicting stablecoin funding message")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("tosctl prepared output has trailing data")
	}
	messageBOC, err := base64.StdEncoding.DecodeString(prepared.MessageBOC)
	if err != nil {
		return nil, errors.New("tosctl prepared an invalid message BOC")
	}
	message, err := cell.FromBOC(messageBOC)
	if err != nil {
		return nil, errors.New("tosctl prepared an invalid message BOC")
	}
	return &PreparedFunding{Intent: cloneFundingIntent(intent), MessageBOCBase64: prepared.MessageBOC,
		MessageHash: fmt.Sprintf("tvm-cell-sha256:%x", message.Hash())}, nil
}

func (s *TOSCTLFundingSender) BroadcastStablecoinFunding(ctx context.Context, prepared *PreparedFunding) error {
	if s == nil || ctx == nil || prepared == nil || !validFundingIntent(prepared.Intent) ||
		!validCellDigest(prepared.MessageHash) || prepared.MessageBOCBase64 == "" {
		return errors.New("invalid prepared stablecoin funding")
	}
	messageBOC, err := base64.StdEncoding.DecodeString(prepared.MessageBOCBase64)
	if err != nil {
		return errors.New("invalid prepared stablecoin funding BOC")
	}
	message, err := cell.FromBOC(messageBOC)
	if err != nil || fmt.Sprintf("tvm-cell-sha256:%x", message.Hash()) != prepared.MessageHash {
		return errors.New("prepared stablecoin funding identity changed")
	}
	broadcastRaw, err := s.run(ctx, "wallet", "broadcast-prepared",
		"--message-boc", prepared.MessageBOCBase64, "--yes")
	if err != nil {
		return errors.New("tosctl stablecoin funding broadcast outcome is ambiguous")
	}
	var result struct {
		Version     string `json:"version"`
		MessageHash string `json:"message_hash"`
		Status      string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(broadcastRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&result) != nil || result.Version != "tosctl.wallet-prepared-broadcast.v1" ||
		result.MessageHash != prepared.MessageHash || result.Status != "submitted" {
		return errors.New("tosctl stablecoin funding broadcast outcome is ambiguous")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tosctl stablecoin funding broadcast output has trailing data")
	}
	return nil
}

func (s *TOSCTLFundingSender) run(ctx context.Context, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.runner.run(call, s.binary, args...)
}

func cloneFundingIntent(intent FundingIntent) FundingIntent {
	result := intent
	result.Asset = proto.Clone(intent.Asset).(*nativev1.TOSAssetIdentityV1)
	return result
}

func validFundingIntent(i FundingIntent) bool {
	return i.NetworkID != "" && len(i.NetworkID) <= 64 && strings.TrimSpace(i.NetworkID) == i.NetworkID &&
		i.QueryID != 0 && i.Asset != nil && i.Asset.Master != nil &&
		i.Asset.Master.Workchain == 0 && len(i.Asset.Master.AccountId) == 32 &&
		!bytes.Equal(i.Asset.Master.AccountId, make([]byte, 32)) &&
		validCellDigest(i.Asset.Master.CodeHash) && validCellDigest(i.Asset.WalletCodeHash) &&
		i.Asset.Decimals > 0 && i.Asset.Decimals <= 18 &&
		validCellDigest(i.QuoteCommitment) &&
		isRawAddress(i.EscrowAddress) && isRawAddress(i.BuyerAddress) && isRawAddress(i.BuyerWallet) &&
		positiveAtomic(i.AmountAtomic) != nil
}

func validCellDigest(value string) bool {
	const prefix = "tvm-cell-sha256:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[len(prefix):])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func parseRawAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Workchain() != 0 || parsed.StringRaw() != value {
		return nil, errors.New("invalid raw workchain-zero address")
	}
	return parsed, nil
}

func isRawAddress(value string) bool {
	_, err := parseRawAddress(value)
	return err == nil
}

func sameAddress(left, right string) bool {
	a, errA := parseAnyAddress(left)
	b, errB := parseAnyAddress(right)
	return errA == nil && errB == nil && a.Workchain() == b.Workchain() && bytes.Equal(a.Data(), b.Data())
}

func parseAnyAddress(value string) (*address.Address, error) {
	if parsed, err := address.ParseRawAddr(value); err == nil {
		return parsed, nil
	}
	return address.ParseAddr(value)
}

func secureExecutable(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o022 == 0 && info.Mode().Perm()&0o111 != 0 && osguard.TrustedExecutableOwner(info)
}

func secureConfigFile(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && filepath.IsAbs(path) && filepath.Clean(path) == path && info.Mode().IsRegular() &&
		info.Mode().Perm()&0o077 == 0 && osguard.CurrentUserOwns(info)
}

type executableIdentity struct {
	size   int64
	digest [sha256.Size]byte
}

type execRunner struct {
	identity    executableIdentity
	config      []byte
	environment []string
	extraArgs   []string
}

func newPinnedExecRunner(binaryPath, configPath string) (*execRunner, error) {
	return newPinnedExecRunnerWithVault(binaryPath, configPath, "")
}

func newPinnedExecRunnerWithVault(binaryPath, configPath, vaultURL string) (*execRunner, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("descriptor-pinned tosctl custody is supported only on Linux")
	}
	executable, identity, err := openAndIdentifyExecutable(binaryPath)
	if err != nil {
		return nil, err
	}
	_ = executable.Close()
	config, err := os.ReadFile(configPath)
	if err != nil || len(config) == 0 || len(config) > 2<<20 {
		return nil, errors.New("read bounded tosctl custody configuration")
	}
	environment := []string{}
	if vaultURL != "" {
		if len(vaultURL) > 4096 || strings.ContainsRune(vaultURL, '\x00') ||
			(!strings.HasPrefix(vaultURL, "file://") && !strings.HasPrefix(vaultURL, "hashicorp://")) {
			return nil, errors.New("invalid bounded tosctl vault URL")
		}
		environment = []string{"VAULT_URL=" + vaultURL}
	}
	return &execRunner{identity: identity, config: append([]byte(nil), config...), environment: environment}, nil
}

func (r *execRunner) run(ctx context.Context, binary string, args ...string) ([]byte, error) {
	if r == nil {
		return nil, errors.New("tosctl custody runner is unavailable")
	}
	executable, identity, err := openAndIdentifyExecutable(binary)
	if err != nil || identity != r.identity {
		if executable != nil {
			_ = executable.Close()
		}
		return nil, errors.New("enrolled tosctl executable identity changed")
	}
	defer executable.Close()
	config, err := pinnedDescriptor(r.config)
	if err != nil {
		return nil, err
	}
	defer config.Close()
	args = append(args, r.extraArgs...)
	args = append(args, "--config-fd", "3", "--config-format", "json")
	command := exec.CommandContext(ctx, "/proc/self/fd/4", args...)
	command.ExtraFiles = []*os.File{config, executable}
	// Custody must not inherit loader, proxy, HOME, PATH, certificate, or
	// wallet-selection variables from the long-running OpenFox process.
	command.Env = append([]string(nil), r.environment...)
	output := cappedBuffer{limit: 1 << 20}
	command.Stdout, command.Stderr = &output, &output
	err = command.Run()
	return output.Bytes(), err
}

func openAndIdentifyExecutable(path string) (*os.File, executableIdentity, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil || !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathInfo.Mode().IsRegular() ||
		pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm()&0o111 == 0 || pathInfo.Mode().Perm()&0o022 != 0 {
		return nil, executableIdentity{}, errors.New("invalid tosctl executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, executableIdentity{}, err
	}
	info, err := file.Stat()
	if err != nil || !os.SameFile(pathInfo, info) || !osguard.TrustedExecutableOwner(info) {
		file.Close()
		return nil, executableIdentity{}, errors.New("tosctl executable identity is untrusted")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		file.Close()
		return nil, executableIdentity{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	identity := executableIdentity{size: info.Size(), digest: digest}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, executableIdentity{}, err
	}
	return file, identity, nil
}

func pinnedDescriptor(raw []byte) (*os.File, error) {
	file, err := os.CreateTemp("", "tosctl-custody-config-*")
	if err != nil {
		return nil, err
	}
	if err := os.Remove(file.Name()); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return nil, err
	}
	if _, err := file.Seek(0, 0); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(value []byte) (int, error) {
	remaining := b.limit - b.Len()
	if remaining <= 0 {
		return 0, errors.New("tosctl output exceeded limit")
	}
	if len(value) > remaining {
		written, _ := b.Buffer.Write(value[:remaining])
		return written, errors.New("tosctl output exceeded limit")
	}
	return b.Buffer.Write(value)
}
