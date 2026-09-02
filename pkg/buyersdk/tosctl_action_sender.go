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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// WalletActionIntent is a fully materialized, reviewable TOS wallet effect.
// StableActionID belongs to the economic authority; tosctl signs only the exact
// body and optional StateInit captured here.
type WalletActionIntent struct {
	StableActionID     string                              `json:"stable_action_id"`
	NetworkID          string                              `json:"network_id"`
	TransitionKind     string                              `json:"transition_kind"`
	Destination        string                              `json:"destination"`
	AmountNanoTOS      uint64                              `json:"amount_nanotos"`
	BodyBOCBase64      string                              `json:"body_boc_base64"`
	BodyHash           string                              `json:"body_hash"`
	StateInitBOCBase64 string                              `json:"state_init_boc_base64,omitempty"`
	StateInitHash      string                              `json:"state_init_hash,omitempty"`
	ValidUntilUnix     uint32                              `json:"valid_until_unix"`
	Authorization      commerce.CustodyEffectAuthorization `json:"authorization"`
}

type PreparedWalletAction struct {
	Intent           WalletActionIntent `json:"intent"`
	MessageBOCBase64 string             `json:"message_boc_base64"`
	MessageHash      string             `json:"message_hash"`
	DeploymentID     string             `json:"deployment_id"`
	ControllerEpoch  uint64             `json:"controller_epoch"`
	Seqno            uint32             `json:"seqno"`
}

type WalletActionSender interface {
	PrepareWalletAction(context.Context, WalletActionIntent) (*PreparedWalletAction, error)
	BroadcastWalletAction(context.Context, *PreparedWalletAction) error
}

// WalletActionResolver closes the custody sequence after independently
// locating the exact broadcast action from a strict majority of RPC views.
// Callers must resolve one action before asking the same Agent Account to sign
// its next sequence.
type WalletActionResolver interface {
	ResolveWalletAction(context.Context, *PreparedWalletAction) error
}

type TOSCTLWalletActionSenderConfig struct {
	BinaryPath        string
	ConfigPath        string
	WalletName        string
	FeeReserveNanoTOS uint64
	Timeout           time.Duration
	VaultURL          string
	JournalDirectory  string
	QuorumConfigPaths []string
}

type TOSCTLWalletActionSender struct {
	binary, config, wallet string
	timeout                time.Duration
	feeReserve             uint64
	runner                 commandRunner
	quorumConfigs          []string
}

func NewTOSCTLWalletActionSender(config TOSCTLWalletActionSenderConfig) (*TOSCTLWalletActionSender, error) {
	if !secureExecutable(config.BinaryPath) || !secureConfigFile(config.ConfigPath) || config.WalletName == "" ||
		strings.TrimSpace(config.WalletName) != config.WalletName || len(config.WalletName) > 128 {
		return nil, errors.New("invalid tosctl wallet action sender configuration")
	}
	if config.Timeout == 0 {
		config.Timeout = 90 * time.Second
	}
	if config.FeeReserveNanoTOS == 0 {
		config.FeeReserveNanoTOS = 100_000_000
	}
	if config.FeeReserveNanoTOS > 1_000_000_000 {
		return nil, errors.New("invalid tosctl wallet action fee reserve")
	}
	if config.Timeout < time.Second || config.Timeout > 5*time.Minute {
		return nil, errors.New("invalid tosctl wallet action timeout")
	}
	runner, err := newPinnedExecRunnerWithVault(config.BinaryPath, config.ConfigPath, config.VaultURL)
	if err != nil {
		return nil, err
	}
	journalDirectory := config.JournalDirectory
	if journalDirectory == "" {
		journalDirectory = filepath.Join(filepath.Dir(config.ConfigPath), ".tosctl-agent-controller-journal")
	}
	if !filepath.IsAbs(journalDirectory) || filepath.Clean(journalDirectory) != journalDirectory {
		return nil, errors.New("invalid tosctl custody journal directory")
	}
	if err := ensureOwnerPrivateDirectory(journalDirectory); err != nil {
		return nil, err
	}
	if len(config.QuorumConfigPaths) != 0 && len(config.QuorumConfigPaths) != 2 {
		return nil, errors.New("tosctl wallet action resolution requires exactly two quorum configs")
	}
	seenConfigs := map[string]bool{config.ConfigPath: true}
	for _, path := range config.QuorumConfigPaths {
		if !secureConfigFile(path) || seenConfigs[path] {
			return nil, errors.New("invalid or duplicate tosctl wallet action quorum config")
		}
		seenConfigs[path] = true
	}
	runner.extraArgs = []string{"--journal-directory", journalDirectory}
	return &TOSCTLWalletActionSender{binary: config.BinaryPath, config: config.ConfigPath,
		wallet: config.WalletName, timeout: config.Timeout, feeReserve: config.FeeReserveNanoTOS, runner: runner,
		quorumConfigs: append([]string(nil), config.QuorumConfigPaths...)}, nil
}

func ensureOwnerPrivateDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("tosctl custody journal directory must be owner-private")
	}
	if !osguard.CurrentUserOwns(info) {
		return errors.New("tosctl custody journal directory has the wrong owner")
	}
	return nil
}

func (sender *TOSCTLWalletActionSender) PrepareWalletAction(ctx context.Context,
	intent WalletActionIntent) (*PreparedWalletAction, error) {
	if sender == nil || ctx == nil || validateWalletActionIntent(intent) != nil {
		return nil, errors.New("invalid tosctl wallet action")
	}
	authorizationPath, cleanup, err := writeCustodyEffectAuthorization(intent.Authorization)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	args := []string{"agent", "account", "economic-effect-prepare", "--wallet", sender.wallet,
		"--target", intent.Destination, "--amount-nanotos", fmt.Sprint(intent.AmountNanoTOS),
		"--fee-reserve-nanotos", fmt.Sprint(sender.feeReserve), "--valid-until", strconv.FormatUint(uint64(intent.ValidUntilUnix), 10),
		"--body-boc", intent.BodyBOCBase64, "--authorization-file", authorizationPath, "--yes", "-c", sender.config}
	raw, err := sender.run(ctx, args...)
	if err != nil {
		return nil, fmt.Errorf("tosctl could not prepare wallet action: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	var output struct {
		Schema              string                         `json:"schema"`
		StableActionID      string                         `json:"stable_action_id"`
		ActionKind          string                         `json:"action_kind"`
		AgreementBodyDigest string                         `json:"agreement_body_digest"`
		ObligationID        string                         `json:"obligation_id"`
		Account             string                         `json:"account"`
		Target              string                         `json:"target"`
		AmountNanoTOS       uint64                         `json:"amount_nanotos"`
		BodyHash            string                         `json:"body_hash"`
		DeploymentID        string                         `json:"deployment_id"`
		ControllerEpoch     uint64                         `json:"controller_epoch"`
		Seqno               uint32                         `json:"seqno"`
		NetworkGlobalID     int32                          `json:"network_global_id"`
		NetworkDomain       *commerce.CustodyNetworkDomain `json:"network_domain"`
		ValidUntil          uint32                         `json:"valid_until"`
		MessageBOC          string                         `json:"exact_signed_boc"`
		MessageDigest       string                         `json:"exact_signed_boc_digest"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || output.Schema != "tosctl.agent-account.economic-effect-prepared.v1" ||
		output.StableActionID != intent.StableActionID || output.ActionKind != intent.TransitionKind ||
		output.AgreementBodyDigest != intent.Authorization.AgreementBodyDigest || output.ObligationID != intent.Authorization.ObligationID ||
		!sameAddress(output.Account, intent.Authorization.SourceAccount) || !sameAddress(output.Target, intent.Destination) ||
		output.AmountNanoTOS != intent.AmountNanoTOS || output.BodyHash != intent.BodyHash || output.ValidUntil == 0 ||
		!validLowerHex256(output.DeploymentID) ||
		uint64(output.ValidUntil) > intent.Authorization.ExpiresAtUnix || time.Now().Unix() >= int64(output.ValidUntil) ||
		output.NetworkGlobalID != intent.Authorization.NetworkGlobalID ||
		!sameCustodyNetworkDomain(output.NetworkDomain, intent.Authorization.NetworkDomain) ||
		output.MessageBOC == "" || !validSHA256Digest(output.MessageDigest) {
		return nil, errors.New("tosctl prepared a conflicting wallet action")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("tosctl wallet action output has trailing data")
	}
	messageBytes, err := decodeBase64BOC(output.MessageBOC)
	if err != nil {
		return nil, errors.New("tosctl prepared an invalid wallet action BOC")
	}
	if _, err := decodeSingleCell(output.MessageBOC); err != nil {
		return nil, errors.New("tosctl prepared an invalid wallet action BOC")
	}
	messageDigest := sha256Text(messageBytes)
	if messageDigest != output.MessageDigest {
		return nil, errors.New("tosctl returned an unrelated signed effect")
	}
	preparedIntent := cloneWalletActionIntent(intent)
	preparedIntent.ValidUntilUnix = output.ValidUntil
	return &PreparedWalletAction{Intent: preparedIntent, MessageBOCBase64: output.MessageBOC,
		MessageHash: messageDigest, DeploymentID: output.DeploymentID,
		ControllerEpoch: output.ControllerEpoch, Seqno: output.Seqno}, nil
}

func validLowerHex256(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && !bytes.Equal(decoded, make([]byte, 32))
}

func sameCustodyNetworkDomain(left, right *commerce.CustodyNetworkDomain) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func (sender *TOSCTLWalletActionSender) BroadcastWalletAction(ctx context.Context, prepared *PreparedWalletAction) error {
	if sender == nil || ctx == nil || prepared == nil || validateWalletActionIntent(prepared.Intent) != nil ||
		!validSHA256Digest(prepared.MessageHash) || prepared.MessageBOCBase64 == "" ||
		!validLowerHex256(prepared.DeploymentID) {
		return errors.New("invalid prepared wallet action")
	}
	messageBytes, err := decodeBase64BOC(prepared.MessageBOCBase64)
	if err != nil || sha256Text(messageBytes) != prepared.MessageHash {
		return errors.New("prepared wallet action identity changed")
	}
	if _, err := decodeSingleCell(prepared.MessageBOCBase64); err != nil {
		return errors.New("prepared wallet action identity changed")
	}
	raw, err := sender.run(ctx, "agent", "account", "economic-effect-broadcast", "--wallet", sender.wallet,
		"--stable-action-id", prepared.Intent.StableActionID, "--yes", "-c", sender.config)
	if err != nil {
		return errors.New("tosctl wallet action broadcast outcome is ambiguous")
	}
	var output struct {
		Schema         string `json:"schema"`
		StableActionID string `json:"stable_action_id"`
		ActionKind     string `json:"action_kind"`
		Account        string `json:"account"`
		MessageHash    string `json:"exact_signed_boc_digest"`
		Status         string `json:"state"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil || output.Schema != "tosctl.agent-account.economic-effect-broadcast.v1" ||
		output.StableActionID != prepared.Intent.StableActionID || output.ActionKind != prepared.Intent.TransitionKind ||
		!sameAddress(output.Account, prepared.Intent.Authorization.SourceAccount) ||
		output.MessageHash != prepared.MessageHash || output.Status != "broadcasting" {
		return errors.New("tosctl wallet action broadcast outcome is ambiguous")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tosctl wallet action broadcast output has trailing data")
	}
	return nil
}

func (sender *TOSCTLWalletActionSender) ResolveWalletAction(ctx context.Context, prepared *PreparedWalletAction) error {
	if sender == nil || ctx == nil || prepared == nil || validateWalletActionIntent(prepared.Intent) != nil ||
		!validSHA256Digest(prepared.MessageHash) || prepared.MessageBOCBase64 == "" ||
		!validLowerHex256(prepared.DeploymentID) || len(sender.quorumConfigs) != 2 {
		return errors.New("invalid or unconfigured tosctl wallet action resolution")
	}
	actionID := strings.TrimPrefix(prepared.Intent.StableActionID, "sha256:")
	args := []string{"agent", "account", "task-send-resolve", "--wallet", sender.wallet,
		"--action-id", actionID, "--quorum-config", sender.quorumConfigs[0], sender.quorumConfigs[1],
		"-c", sender.config}
	raw, err := sender.run(ctx, args...)
	if err != nil {
		return fmt.Errorf("tosctl could not resolve exact wallet action: %w: %s", err, strings.TrimSpace(string(raw)))
	}
	var output struct {
		Schema                   string                         `json:"schema"`
		Wallet                   string                         `json:"wallet"`
		ActionID                 string                         `json:"action_id"`
		SourceAccount            string                         `json:"source_account"`
		DeploymentID             string                         `json:"deployment_id"`
		ControllerEpoch          uint64                         `json:"controller_epoch"`
		Seqno                    uint32                         `json:"seqno"`
		FinalizedControllerEpoch uint64                         `json:"finalized_controller_epoch"`
		FinalizedSeqno           uint32                         `json:"finalized_seqno"`
		Destination              string                         `json:"destination"`
		AmountNanoTOS            uint64                         `json:"amount_nanotos"`
		BodyHash                 string                         `json:"body_hash"`
		ExactSignedBOCDigest     string                         `json:"exact_signed_boc_digest"`
		SubmittedMessageCellHash string                         `json:"submitted_message_cell_hash"`
		NetworkDomain            *commerce.CustodyNetworkDomain `json:"network_domain"`
		Quorum                   struct {
			Members   uint32 `json:"members"`
			Threshold uint32 `json:"threshold"`
			Agreeing  uint32 `json:"agreeing"`
		} `json:"quorum"`
		ProcessViewScope           string            `json:"process_view_scope"`
		BlockReferenceScope        string            `json:"block_reference_scope"`
		IndependentOperatorsProven bool              `json:"independent_operator_domains_proven"`
		Transaction                json.RawMessage   `json:"transaction"`
		Observations               []json.RawMessage `json:"observations"`
		State                      string            `json:"state"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&output) != nil {
		return errors.New("tosctl returned an invalid wallet action resolution")
	}
	finalizedSequenceAdvanced := output.FinalizedControllerEpoch > output.ControllerEpoch ||
		(output.FinalizedControllerEpoch == output.ControllerEpoch && output.FinalizedSeqno > output.Seqno)
	if output.Schema != "tos.agent-account.task-send-finalized.v1" ||
		output.Wallet != sender.wallet || output.ActionID != actionID ||
		output.DeploymentID != prepared.DeploymentID || output.ControllerEpoch != prepared.ControllerEpoch ||
		output.Seqno != prepared.Seqno ||
		!sameAddress(output.SourceAccount, prepared.Intent.Authorization.SourceAccount) ||
		!sameAddress(output.Destination, prepared.Intent.Destination) ||
		output.AmountNanoTOS != prepared.Intent.AmountNanoTOS || output.BodyHash != prepared.Intent.BodyHash ||
		output.ExactSignedBOCDigest != prepared.MessageHash || !validCellDigest(output.SubmittedMessageCellHash) ||
		!sameCustodyNetworkDomain(output.NetworkDomain, prepared.Intent.Authorization.NetworkDomain) ||
		!finalizedSequenceAdvanced ||
		output.Quorum.Members != 3 || output.Quorum.Threshold != 2 || output.Quorum.Agreeing < 2 || output.Quorum.Agreeing > 3 ||
		output.IndependentOperatorsProven || output.ProcessViewScope != "distinct RPC process views; no independent-operator or Byzantine-finality claim" ||
		output.BlockReferenceScope != "RPC-asserted transaction and block identifiers; no inclusion proof was verified" ||
		len(output.Transaction) == 0 || len(output.Observations) < 2 || len(output.Observations) > 3 || output.State != "resolved" {
		return errors.New("tosctl resolved a conflicting wallet action")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tosctl wallet action resolution output has trailing data")
	}
	return nil
}

func validateWalletActionIntent(intent WalletActionIntent) error {
	if !validSHA256Digest(intent.StableActionID) || intent.NetworkID == "" || len(intent.NetworkID) > 128 ||
		strings.TrimSpace(intent.NetworkID) != intent.NetworkID || intent.TransitionKind == "" ||
		len(intent.TransitionKind) > 128 || strings.TrimSpace(intent.TransitionKind) != intent.TransitionKind ||
		!isRawAddress(intent.Destination) || intent.AmountNanoTOS == 0 || intent.AmountNanoTOS > 100_000_000_000 || intent.ValidUntilUnix == 0 ||
		!validCellDigest(intent.BodyHash) {
		return errors.New("wallet action metadata is invalid")
	}
	body, err := decodeSingleCell(intent.BodyBOCBase64)
	if err != nil || cellHash(body) != intent.BodyHash {
		return errors.New("wallet action body is invalid")
	}
	if (intent.StateInitBOCBase64 == "") != (intent.StateInitHash == "") {
		return errors.New("wallet action StateInit is incomplete")
	}
	if intent.StateInitBOCBase64 != "" {
		stateInit, hash, err := decodeStateInit(intent.StateInitBOCBase64)
		if err != nil || hash != intent.StateInitHash || intent.Destination != "0:"+fmt.Sprintf("%x", stateInit.Hash()) {
			return errors.New("wallet action StateInit is invalid")
		}
	}
	noStateInit := "sha256:" + strings.Repeat("0", 64)
	authorization := intent.Authorization
	if authorization.StableActionID != intent.StableActionID || authorization.NetworkID != intent.NetworkID ||
		authorization.ActionKind != intent.TransitionKind || authorization.Destination != intent.Destination ||
		authorization.AmountNanoTOS != intent.AmountNanoTOS || authorization.BodyHash != intent.BodyHash ||
		authorization.StateInitHashOrZero != noStateInit || authorization.ExpiresAtUnix < uint64(intent.ValidUntilUnix) {
		return errors.New("wallet action differs from custody authorization")
	}
	return nil
}

func cloneWalletActionIntent(intent WalletActionIntent) WalletActionIntent { return intent }

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	raw, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil && !bytes.Equal(raw, make([]byte, 32))
}

func sha256Text(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func decodeBase64BOC(value string) ([]byte, error) {
	if value == "" || len(value) > 4<<20 {
		return nil, errors.New("invalid BOC encoding")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) == 0 || len(raw) > 3<<20 {
		return nil, errors.New("invalid BOC encoding")
	}
	return raw, nil
}

func writeCustodyEffectAuthorization(value commerce.CustodyEffectAuthorization) (string, func(), error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) == 0 || len(raw) > 64<<10 {
		return "", nil, errors.New("invalid custody effect authorization")
	}
	directory, err := os.MkdirTemp("", "tos-custody-effect-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	if err := os.Chmod(directory, 0700); err != nil {
		cleanup()
		return "", nil, err
	}
	path := filepath.Join(directory, "authorization.json")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = file.Write(raw)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		cleanup()
		return "", nil, err
	}
	return path, cleanup, nil
}

func (sender *TOSCTLWalletActionSender) run(ctx context.Context, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, sender.timeout)
	defer cancel()
	return sender.runner.run(call, sender.binary, args...)
}
