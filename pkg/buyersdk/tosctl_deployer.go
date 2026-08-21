package buyersdk

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// TOSCTLEscrowDeployerConfig pins the custody command used to deploy one
// already-reviewed deterministic escrow. The deployer never receives keys.
type TOSCTLEscrowDeployerConfig struct {
	BinaryPath      string
	ConfigPath      string
	WalletName      string
	BuyerAddress    string
	AttachedNanoTOS uint64
	Timeout         time.Duration
}

// PreparedEscrowDeployment binds the reviewed StateInit to the exact signed
// external wallet message. It is safe to persist between owner review and the
// separate one-way broadcast step.
type PreparedEscrowDeployment struct {
	Schema             string `json:"schema"`
	EscrowAddress      string `json:"escrow_address"`
	QuoteCommitment    string `json:"quote_commitment"`
	StateInitBOCBase64 string `json:"state_init_boc_base64"`
	StateInitHash      string `json:"state_init_hash"`
	AttachedNanoTOS    uint64 `json:"attached_nanotos"`
	MessageBOCBase64   string `json:"message_boc_base64"`
	MessageHash        string `json:"message_hash"`
}

type TOSCTLEscrowDeployer struct {
	binary, config, wallet, buyer string
	attached                      uint64
	timeout                       time.Duration
	runner                        commandRunner
}

func NewTOSCTLEscrowDeployer(c TOSCTLEscrowDeployerConfig) (*TOSCTLEscrowDeployer, error) {
	if !secureExecutable(c.BinaryPath) || !secureConfigFile(c.ConfigPath) || !isRawAddress(c.BuyerAddress) ||
		c.WalletName == "" || strings.TrimSpace(c.WalletName) != c.WalletName || len(c.WalletName) > 128 {
		return nil, errors.New("invalid tosctl escrow deployer configuration")
	}
	if c.AttachedNanoTOS == 0 {
		c.AttachedNanoTOS = 100_000_000
	}
	if c.AttachedNanoTOS > 1_000_000_000 {
		return nil, errors.New("invalid escrow deployment fee budget")
	}
	if c.Timeout == 0 {
		c.Timeout = 90 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return nil, errors.New("invalid tosctl deployer timeout")
	}
	return &TOSCTLEscrowDeployer{binary: c.BinaryPath, config: c.ConfigPath, wallet: c.WalletName,
		buyer: c.BuyerAddress, attached: c.AttachedNanoTOS, timeout: c.Timeout, runner: execRunner{}}, nil
}

// PrepareEscrowDeployment asks custody to sign, but not broadcast, the exact
// StateInit-bearing deployment message and independently checks its projection.
func (d *TOSCTLEscrowDeployer) PrepareEscrowDeployment(ctx context.Context, purchase *PreparedPurchase) (*PreparedEscrowDeployment, error) {
	if d == nil || ctx == nil {
		return nil, errors.New("invalid tosctl escrow deployment request")
	}
	stateInit, stateInitHash, err := validateDeploymentPurchase(purchase)
	if err != nil {
		return nil, err
	}
	state, err := decodePreparedEscrowData(purchase)
	if err != nil || state.BuyerAddress != d.buyer {
		return nil, errors.New("prepared escrow buyer does not match custody payer")
	}
	args := []string{"wallet", "--config", d.config, "send", "--from", d.wallet,
		"--to", purchase.Escrow.Address, "--amount-nanotos", fmt.Sprint(d.attached),
		"--state-init-boc", stateInit, "--build-only"}
	preparedRaw, err := d.run(ctx, args...)
	if err != nil {
		return nil, errors.New("tosctl could not prepare escrow deployment")
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
	emptyBody := cell.BeginCell().EndCell()
	if decoder.Decode(&prepared) != nil || prepared.Version != "tosctl.wallet-prepared-send.v1" ||
		prepared.Wallet != d.wallet || !sameAddress(prepared.Payer, d.buyer) ||
		!sameAddress(prepared.Destination, purchase.Escrow.Address) || prepared.AmountNanoTOS != d.attached ||
		prepared.BodyHash != cellHash(emptyBody) || prepared.StateInitHash != stateInitHash || prepared.MessageBOC == "" {
		return nil, errors.New("tosctl prepared a conflicting escrow deployment message")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("tosctl prepared deployment output has trailing data")
	}
	message, err := decodeSingleCell(prepared.MessageBOC)
	if err != nil {
		return nil, errors.New("tosctl prepared an invalid deployment message BOC")
	}
	return &PreparedEscrowDeployment{Schema: "tos.service.escrow-deployment.v1",
		EscrowAddress: purchase.Escrow.Address, QuoteCommitment: purchase.QuoteCommitment,
		StateInitBOCBase64: stateInit, StateInitHash: stateInitHash, AttachedNanoTOS: d.attached,
		MessageBOCBase64: prepared.MessageBOC, MessageHash: cellHash(message)}, nil
}

// BroadcastEscrowDeployment submits only the exact previously reviewed signed
// bytes. An uncertain outcome is returned as ambiguous and is never rebuilt.
func (d *TOSCTLEscrowDeployer) BroadcastEscrowDeployment(ctx context.Context, prepared *PreparedEscrowDeployment) error {
	if d == nil || ctx == nil || prepared == nil || prepared.Schema != "tos.service.escrow-deployment.v1" ||
		!isRawAddress(prepared.EscrowAddress) || !validCellDigest(prepared.QuoteCommitment) ||
		prepared.AttachedNanoTOS != d.attached || prepared.MessageBOCBase64 == "" || !validCellDigest(prepared.MessageHash) {
		return errors.New("invalid prepared escrow deployment")
	}
	stateInit, stateInitHash, err := decodeStateInit(prepared.StateInitBOCBase64)
	if err != nil || stateInitHash != prepared.StateInitHash ||
		prepared.EscrowAddress != "0:"+hex.EncodeToString(stateInit.Hash()) {
		return errors.New("prepared escrow deployment identity changed")
	}
	_, data, err := strictStateInitParts(stateInit)
	if err != nil {
		return errors.New("prepared escrow deployment StateInit changed")
	}
	state, err := nativecore.DecodeEscrowDataV1(data)
	if err != nil || state.QuoteCommitment != prepared.QuoteCommitment || state.BuyerAddress != d.buyer {
		return errors.New("prepared escrow deployment terms changed")
	}
	message, err := decodeSingleCell(prepared.MessageBOCBase64)
	if err != nil || cellHash(message) != prepared.MessageHash {
		return errors.New("prepared escrow deployment message changed")
	}
	broadcastRaw, err := d.run(ctx, "wallet", "--config", d.config, "broadcast-prepared",
		"--message-boc", prepared.MessageBOCBase64, "--yes")
	if err != nil {
		return errors.New("tosctl escrow deployment broadcast outcome is ambiguous")
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
		return errors.New("tosctl escrow deployment broadcast outcome is ambiguous")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("tosctl deployment broadcast output has trailing data")
	}
	return nil
}

func validateDeploymentPurchase(purchase *PreparedPurchase) (string, string, error) {
	if purchase == nil || purchase.Escrow.Data == nil || !validCellDigest(purchase.QuoteCommitment) ||
		purchase.Escrow.QuoteCommitment != purchase.QuoteCommitment || !isRawAddress(purchase.Escrow.Address) {
		return "", "", errors.New("invalid prepared purchase deployment identity")
	}
	state, err := decodePreparedEscrowData(purchase)
	if err != nil {
		return "", "", err
	}
	if state.QuoteCommitment != purchase.QuoteCommitment {
		return "", "", errors.New("prepared escrow data changed before deployment")
	}
	stateInit, hash, err := decodeStateInit(purchase.Escrow.StateInitBOC)
	if err != nil || purchase.Escrow.Address != "0:"+hex.EncodeToString(stateInit.Hash()) {
		return "", "", errors.New("prepared escrow StateInit changed before deployment")
	}
	code, data, err := strictStateInitParts(stateInit)
	if err != nil || cellHash(code) != purchase.Escrow.CodeHash || !bytes.Equal(data.Hash(), purchase.Escrow.Data.Hash()) {
		return "", "", errors.New("prepared escrow StateInit contents changed before deployment")
	}
	return purchase.Escrow.StateInitBOC, hash, nil
}

// decodePreparedEscrowData keeps deploy-time validation on the same strict
// typed decoder as funding and finalized-chain reconciliation.
func decodePreparedEscrowData(purchase *PreparedPurchase) (*nativecore.EscrowStateV1, error) {
	state, err := nativecore.DecodeEscrowDataV1(purchase.Escrow.Data)
	if err != nil {
		return nil, errors.New("invalid prepared escrow data")
	}
	return state, nil
}

func decodeStateInit(encoded string) (*cell.Cell, string, error) {
	value, err := decodeSingleCell(encoded)
	if err != nil {
		return nil, "", err
	}
	return value, cellHash(value), nil
}

func strictStateInitParts(value *cell.Cell) (*cell.Cell, *cell.Cell, error) {
	if value == nil {
		return nil, nil, errors.New("missing StateInit")
	}
	s, err := value.BeginParse()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit cell")
	}
	splitDepth, err := s.LoadBoolBit()
	if err != nil || splitDepth {
		return nil, nil, errors.New("unsupported StateInit split depth")
	}
	special, err := s.LoadBoolBit()
	if err != nil || special {
		return nil, nil, errors.New("unsupported StateInit special value")
	}
	codePresent, err := s.LoadBoolBit()
	if err != nil || !codePresent {
		return nil, nil, errors.New("missing StateInit code")
	}
	code, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit code")
	}
	dataPresent, err := s.LoadBoolBit()
	if err != nil || !dataPresent {
		return nil, nil, errors.New("missing StateInit data")
	}
	data, err := s.LoadRefCell()
	if err != nil {
		return nil, nil, errors.New("invalid StateInit data")
	}
	libraryPresent, err := s.LoadBoolBit()
	if err != nil || libraryPresent || s.BitsLeft() != 0 || s.RefsNum() != 0 {
		return nil, nil, errors.New("unsupported StateInit library or trailing data")
	}
	return code, data, nil
}

func decodeSingleCell(encoded string) (*cell.Cell, error) {
	if encoded == "" || strings.Join(strings.Fields(encoded), "") != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 2<<20 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, errors.New("invalid cell BOC")
	}
	value, err := cell.FromBOC(raw)
	if err != nil {
		return nil, errors.New("invalid cell BOC")
	}
	return value, nil
}

func cellHash(value *cell.Cell) string {
	return "tvm-cell-sha256:" + hex.EncodeToString(value.Hash())
}

func (d *TOSCTLEscrowDeployer) run(ctx context.Context, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.runner.run(call, d.binary, args...)
}
