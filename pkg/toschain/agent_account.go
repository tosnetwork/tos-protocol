package toschain

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/tosnetwork/tos-protocol/internal/jsonstrict"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type blockID struct {
	Type      string `json:"@type"`
	Workchain int32  `json:"workchain"`
	Shard     string `json:"shard"`
	Seqno     uint64 `json:"seqno"`
	RootHash  string `json:"root_hash"`
	FileHash  string `json:"file_hash"`
}

type transactionID struct {
	Type string `json:"@type"`
	LT   string `json:"lt"`
	Hash string `json:"hash"`
}

type accountInformation struct {
	Type              string          `json:"@type"`
	Balance           string          `json:"balance"`
	Code              string          `json:"code"`
	Data              string          `json:"data"`
	LastTransactionID transactionID   `json:"last_transaction_id"`
	BlockID           blockID         `json:"block_id"`
	SyncUtime         int64           `json:"sync_utime"`
	ExtraCurrencies   json.RawMessage `json:"extra_currencies"`
	State             string          `json:"state"`
	FrozenHash        string          `json:"frozen_hash"`
}

type runMethodResult struct {
	Type     string            `json:"@type"`
	GasUsed  uint64            `json:"gas_used"`
	Stack    []json.RawMessage `json:"stack"`
	ExitCode int32             `json:"exit_code"`
}

type stackNumber struct {
	Type   string `json:"@type"`
	Number struct {
		Type   string `json:"@type"`
		Number string `json:"number"`
	} `json:"number"`
}

type agentAccountState struct {
	controllerKey  []byte
	controllerID   string
	manifestDigest string
	codeHash       string
}

type agentAccountQuorumState struct {
	ControllerKeyHex string `json:"controller_key_hex"`
	ManifestDigest   string `json:"manifest_digest"`
	CodeHash         string `json:"code_hash"`
}

func (a *Adapter) resolveAgentAccount(
	ctx context.Context,
	account string,
	serviceID string,
	requireManifestCommitment bool,
) (agentAccountState, consensusObservation, error) {
	observation, nodes, err := a.consensus(ctx)
	if err != nil {
		return agentAccountState{}, consensusObservation{}, err
	}
	state, _, err := quorumRead(ctx, nodes, a.quorum, func(
		ctx context.Context,
		node *rpcNode,
	) (agentAccountQuorumState, error) {
		return readAgentAccount(
			ctx, node, account, observation.seqno, requireManifestCommitment,
		)
	})
	if err != nil {
		return agentAccountState{}, consensusObservation{}, fmt.Errorf(
			"resolve Agent Account quorum for service %q: %w", serviceID, err,
		)
	}
	key, err := hex.DecodeString(state.ControllerKeyHex)
	if err != nil || len(key) != 32 {
		return agentAccountState{}, consensusObservation{}, errors.New("invalid quorum controller key")
	}
	return agentAccountState{
		controllerKey: key, controllerID: controllerID(key),
		manifestDigest: state.ManifestDigest, codeHash: state.CodeHash,
	}, observation, nil
}

func readAgentAccount(
	ctx context.Context,
	node *rpcNode,
	account string,
	masterSeqno uint64,
	requireManifestCommitment bool,
) (agentAccountQuorumState, error) {
	params := struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{Address: account, Seqno: masterSeqno}
	var information accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", params, &information); err != nil {
		return agentAccountQuorumState{}, err
	}
	if information.Type != "raw.fullAccountState" || information.State != "active" ||
		information.Code == "" || information.BlockID.Type != "tos.blockIdExt" ||
		information.BlockID.Workchain != -1 || information.BlockID.Seqno != masterSeqno {
		return agentAccountQuorumState{}, errors.New("Agent Account is not active")
	}
	codeHash, err := cellHashFromBase64(information.Code)
	if err != nil {
		return agentAccountQuorumState{}, fmt.Errorf("decode Agent Account code: %w", err)
	}
	methodParams := struct {
		Address string        `json:"address"`
		Method  string        `json:"method"`
		Stack   []interface{} `json:"stack"`
		Seqno   uint64        `json:"seqno"`
	}{Address: account, Method: "get_agent_account_data", Stack: []interface{}{}, Seqno: masterSeqno}
	var method runMethodResult
	if err := node.client.Call(ctx, "runGetMethodStd", methodParams, &method); err != nil {
		return agentAccountQuorumState{}, err
	}
	if method.Type != "smc.runResult" || method.ExitCode != 0 || len(method.Stack) != 10 {
		return agentAccountQuorumState{}, errors.New("invalid Agent Account get-method result")
	}
	// runGetMethodStd serializes the TVM stack from top to bottom. FunC's
	// tuple return order is therefore reversed in the JSON array: owner is
	// entry 9, controller is 8, and service_endpoint_hash is 3.
	controller, err := decodeStackUint256(method.Stack[8], false)
	if err != nil {
		return agentAccountQuorumState{}, fmt.Errorf("decode Agent Account controller: %w", err)
	}
	if allZero(controller) {
		return agentAccountQuorumState{}, errors.New("Agent Account controller key is zero")
	}
	result := agentAccountQuorumState{
		ControllerKeyHex: hex.EncodeToString(controller),
		CodeHash:         codeHashPrefix + hex.EncodeToString(codeHash),
	}
	if requireManifestCommitment {
		commitment, err := decodeStackUint256(method.Stack[3], true)
		if err != nil {
			return agentAccountQuorumState{}, fmt.Errorf(
				"decode Agent Account manifest commitment: %w", err,
			)
		}
		if commitment == nil || allZero(commitment) {
			return agentAccountQuorumState{}, errors.New(
				"Agent Account has no service manifest commitment",
			)
		}
		// The TOS Protocol Agent Account profile assigns
		// service_endpoint_hash to the canonical tos.manifest.v1 digest.
		// metadata_hash retains its native AgentCapabilityMetadataBundle
		// meaning and is deliberately not reinterpreted here.
		result.ManifestDigest = manifestHashPrefix + hex.EncodeToString(commitment)
	}
	return result, nil
}

func decodeStackUint256(raw json.RawMessage, allowMissing bool) ([]byte, error) {
	var entry stackNumber
	if err := jsonstrict.Decode(raw, &entry); err != nil {
		return nil, err
	}
	if entry.Type != "tvm.stackEntryNumber" || entry.Number.Type != "tvm.numberDecimal" ||
		entry.Number.Number == "" {
		return nil, errors.New("stack entry is not a decimal number")
	}
	if allowMissing && entry.Number.Number == "-1" {
		return nil, nil
	}
	value, ok := new(big.Int).SetString(entry.Number.Number, 10)
	if !ok || value.Sign() < 0 || value.BitLen() > 256 {
		return nil, errors.New("stack number is outside uint256")
	}
	result := make([]byte, 32)
	value.FillBytes(result)
	return result, nil
}

func allZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func cellHashFromBase64(value string) (hash []byte, err error) {
	data, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			hash = nil
			err = fmt.Errorf("invalid BOC: %v", recovered)
		}
	}()
	root, err := cell.FromBOC(data)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), root.Hash()...), nil
}
