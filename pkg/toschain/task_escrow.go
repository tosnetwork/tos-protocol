package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/identity"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const taskEscrowReferencePrefix = "tos:task-escrow:v1:"

var taskEscrowOpcodes = map[chain.TaskEscrowActionKind]uint64{
	chain.TaskEscrowActionAccept:  0x54415301,
	chain.TaskEscrowActionResult:  0x54415302,
	chain.TaskEscrowActionSettle:  0x54415303,
	chain.TaskEscrowActionCancel:  0x54415304,
	chain.TaskEscrowActionTimeout: 0x54415305,
	chain.TaskEscrowActionReject:  0x54415306,
	chain.TaskEscrowActionDispute: 0x54415308,
	chain.TaskEscrowActionResolve: 0x54415309,
}

type taskEscrowQuorumState struct {
	ContractAddress    string `json:"contract_address"`
	Creator            string `json:"creator"`
	Agent              string `json:"agent"`
	HasAgent           bool   `json:"has_agent"`
	Verifier           string `json:"verifier"`
	HasVerifier        bool   `json:"has_verifier"`
	BudgetNanoTOS      uint64 `json:"budget_nano_tos"`
	BalanceNanoTOS     uint64 `json:"balance_nano_tos"`
	DeadlineUnix       uint64 `json:"deadline_unix"`
	Status             uint8  `json:"status"`
	ResultHash         string `json:"result_hash"`
	EvidenceHash       string `json:"evidence_hash"`
	PolicyHash         string `json:"policy_hash"`
	PermissionHash     string `json:"permission_hash"`
	ReviewPeriod       uint32 `json:"review_period"`
	ReviewDeadlineUnix uint64 `json:"review_deadline_unix"`
	DisputeHash        string `json:"dispute_hash"`
	AttestorPublicKey  string `json:"attestor_public_key"`
	CodeHash           string `json:"code_hash"`
}

type taskTransitionQuorumState struct {
	Sender             string `json:"sender"`
	InboundNanoTOS     uint64 `json:"inbound_nano_tos"`
	BodyHash           string `json:"body_hash"`
	Opcode             uint64 `json:"opcode"`
	QueryID            uint64 `json:"query_id"`
	AgentPaidNanoTOS   uint64 `json:"agent_paid_nano_tos"`
	CreatorPaidNanoTOS uint64 `json:"creator_paid_nano_tos"`
}

func FormatTaskEscrowReference(address string) (string, error) {
	canonical, err := requireCanonicalAddress(address)
	if err != nil {
		return "", err
	}
	return taskEscrowReferencePrefix + canonical, nil
}

func ParseTaskEscrowReference(reference string) (string, error) {
	if !strings.HasPrefix(reference, taskEscrowReferencePrefix) {
		return "", errors.New("unsupported TOS task escrow reference")
	}
	return requireCanonicalAddress(strings.TrimPrefix(reference, taskEscrowReferencePrefix))
}

func (a *Adapter) CheckChainReady(ctx context.Context, now time.Time) (uint64, time.Time, error) {
	if a == nil || ctx == nil || now.IsZero() {
		return 0, time.Time{}, errors.New("invalid TOS chain readiness request")
	}
	observation, _, err := a.consensus(ctx)
	if err != nil {
		return 0, time.Time{}, err
	}
	now = now.UTC()
	if observation.observedAt.IsZero() ||
		observation.observedAt.After(now.Add(identity.MaxClockSkew)) ||
		!observation.observedAt.Add(a.readinessAge).After(now) {
		return 0, time.Time{}, errors.New("TOS chain finality observation is not current")
	}
	return observation.seqno, observation.observedAt, nil
}

func (runtime *Runtime) CheckChainReady(ctx context.Context, now time.Time) (uint64, time.Time, error) {
	if runtime == nil || runtime.Chain == nil {
		return 0, time.Time{}, errors.New("invalid TOS chain runtime")
	}
	return runtime.Chain.CheckChainReady(ctx, now)
}

func (runtime *Runtime) ReadTaskEscrow(
	ctx context.Context,
	reference chain.TaskEscrowReference,
) (chain.TaskEscrowState, error) {
	if runtime == nil || runtime.Chain == nil {
		return chain.TaskEscrowState{}, errors.New("invalid TOS task escrow runtime")
	}
	return runtime.Chain.ReadTaskEscrow(ctx, reference)
}

func (runtime *Runtime) ObserveTaskEscrowTransition(
	ctx context.Context,
	reference chain.TaskEscrowTransitionReference,
) (chain.TaskEscrowTransition, error) {
	if runtime == nil || runtime.Chain == nil {
		return chain.TaskEscrowTransition{}, errors.New("invalid TOS task escrow runtime")
	}
	return runtime.Chain.ObserveTaskEscrowTransition(ctx, reference)
}

func (a *Adapter) ReadTaskEscrow(
	ctx context.Context,
	reference chain.TaskEscrowReference,
) (chain.TaskEscrowState, error) {
	if a == nil || ctx == nil || reference.Network != a.network {
		return chain.TaskEscrowState{}, errors.New("invalid TOS task escrow reference")
	}
	contractAddress, err := requireCanonicalAddress(reference.ContractAddress)
	if err != nil {
		return chain.TaskEscrowState{}, fmt.Errorf("invalid task escrow address: %w", err)
	}
	allowed, err := normalizedCodeHashSet(reference.AllowedCodeHashes)
	if err != nil {
		return chain.TaskEscrowState{}, err
	}
	observation, nodes, err := a.consensus(ctx)
	if err != nil {
		return chain.TaskEscrowState{}, err
	}
	if observation.seqno < reference.MinimumMasterSeqno {
		return chain.TaskEscrowState{}, errors.New("TOS task escrow observation is below high-water mark")
	}
	state, _, err := quorumRead(ctx, nodes, a.quorum, func(
		ctx context.Context,
		node *rpcNode,
	) (taskEscrowQuorumState, error) {
		return readTaskEscrowAt(ctx, node, contractAddress, observation.seqno, allowed)
	})
	if err != nil {
		return chain.TaskEscrowState{}, fmt.Errorf("resolve TOS task escrow quorum: %w", err)
	}
	return chain.TaskEscrowState{
		Network: a.network, ContractAddress: state.ContractAddress,
		Creator: state.Creator, Agent: state.Agent, HasAgent: state.HasAgent,
		Verifier: state.Verifier, HasVerifier: state.HasVerifier,
		BudgetNanoTOS: state.BudgetNanoTOS, BalanceNanoTOS: state.BalanceNanoTOS,
		DeadlineUnix: state.DeadlineUnix, Status: chain.TaskEscrowStatus(state.Status),
		ResultHash: state.ResultHash, EvidenceHash: state.EvidenceHash,
		PolicyHash: state.PolicyHash, PermissionHash: state.PermissionHash,
		ReviewPeriod: state.ReviewPeriod, ReviewDeadlineUnix: state.ReviewDeadlineUnix,
		DisputeHash: state.DisputeHash, AttestorPublicKey: state.AttestorPublicKey,
		CodeHash: state.CodeHash, ObservedMasterSeqno: observation.seqno,
		ObservedAt: observation.observedAt,
	}, nil
}

func readTaskEscrowAt(
	ctx context.Context,
	node *rpcNode,
	contractAddress string,
	masterSeqno uint64,
	allowedCodeHashes map[string]struct{},
) (taskEscrowQuorumState, error) {
	params := struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{Address: contractAddress, Seqno: masterSeqno}
	var information accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", params, &information); err != nil {
		return taskEscrowQuorumState{}, err
	}
	if information.Type != "raw.fullAccountState" || information.State != "active" ||
		information.Code == "" || information.Data == "" ||
		information.BlockID.Type != "tos.blockIdExt" || information.BlockID.Workchain != -1 ||
		information.BlockID.Seqno != masterSeqno {
		return taskEscrowQuorumState{}, errors.New("Task Escrow is not active at finalized state")
	}
	codeHashBytes, err := cellHashFromBase64(information.Code)
	if err != nil {
		return taskEscrowQuorumState{}, fmt.Errorf("decode Task Escrow code: %w", err)
	}
	codeHash := codeHashPrefix + hex.EncodeToString(codeHashBytes)
	if _, ok := allowedCodeHashes[codeHash]; !ok {
		return taskEscrowQuorumState{}, errors.New("Task Escrow code hash is not allowed")
	}
	balance, err := strconv.ParseUint(information.Balance, 10, 64)
	if err != nil {
		return taskEscrowQuorumState{}, errors.New("Task Escrow balance is outside uint64")
	}
	data, err := base64.StdEncoding.DecodeString(information.Data)
	if err != nil {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow data encoding")
	}
	root, err := cell.FromBOC(data)
	if err != nil {
		return taskEscrowQuorumState{}, fmt.Errorf("decode Task Escrow data: %w", err)
	}
	state, err := decodeTaskEscrowData(root, contractAddress, balance, codeHash)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	return state, nil
}

func decodeTaskEscrowData(
	root *cell.Cell,
	contractAddress string,
	balance uint64,
	codeHash string,
) (taskEscrowQuorumState, error) {
	if root == nil {
		return taskEscrowQuorumState{}, errors.New("Task Escrow data cell is missing")
	}
	slice := root.BeginParse()
	creator, err := slice.LoadAddr()
	if err != nil || creator == nil || creator.IsAddrNone() || creator.Type() != address.StdAddress {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow creator")
	}
	hasAgent, err := slice.LoadBoolBit()
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	agent, err := slice.LoadAddr()
	if err != nil || agent == nil || (hasAgent && (agent.IsAddrNone() || agent.Type() != address.StdAddress)) {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow agent")
	}
	hasVerifier, err := slice.LoadBoolBit()
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	verifier, err := slice.LoadAddr()
	if err != nil || verifier == nil || (hasVerifier && (verifier.IsAddrNone() || verifier.Type() != address.StdAddress)) {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow verifier")
	}
	budget, err := slice.LoadBigCoins()
	if err != nil || !budget.IsUint64() {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow budget")
	}
	deadline, err := slice.LoadUInt(64)
	if err != nil || deadline == 0 {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow deadline")
	}
	status, err := slice.LoadUInt(8)
	if err != nil || status > uint64(chain.TaskEscrowStatusDisputed) {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow status")
	}
	hashes, err := slice.LoadRef()
	if err != nil {
		return taskEscrowQuorumState{}, errors.New("Task Escrow hashes are missing")
	}
	resultHash, err := hashes.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	evidenceHash, err := hashes.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	policyHash, err := hashes.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	reviewPeriod, err := hashes.LoadUInt(32)
	if err != nil || reviewPeriod < 3600 || reviewPeriod > uint64(^uint32(0)) {
		return taskEscrowQuorumState{}, errors.New("invalid Task Escrow review period")
	}
	reviewDeadline, err := hashes.LoadUInt(64)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	permission, err := hashes.LoadRef()
	if err != nil {
		return taskEscrowQuorumState{}, errors.New("Task Escrow permission state is missing")
	}
	permissionHash, err := permission.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	disputeHash, err := permission.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	attestor, err := hashes.LoadRef()
	if err != nil {
		return taskEscrowQuorumState{}, errors.New("Task Escrow attestor state is missing")
	}
	hasAttestor, err := attestor.LoadBoolBit()
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	attestorKey, err := attestor.LoadSlice(256)
	if err != nil {
		return taskEscrowQuorumState{}, err
	}
	if slice.BitsLeft() != 0 || slice.RefsNum() != 0 || hashes.BitsLeft() != 0 ||
		hashes.RefsNum() != 0 || permission.BitsLeft() != 0 || permission.RefsNum() != 0 ||
		attestor.BitsLeft() != 0 || attestor.RefsNum() != 0 {
		return taskEscrowQuorumState{}, errors.New("Task Escrow data contains trailing fields")
	}
	agentAddress := ""
	if !agent.IsAddrNone() {
		agentAddress = agent.StringRaw()
	}
	verifierAddress := ""
	if !verifier.IsAddrNone() {
		verifierAddress = verifier.StringRaw()
	}
	state := taskEscrowQuorumState{
		ContractAddress: contractAddress, Creator: creator.StringRaw(),
		Agent: agentAddress, HasAgent: hasAgent,
		Verifier: verifierAddress, HasVerifier: hasVerifier,
		BudgetNanoTOS: budget.Uint64(), BalanceNanoTOS: balance,
		DeadlineUnix: deadline, Status: uint8(status),
		ResultHash: digestHex(resultHash), EvidenceHash: digestHex(evidenceHash),
		PolicyHash: digestHex(policyHash), PermissionHash: digestHex(permissionHash),
		ReviewPeriod: uint32(reviewPeriod), ReviewDeadlineUnix: reviewDeadline,
		DisputeHash: digestHex(disputeHash), CodeHash: codeHash,
	}
	if !hasAgent {
		state.Agent = ""
	}
	if !hasVerifier {
		state.Verifier = ""
	}
	if hasAttestor {
		state.AttestorPublicKey = hex.EncodeToString(attestorKey)
	} else if !allZero(attestorKey) {
		return taskEscrowQuorumState{}, errors.New("Task Escrow disabled attestor key is not zero")
	}
	return state, nil
}

func (a *Adapter) ObserveTaskEscrowTransition(
	ctx context.Context,
	reference chain.TaskEscrowTransitionReference,
) (chain.TaskEscrowTransition, error) {
	if a == nil || ctx == nil || reference.Network != a.network ||
		strings.TrimSpace(reference.TransactionReference) == "" {
		return chain.TaskEscrowTransition{}, errors.New("invalid TOS task escrow transition reference")
	}
	contractAddress, err := requireCanonicalAddress(reference.ContractAddress)
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	target, err := parseTransactionReference(reference.TransactionReference)
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	if target.payee != contractAddress {
		return chain.TaskEscrowTransition{}, errors.New("task transition reference does not name the escrow contract")
	}
	before, nodes, err := a.consensus(ctx)
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	if before.seqno < reference.MinimumMasterSeqno {
		return chain.TaskEscrowTransition{}, errors.New("task transition observation is below high-water mark")
	}
	observed, _, err := quorumRead(ctx, nodes, a.quorum, func(
		ctx context.Context,
		node *rpcNode,
	) (taskTransitionQuorumState, error) {
		return readTaskEscrowTransition(ctx, node, target, contractAddress,
			reference.ExpectedAgent, reference.ExpectedCreator)
	})
	if err != nil {
		return chain.TaskEscrowTransition{}, fmt.Errorf("resolve task transition quorum: %w", err)
	}
	if expectedSender := strings.TrimSpace(reference.ExpectedSender); expectedSender != "" {
		expectedSender, err = requireCanonicalAddress(expectedSender)
		if err != nil || observed.Sender != expectedSender {
			return chain.TaskEscrowTransition{}, errors.New("task transition sender mismatch")
		}
	}
	if observed.InboundNanoTOS < reference.ExpectedInboundMinimum {
		return chain.TaskEscrowTransition{}, errors.New("task transition funding is below expected minimum")
	}
	if reference.ExpectedKind != chain.TaskEscrowActionDeploy {
		expectedOpcode, ok := taskEscrowOpcodes[reference.ExpectedKind]
		if !ok || observed.Opcode != expectedOpcode || observed.QueryID != reference.ExpectedQueryID ||
			observed.BodyHash != reference.ExpectedBodyHash {
			return chain.TaskEscrowTransition{}, errors.New("task transition body binding mismatch")
		}
	}
	if (strings.TrimSpace(reference.ExpectedAgent) != "" &&
		observed.AgentPaidNanoTOS != reference.ExpectedAgentPayout) ||
		observed.CreatorPaidNanoTOS < reference.ExpectedCreatorMinimum {
		return chain.TaskEscrowTransition{}, errors.New("task transition payout binding mismatch")
	}
	after, _, err := a.consensus(ctx)
	if err != nil || after.seqno < before.seqno {
		return chain.TaskEscrowTransition{}, errors.New("task transition finality observation is not current")
	}
	state, err := a.ReadTaskEscrow(ctx, chain.TaskEscrowReference{
		Network: a.network, ContractAddress: contractAddress,
		AllowedCodeHashes:  reference.AllowedCodeHashes,
		MinimumMasterSeqno: after.seqno,
	})
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	return chain.TaskEscrowTransition{
		State: state, TransactionReference: reference.TransactionReference,
		Sender: observed.Sender, BodyHash: observed.BodyHash, QueryID: observed.QueryID,
		AgentPaidNanoTOS:    observed.AgentPaidNanoTOS,
		CreatorPaidNanoTOS:  observed.CreatorPaidNanoTOS,
		ObservedMasterSeqno: state.ObservedMasterSeqno, ObservedAt: state.ObservedAt,
	}, nil
}

func readTaskEscrowTransition(
	ctx context.Context,
	node *rpcNode,
	target transactionReference,
	contractAddress, expectedAgent, expectedCreator string,
) (taskTransitionQuorumState, error) {
	params := struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{
		Address: contractAddress, Limit: 1, LT: strconv.FormatUint(target.lt, 10),
		Hash: base64.StdEncoding.EncodeToString(target.hash),
	}
	var transactions []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", params, &transactions); err != nil {
		return taskTransitionQuorumState{}, err
	}
	if len(transactions) != 1 {
		return taskTransitionQuorumState{}, errors.New("exact task transition query returned an unexpected count")
	}
	return decodeTaskEscrowTransition(transactions[0], target, contractAddress, expectedAgent, expectedCreator)
}

func decodeTaskEscrowTransition(
	raw rawTransaction,
	target transactionReference,
	contractAddress, expectedAgent, expectedCreator string,
) (result taskTransitionQuorumState, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = taskTransitionQuorumState{}
			err = fmt.Errorf("invalid task transition BOC: %v", recovered)
		}
	}()
	if raw.Type != "raw.transaction" || raw.BlockID.Type != "tos.blockIdExt" ||
		raw.BlockID.Workchain != target.workchain || raw.BlockID.Seqno == 0 ||
		raw.TransactionID.Type != "internal.transactionId" || raw.Data == "" {
		return taskTransitionQuorumState{}, errors.New("invalid raw task transition response")
	}
	lt, err := strconv.ParseUint(raw.TransactionID.LT, 10, 64)
	if err != nil || lt != target.lt {
		return taskTransitionQuorumState{}, errors.New("task transaction logical time mismatch")
	}
	if _, err := decodeBase64Hash(raw.BlockID.RootHash); err != nil {
		return taskTransitionQuorumState{}, errors.New("invalid task transaction block root hash")
	}
	if _, err := decodeBase64Hash(raw.BlockID.FileHash); err != nil {
		return taskTransitionQuorumState{}, errors.New("invalid task transaction block file hash")
	}
	responseHash, err := base64.StdEncoding.DecodeString(raw.TransactionID.Hash)
	if err != nil || !bytes.Equal(responseHash, target.hash) {
		return taskTransitionQuorumState{}, errors.New("task transaction hash mismatch")
	}
	boc, err := base64.StdEncoding.DecodeString(raw.Data)
	if err != nil {
		return taskTransitionQuorumState{}, errors.New("invalid task transaction BOC encoding")
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(root.Hash(), target.hash) {
		return taskTransitionQuorumState{}, errors.New("task transaction BOC hash mismatch")
	}
	var transaction tlb.Transaction
	if err := tlb.LoadFromCell(&transaction, root.BeginParse()); err != nil {
		return taskTransitionQuorumState{}, fmt.Errorf("decode task transaction: %w", err)
	}
	if transaction.LT != target.lt || !bytes.Equal(transaction.AccountAddr, target.account) ||
		transaction.Now != raw.Utime || !strings.EqualFold(raw.Account, hex.EncodeToString(target.account)) ||
		transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal {
		return taskTransitionQuorumState{}, errors.New("task transaction is not an inbound internal call")
	}
	if err := verifySuccessfulOrdinaryTransaction(&transaction); err != nil {
		return taskTransitionQuorumState{}, err
	}
	message := transaction.IO.In.AsInternal()
	if message == nil || message.Bounced || message.SrcAddr == nil || message.DstAddr == nil ||
		message.SrcAddr.Type() != address.StdAddress || message.DstAddr.Type() != address.StdAddress ||
		message.SrcAddr.StringRaw() == "" || message.DstAddr.StringRaw() != contractAddress {
		return taskTransitionQuorumState{}, errors.New("task transaction inbound message is invalid")
	}
	amount := message.Amount.Nano()
	if amount.Sign() < 0 || !amount.IsUint64() {
		return taskTransitionQuorumState{}, errors.New("task transaction inbound amount is outside uint64")
	}
	result.Sender = message.SrcAddr.StringRaw()
	result.InboundNanoTOS = amount.Uint64()
	if message.Body != nil {
		result.BodyHash = codeHashPrefix + hex.EncodeToString(message.Body.Hash())
		body := message.Body.BeginParse()
		if body.BitsLeft() >= 96 {
			result.Opcode, _ = body.LoadUInt(32)
			result.QueryID, _ = body.LoadUInt(64)
		}
	}
	if transaction.IO.Out != nil {
		outputs, err := transaction.IO.Out.ToSlice()
		if err != nil {
			return taskTransitionQuorumState{}, err
		}
		for _, output := range outputs {
			if output.MsgType != tlb.MsgTypeInternal {
				continue
			}
			internal := output.AsInternal()
			if internal == nil || internal.Bounced || internal.SrcAddr == nil ||
				internal.DstAddr == nil || internal.SrcAddr.Type() != address.StdAddress ||
				internal.DstAddr.Type() != address.StdAddress ||
				internal.SrcAddr.StringRaw() != contractAddress {
				continue
			}
			nano := internal.Amount.Nano()
			if nano.Sign() < 0 || !nano.IsUint64() {
				return taskTransitionQuorumState{}, errors.New("task output amount is outside uint64")
			}
			destination := internal.DstAddr.StringRaw()
			if expectedAgent != "" && destination == expectedAgent {
				result.AgentPaidNanoTOS, err = addUint64(result.AgentPaidNanoTOS, nano.Uint64())
				if err != nil {
					return taskTransitionQuorumState{}, err
				}
			}
			if expectedCreator != "" && destination == expectedCreator {
				result.CreatorPaidNanoTOS, err = addUint64(result.CreatorPaidNanoTOS, nano.Uint64())
				if err != nil {
					return taskTransitionQuorumState{}, err
				}
			}
		}
	}
	return result, nil
}

func verifySuccessfulOrdinaryTransaction(transaction *tlb.Transaction) error {
	if transaction == nil {
		return errors.New("task transaction is missing")
	}
	var ordinary tlb.TransactionDescriptionOrdinary
	switch value := transaction.Description.(type) {
	case tlb.TransactionDescriptionOrdinary:
		ordinary = value
	case *tlb.TransactionDescriptionOrdinary:
		if value == nil {
			return errors.New("task transaction description is missing")
		}
		ordinary = *value
	default:
		return errors.New("task transaction is not ordinary")
	}
	if ordinary.Aborted || ordinary.Destroyed || ordinary.ActionPhase == nil ||
		!ordinary.ActionPhase.Success || !ordinary.ActionPhase.Valid || ordinary.ActionPhase.NoFunds ||
		ordinary.ActionPhase.ResultCode != 0 {
		return errors.New("task transaction did not complete successfully")
	}
	switch phase := ordinary.ComputePhase.Phase.(type) {
	case tlb.ComputePhaseVM:
		if !phase.Success || phase.Details.ExitCode != 0 {
			return errors.New("task transaction VM execution failed")
		}
	case *tlb.ComputePhaseVM:
		if phase == nil || !phase.Success || phase.Details.ExitCode != 0 {
			return errors.New("task transaction VM execution failed")
		}
	default:
		return errors.New("task transaction did not execute the VM")
	}
	return nil
}

func normalizedCodeHashSet(values []string) (map[string]struct{}, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, errors.New("Task Escrow code hash allowlist is required")
	}
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !strings.HasPrefix(value, codeHashPrefix) {
			return nil, errors.New("invalid Task Escrow code hash")
		}
		raw := strings.TrimPrefix(value, codeHashPrefix)
		decoded, err := hex.DecodeString(raw)
		if err != nil || len(decoded) != 32 || raw != strings.ToLower(raw) {
			return nil, errors.New("invalid Task Escrow code hash")
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func digestHex(value []byte) string {
	return "sha256:" + hex.EncodeToString(value)
}

func addUint64(left, right uint64) (uint64, error) {
	value := new(big.Int).Add(new(big.Int).SetUint64(left), new(big.Int).SetUint64(right))
	if !value.IsUint64() {
		return 0, errors.New("task output amount overflows uint64")
	}
	return value.Uint64(), nil
}

var _ chain.TaskEscrowObserver = (*Runtime)(nil)
