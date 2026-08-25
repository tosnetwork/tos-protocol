package toschain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strconv"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/agentgift"
	"github.com/tosnetwork/tosutils-go/tlb"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
	"google.golang.org/protobuf/proto"
)

type AgentGiftReader struct {
	chain   *Adapter
	network *nativev1.NetworkDomain
}

const maxGiftHistoryTransactions = 256

type giftExecutionVote struct {
	Executed      bool   `json:"executed"`
	AbsenceKnown  bool   `json:"absence_known"`
	ExactOutput   bool   `json:"exact_output"`
	OutputHash    string `json:"output_hash"`
	ExecutionTime uint32 `json:"execution_time"`
}

type giftCreditVote struct {
	Credited     bool `json:"credited"`
	AbsenceKnown bool `json:"absence_known"`
}

// ResolveGift traces the exact external message through the finalized sender
// transaction and, when an output exists, through the finalized recipient
// transaction. The bounded history walk starts at each account's
// checkpoint-pinned last transaction, never at a node's moving latest head.
func (r *AgentGiftReader) ResolveGift(ctx context.Context, accountAddress, destination string, exactBOC []byte, signedSeqno, validUntil uint32, expectedDeployment string, feeReserveAtomic uint64, createdAtUnix int64) (agentgift.FinalizedGiftObservation, error) {
	return r.resolveFinalizedGift(ctx, accountAddress, destination, exactBOC, signedSeqno, validUntil, expectedDeployment, feeReserveAtomic, createdAtUnix)
}

func (r *AgentGiftReader) resolveFinalizedGift(ctx context.Context, accountAddress, destination string, exactBOC []byte, signedSeqno, validUntil uint32, expectedDeployment string, feeReserveAtomic uint64, createdAtUnix int64) (agentgift.FinalizedGiftObservation, error) {
	base := agentgift.FinalizedGiftObservation{ExpectedDeploymentID: expectedDeployment, SignedSeqno: signedSeqno, ValidUntil: validUntil}
	if r == nil || ctx == nil || expectedDeployment == "" || validUntil == 0 || createdAtUnix <= 0 {
		return base, errors.New("invalid finalized Gift resolution request")
	}
	parsed, err := agentgift.ParseAgentNativeSendBOC(exactBOC)
	if err != nil || parsed.SenderAgentAccount != accountAddress || parsed.DestinationAddress != destination || parsed.Seqno != signedSeqno || parsed.ValidUntil != validUntil {
		return base, errors.New("finalized Gift request conflicts with exact BOC")
	}
	base.ExpectedControllerEpoch = parsed.ControllerEpoch
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return base, err
	}
	current, err := r.finalizedAgentAccountAt(ctx, accountAddress, observation, nodes)
	if err != nil {
		return base, err
	}
	base.Available = true
	base.FinalizedChainTime = uint32(observation.observedAt.Unix())
	base.CurrentDeploymentID = current.DeploymentID
	base.CurrentControllerEpoch = current.ControllerEpoch
	base.CurrentSeqno = current.Seqno
	base.BalanceAtomic = current.BalanceAtomic
	base.AmountAtomic = parsed.AmountAtomic
	base.FeeReserveAtomic = feeReserveAtomic
	base.ControllerCurrentlyMatches = current.DeploymentID == expectedDeployment && current.ControllerEpoch == parsed.ControllerEpoch
	base.PolicyCurrentlyAllows = parsed.AmountAtomic <= current.MaxPerTxAtomic && parsed.AmountAtomic <= current.DailyRemainingAtomic
	externalRoot, err := cell.FromBOC(exactBOC)
	if err != nil {
		return base, err
	}
	execution, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (giftExecutionVote, error) {
		last, err := finalizedAccountLastTransaction(ctx, node, accountAddress, observation.seqno)
		if err != nil {
			return giftExecutionVote{}, err
		}
		return findGiftExecution(ctx, node, accountAddress, last, externalRoot.Hash(), destination, parsed.AmountAtomic, createdAtUnix)
	})
	if err != nil {
		return base, err
	}
	base.ExactExternalBOCExecuted = execution.Executed
	base.ExecutionFinalityKnown = execution.Executed || execution.AbsenceKnown
	if !execution.Executed {
		return base, nil
	}
	if !execution.ExactOutput {
		// The frozen proof requires exactly one bodyless, non-bouncing output.
		// A finalized sender transaction that violates that invariant cannot be
		// repaired by any recipient transaction, so the exact credit proof is
		// conclusively false without a destination lookup.
		base.DestinationCreditFinalityKnown = true
		return base, nil
	}
	credit, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (giftCreditVote, error) {
		last, err := finalizedAccountLastTransaction(ctx, node, destination, observation.seqno)
		if err != nil {
			return giftCreditVote{}, err
		}
		return findGiftCredit(ctx, node, destination, last, execution.OutputHash, parsed.AmountAtomic, int64(execution.ExecutionTime))
	})
	if err != nil {
		return base, err
	}
	base.ExactDestinationCredit = credit.Credited
	base.DestinationCreditFinalityKnown = credit.Credited || credit.AbsenceKnown
	return base, nil
}

func finalizedAccountLastTransaction(ctx context.Context, node *rpcNode, address string, seqno uint64) (transactionID, error) {
	var info accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{address, seqno}, &info); err != nil {
		return transactionID{}, err
	}
	if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Seqno != seqno || info.LastTransactionID.Type != "internal.transactionId" {
		return transactionID{}, errors.New("Gift account response is not checkpoint-finalized")
	}
	return info.LastTransactionID, nil
}

func finalizedTransactionHistory(ctx context.Context, node *rpcNode, address string, last transactionID) ([]tlb.Transaction, error) {
	var values []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", struct {
		Address string `json:"address"`
		Limit   int    `json:"limit"`
		LT      string `json:"lt"`
		Hash    string `json:"hash"`
	}{address, maxGiftHistoryTransactions, last.LT, last.Hash}, &values); err != nil {
		return nil, err
	}
	if len(values) == 0 || len(values) > maxGiftHistoryTransactions || values[0].TransactionID != last {
		return nil, errors.New("invalid bounded finalized Gift transaction history")
	}
	transactions := make([]tlb.Transaction, 0, len(values))
	var previous *tlb.Transaction
	for _, value := range values {
		if value.Type != "raw.transaction" || value.Data == "" || value.TransactionID.Type != "internal.transactionId" {
			return nil, errors.New("malformed finalized Gift transaction")
		}
		hash, err := decodeBase64Hash(value.TransactionID.Hash)
		if err != nil {
			return nil, err
		}
		raw, err := base64.StdEncoding.DecodeString(value.Data)
		if err != nil {
			return nil, err
		}
		root, err := cell.FromBOC(raw)
		if err != nil || !bytes.Equal(root.Hash(), hash) {
			return nil, errors.New("finalized Gift transaction hash mismatch")
		}
		slice, _ := root.BeginParse()
		var transaction tlb.Transaction
		lt, parseErr := strconv.ParseUint(value.TransactionID.LT, 10, 64)
		if slice == nil || tlb.LoadFromCell(&transaction, slice) != nil || parseErr != nil || transaction.LT != lt {
			return nil, errors.New("invalid finalized Gift transaction BOC")
		}
		transaction.Hash = append([]byte(nil), hash...)
		if previous != nil && (previous.PrevTxLT != transaction.LT || !bytes.Equal(previous.PrevTxHash, hash)) {
			return nil, errors.New("discontinuous finalized Gift transaction history")
		}
		transactions = append(transactions, transaction)
		previous = &transactions[len(transactions)-1]
	}
	return transactions, nil
}

func findGiftExecution(ctx context.Context, node *rpcNode, address string, last transactionID, externalHash []byte, destination string, amount uint64, createdAtUnix int64) (giftExecutionVote, error) {
	history, err := finalizedTransactionHistory(ctx, node, address, last)
	if err != nil {
		return giftExecutionVote{}, err
	}
	return matchGiftExecution(history, externalHash, address, destination, amount, createdAtUnix)
}

func matchGiftExecution(history []tlb.Transaction, externalHash []byte, source, destination string, amount uint64, createdAtUnix int64) (giftExecutionVote, error) {
	if len(history) == 0 {
		return giftExecutionVote{}, errors.New("empty finalized Gift transaction history")
	}
	for _, transaction := range history {
		if transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeExternalIn {
			continue
		}
		message, err := transaction.IO.In.ToCell()
		if err != nil || !bytes.Equal(message.Hash(), externalHash) {
			continue
		}
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		compute, vm := description.ComputePhase.Phase.(tlb.ComputePhaseVM)
		if !ordinary || !vm {
			return giftExecutionVote{}, errors.New("exact Gift external message has an invalid transaction description")
		}
		if !compute.Success || description.Aborted {
			return giftExecutionVote{AbsenceKnown: true}, nil
		}
		vote := giftExecutionVote{Executed: true, AbsenceKnown: true, ExecutionTime: transaction.Now}
		if transaction.IO.Out == nil || transaction.OutMsgCount != 1 {
			return vote, nil
		}
		outputs, err := transaction.IO.Out.ToSlice()
		if err != nil || len(outputs) != 1 || outputs[0].MsgType != tlb.MsgTypeInternal {
			return vote, nil
		}
		out := outputs[0].AsInternal()
		if out.Body == nil {
			return vote, nil
		}
		body, bodyErr := out.Body.BeginParse()
		if out.SrcAddr == nil || out.SrcAddr.StringRaw() != source || out.DstAddr == nil || out.DstAddr.StringRaw() != destination ||
			!out.IHRDisabled || out.Bounce || out.Bounced || out.StateInit != nil ||
			(out.ExtraCurrencies != nil && !out.ExtraCurrencies.IsEmpty()) || bodyErr != nil || body.BitsLeft() != 0 || body.RefsNum() != 0 ||
			out.Amount.Nano().Sign() <= 0 || !out.Amount.Nano().IsUint64() || out.Amount.Nano().Uint64() != amount {
			return vote, nil
		}
		cellValue, err := outputs[0].ToCell()
		if err != nil {
			return vote, err
		}
		vote.ExactOutput = true
		vote.OutputHash = hex.EncodeToString(cellValue.Hash())
		return vote, nil
	}
	oldest := history[len(history)-1]
	return giftExecutionVote{AbsenceKnown: len(history) < maxGiftHistoryTransactions || oldest.PrevTxLT == 0 || int64(oldest.Now) < createdAtUnix}, nil
}

func findGiftCredit(ctx context.Context, node *rpcNode, address string, last transactionID, outputHash string, amount uint64, notBeforeUnix int64) (giftCreditVote, error) {
	history, err := finalizedTransactionHistory(ctx, node, address, last)
	if err != nil {
		return giftCreditVote{}, err
	}
	return matchGiftCredit(history, address, outputHash, amount, notBeforeUnix)
}

func matchGiftCredit(history []tlb.Transaction, address, outputHash string, amount uint64, notBeforeUnix int64) (giftCreditVote, error) {
	if len(history) == 0 {
		return giftCreditVote{}, errors.New("empty finalized Gift credit history")
	}
	for _, transaction := range history {
		if transaction.IO.In == nil || transaction.IO.In.MsgType != tlb.MsgTypeInternal {
			continue
		}
		message, err := transaction.IO.In.ToCell()
		if err != nil || hex.EncodeToString(message.Hash()) != outputHash {
			continue
		}
		in := transaction.IO.In.AsInternal()
		description, ordinary := transaction.Description.(tlb.TransactionDescriptionOrdinary)
		if !ordinary || in.DstAddr == nil || in.DstAddr.StringRaw() != address || !in.Amount.Nano().IsUint64() || in.Amount.Nano().Uint64() != amount {
			return giftCreditVote{}, errors.New("exact Gift internal message conflicts with the expected output")
		}
		if description.CreditPhase == nil || !description.CreditPhase.Credit.Coins.Nano().IsUint64() || description.CreditPhase.Credit.Coins.Nano().Uint64() != amount {
			return giftCreditVote{AbsenceKnown: true}, nil
		}
		return giftCreditVote{Credited: true, AbsenceKnown: true}, nil
	}
	oldest := history[len(history)-1]
	return giftCreditVote{AbsenceKnown: len(history) < maxGiftHistoryTransactions || oldest.PrevTxLT == 0 || int64(oldest.Now) < notBeforeUnix}, nil
}

func NewAgentGiftReader(chain *Adapter, network *nativev1.NetworkDomain) (*AgentGiftReader, error) {
	if chain == nil || network == nil || chain.network != network.NetworkId || network.GenesisRootHash == "" || network.GenesisFileHash == "" {
		return nil, errors.New("invalid Agent Gift chain reader configuration")
	}
	return &AgentGiftReader{chain: chain, network: proto.Clone(network).(*nativev1.NetworkDomain)}, nil
}

// FinalizedAgentAccount resolves the exact Agent Account state from a strict
// majority at one consensus checkpoint. It does not use indexers or latest
// non-finalized account state.
func (r *AgentGiftReader) FinalizedAgentAccount(ctx context.Context, account string) (agentgift.FinalizedAgentAccount, uint32, error) {
	var zero agentgift.FinalizedAgentAccount
	if r == nil || r.chain == nil || ctx == nil {
		return zero, 0, errors.New("invalid finalized Agent Account request")
	}
	canonical, err := CanonicalAddress(account)
	if err != nil {
		return zero, 0, err
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return zero, 0, err
	}
	decoded, err := r.finalizedAgentAccountAt(ctx, canonical, observation, nodes)
	if err != nil {
		return zero, uint32(observation.observedAt.Unix()), err
	}
	return decoded, uint32(observation.observedAt.Unix()), nil
}

func (r *AgentGiftReader) finalizedAgentAccountAt(ctx context.Context, canonical string, observation consensusObservation, nodes []*rpcNode) (agentgift.FinalizedAgentAccount, error) {
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, canonical, observation.seqno, r.network, agentgift.AgentAccountCodeHash)
	})
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	if !vote.Found {
		return agentgift.FinalizedAgentAccount{}, errors.New("finalized Agent Account is not active")
	}
	globalID, err := agentGiftGlobalID(ctx, nodes, r.chain.quorum, observation.seqno)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	decoded, err := decodeAgentAccountData(vote.Data, canonical, vote.Balance, globalID, uint32(observation.observedAt.Unix()))
	return decoded, err
}

func agentGiftGlobalID(ctx context.Context, nodes []*rpcNode, quorum int, seqno uint64) (int32, error) {
	returnValue, _, err := quorumRead(ctx, nodes, quorum, func(ctx context.Context, node *rpcNode) (int32, error) {
		var result dnsConfigResult
		if err := node.client.Call(ctx, "getConfigParam", struct {
			Param int    `json:"param"`
			Seqno uint64 `json:"seqno"`
		}{19, seqno}, &result); err != nil {
			return 0, err
		}
		if result.Type != "configInfo" || result.Config.Type != "tvm.cell" {
			return 0, errors.New("invalid ConfigParam 19 response")
		}
		raw, err := base64.StdEncoding.DecodeString(result.Config.Bytes)
		if err != nil {
			return 0, err
		}
		root, err := cell.FromBOC(raw)
		if err != nil {
			return 0, err
		}
		slice, err := root.BeginParse()
		if err != nil || slice.BitsLeft() != 32 || slice.RefsNum() != 0 {
			return 0, errors.New("invalid ConfigParam 19 cell")
		}
		value, err := slice.LoadInt(32)
		if err != nil || value == 0 {
			return 0, errors.New("invalid zero TOS global ID")
		}
		return int32(value), nil
	})
	return returnValue, err
}

func decodeAgentAccountData(encoded, account string, balance uint64, globalID int32, chainTime uint32) (agentgift.FinalizedAgentAccount, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	root, err := cell.FromBOC(raw)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	owner, err := s.LoadAddr()
	if err != nil || owner == nil {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account owner")
	}
	controller, err := s.LoadSlice(256)
	if err != nil || len(controller) != ed25519.PublicKeySize {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account controller")
	}
	deploymentID, err := s.LoadSlice(256)
	if err != nil || len(deploymentID) != 32 || bytes.Equal(deploymentID, make([]byte, 32)) {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account deployment ID")
	}
	controllerEpoch, err := s.LoadUInt(64)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account controller epoch")
	}
	seqno, err := s.LoadUInt(32)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	spendDay, err := s.LoadUInt(32)
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	spentToday, err := s.LoadCoins()
	if err != nil || s.BitsLeft() != 0 || s.RefsNum() != 1 {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account state layout")
	}
	policy, err := s.LoadRef()
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	maxPerTx, err := policy.LoadCoins()
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	if maxPerTx > agentgift.MaxAgentAccountActionAtomic {
		return agentgift.FinalizedAgentAccount{}, errors.New("Agent Account max_per_tx exceeds signed-action wire limit")
	}
	dailyLimit, err := policy.LoadCoins()
	if err != nil {
		return agentgift.FinalizedAgentAccount{}, err
	}
	defaultTaskTimeout, err := policy.LoadUInt(64)
	if err != nil || defaultTaskTimeout == 0 {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account task timeout")
	}
	for range 2 {
		present, err := policy.LoadBoolBit()
		if err != nil {
			return agentgift.FinalizedAgentAccount{}, err
		}
		if present {
			if _, err := policy.LoadSlice(256); err != nil {
				return agentgift.FinalizedAgentAccount{}, err
			}
		}
	}
	if policy.BitsLeft() != 0 || policy.RefsNum() != 0 || maxPerTx == 0 || dailyLimit < maxPerTx {
		return agentgift.FinalizedAgentAccount{}, errors.New("invalid Agent Account policy")
	}
	if uint32(uint64(chainTime)/86400) != uint32(spendDay) {
		spentToday = 0
	}
	remaining := uint64(0)
	if spentToday < dailyLimit {
		remaining = dailyLimit - spentToday
	}
	return agentgift.FinalizedAgentAccount{Active: true, Address: account, OwnerAddress: owner.StringRaw(), CodeHash: agentgift.AgentAccountCodeHash, DeploymentID: "sha256:" + hex.EncodeToString(deploymentID), GlobalID: globalID, TVMVersion: agentgift.MinimumAgentAccountTVMVersion, ControllerPublicKey: append(ed25519.PublicKey(nil), controller...), ControllerEpoch: controllerEpoch, Seqno: uint32(seqno), BalanceAtomic: balance, MaxPerTxAtomic: maxPerTx, DailyRemainingAtomic: remaining, DefaultTaskTimeoutSecs: defaultTaskTimeout}, nil
}
