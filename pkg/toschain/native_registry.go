package toschain

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistrypublisher"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type NativeRegistryResolver struct {
	chain     *Adapter
	network   nativeprotocol.NetworkDomain
	locator   *nativeexecution.ObjectLocator
	mu        sync.Mutex
	highWater uint64
}

type nativeAccountVote struct {
	Found           bool   `json:"found"`
	Code            string `json:"code"`
	Data            string `json:"data"`
	LT              string `json:"lt"`
	TransactionHash string `json:"transaction_hash"`
	TransactionTime uint64 `json:"transaction_time"`
	BlockRoot       string `json:"block_root"`
	BlockFile       string `json:"block_file"`
}

type nativeTransactionVote struct {
	LT              uint64 `json:"lt"`
	TransactionHash string `json:"transaction_hash"`
	TransactionTime uint64 `json:"transaction_time"`
	BlockRoot       string `json:"block_root"`
	BlockFile       string `json:"block_file"`
}

func NewNativeRegistryResolver(chain *Adapter, network nativeprotocol.NetworkDomain, locator *nativeexecution.ObjectLocator) (*NativeRegistryResolver, error) {
	if chain == nil || locator == nil || chain.network != network.NetworkID || locator.Network != network {
		return nil, errors.New("invalid Native registry resolver configuration")
	}
	return &NativeRegistryResolver{chain: chain, network: network, locator: locator}, nil
}
func (r *NativeRegistryResolver) CheckReady(ctx context.Context) error {
	_, err := r.Head(ctx)
	return err
}

func (r *NativeRegistryResolver) EnrollmentBinding() string {
	if r == nil || r.chain == nil {
		return ""
	}
	return r.chain.EnrollmentBinding()
}
func (r *NativeRegistryResolver) Head(ctx context.Context) (nativeregistry.FinalizedHead, error) {
	observation, _, err := r.chain.consensus(ctx)
	if err != nil {
		return nativeregistry.FinalizedHead{}, err
	}
	if err := r.advance(observation.seqno); err != nil {
		return nativeregistry.FinalizedHead{}, err
	}
	return nativeregistry.FinalizedHead{Network: r.network, Checkpoint: observation.seqno, BlockUnixSeconds: uint64(observation.observedAt.Unix())}, nil
}
func (r *NativeRegistryResolver) advance(checkpoint uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if checkpoint == 0 || checkpoint < r.highWater {
		return errors.New("Native registry finalized checkpoint regressed")
	}
	r.highWater = checkpoint
	return nil
}

func (r *NativeRegistryResolver) ResolveAction(ctx context.Context, actionID string) (nativeregistry.Result, error) {
	anchor, err := r.locator.LocateActionAnchor(actionID)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	vote, checkpoint, _, err := r.readAccount(ctx, anchor.Address)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	if !vote.Found {
		return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	decoded, err := nativeexecution.DecodeActionAnchorData(data, actionID)
	if err != nil {
		if nativeexecution.IsPristineActionAnchorData(data, actionID) {
			return nativeregistry.Result{}, nativeregistry.ErrCanonicalPending
		}
		return nativeregistry.Result{}, err
	}
	if !decoded.Completed {
		return nativeregistry.Result{}, nativeregistry.ErrCanonicalPending
	}
	expectedContract, err := r.locator.Locate(decoded.Decoded.Action)
	if err != nil || decoded.Decoded.Contract.Network != expectedContract.Network ||
		decoded.Decoded.Contract.Address != expectedContract.Address ||
		decoded.Decoded.Contract.AllowedCodeHash != expectedContract.AllowedCodeHash ||
		expectedContract.ActionAnchorAddress != anchor.Address {
		return nativeregistry.Result{}, errors.New("finalized Native action contract identity does not match the pinned locator")
	}
	state := decoded.Decoded.Next
	stateDigest, err := nativeprotocol.StateDigest(state)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	event := nativeprotocol.RegistryEvent{Version: nativeprotocol.Version, Kind: decoded.Decoded.Action.Kind, Network: r.network, ActionDigest: actionID, AgentID: decoded.Decoded.Action.AgentID, CapabilityID: decoded.Decoded.Action.CapabilityID, CapabilityVersion: decoded.Decoded.Action.CapabilityVersion, Generation: decoded.Decoded.Action.Generation, Sequence: decoded.Decoded.Action.Sequence, PreviousStateDigest: decoded.Decoded.Action.PreviousStateDigest, StateDigest: stateDigest}
	eventDigest, err := nativeprotocol.EventDigest(event)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	transition, transitionCheckpoint, err := r.readActionCompletionTransaction(ctx, anchor.Address, decoded.CompletionLogicalTime, actionID)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	if transition.TransactionTime != decoded.CompletionUnixSeconds {
		return nativeregistry.Result{}, errors.New("Native completion time does not match its canonical transaction")
	}
	if err := nativeexecution.VerifyAnchorSignatures(decoded, anchor.Address); err != nil {
		return nativeregistry.Result{}, fmt.Errorf("verify finalized Native authorization: %w", err)
	}
	if err := r.validateDecodedTransition(ctx, decoded, stateDigest, transition.TransactionTime); err != nil {
		return nativeregistry.Result{}, err
	}
	lt := transition.LT
	hash, err := hex.DecodeString(strings.TrimPrefix(transition.TransactionHash, "sha256:"))
	if err != nil || len(hash) != 32 {
		return nativeregistry.Result{}, errors.New("invalid Native completion transaction hash")
	}
	if transitionCheckpoint > checkpoint {
		checkpoint = transitionCheckpoint
	}
	wc, account, err := parseRawAddress(anchor.Address)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	inclusion, err := codec.Digest("tos.native.registry-inclusion.v1", struct {
		Account                               string `json:"account"`
		LT                                    uint64 `json:"logical_time"`
		TransactionHash, BlockRoot, BlockFile string
	}{anchor.Address, lt, transition.TransactionHash, transition.BlockRoot, transition.BlockFile})
	if err != nil {
		return nativeregistry.Result{}, err
	}
	observation := nativeprotocol.EventObservation{Version: nativeprotocol.Version, Network: r.network, EventDigest: eventDigest, Reference: nativeprotocol.ChainReference{Workchain: wc, Account: anchor.Address, LogicalTime: lt, TransactionHash: transition.TransactionHash, ContractCodeHash: anchor.AllowedCodeHash}, FinalizedCheckpoint: checkpoint, FinalizedRootHash: transition.BlockRoot, FinalizedFileHash: transition.BlockFile, BlockUnixSeconds: transition.TransactionTime, InclusionProofDigest: inclusion}
	if account != strings.TrimPrefix(anchor.Address, fmt.Sprintf("%d:", wc)) {
		return nativeregistry.Result{}, errors.New("Native Anchor account mismatch")
	}
	if err := nativeprotocol.ValidateEventForActionAndState(decoded.Decoded.Action, state, event); err != nil {
		return nativeregistry.Result{}, err
	}
	if err := observation.Validate(); err != nil {
		return nativeregistry.Result{}, err
	}
	return nativeregistry.Result{ActionID: actionID, Action: decoded.Decoded.Action, Event: event, State: state, Observation: observation}, nil
}

// validateDecodedTransition independently replays the portable state machine
// from the immutable predecessor embedded in the finalized Action Anchor. The
// contract code hash proves what TOS executed; this second implementation
// proves that the emitted state also matches the frozen cross-language model.
func (r *NativeRegistryResolver) validateDecodedTransition(ctx context.Context, anchor nativeexecution.DecodedAnchor, expectedStateDigest string, completionTime uint64) error {
	decoded := anchor.Decoded
	authorityDigest := decoded.Action.PolicyDigest
	if decoded.Action.Kind == nativeprotocol.ActionRegisterAgent {
		authorityDigest = ""
	}
	derived, err := nativeprotocol.DeriveNextState(decoded.Previous, decoded.Action, authorityDigest, completionTime)
	if err != nil {
		return fmt.Errorf("replay finalized Native transition: %w", err)
	}
	derivedDigest, err := nativeprotocol.StateDigest(derived)
	if err != nil || derivedDigest != expectedStateDigest {
		return errors.New("finalized Native state differs from deterministic transition replay")
	}
	policyDigest, err := nativeprotocol.ControllerPolicyDigest(decoded.AuthorityPolicy)
	if err != nil || policyDigest != decoded.Action.PolicyDigest {
		return errors.New("finalized Native authority policy does not match the action")
	}
	if decoded.Action.CapabilityID == "" {
		authorityStateDigest := ""
		if anchor.AuthorityState != nil {
			authorityStateDigest, _ = nativeprotocol.StateDigest(*anchor.AuthorityState)
		}
		if authorityStateDigest != expectedStateDigest || anchor.NewOwnerState != nil {
			return errors.New("finalized Native Agent completion authority evidence is inconsistent")
		}
		if decoded.Action.Kind != nativeprotocol.ActionRegisterAgent {
			if decoded.Previous == nil || decoded.Previous.CurrentPolicyDigest != policyDigest || decoded.Previous.Tombstoned {
				return errors.New("finalized Native action was not authorized by its immediate canonical policy")
			}
			canonicalPolicy, err := nativeprotocol.DecodeControllerPolicy(decoded.Previous.CurrentPolicyCBORBase64, decoded.Previous.CurrentPolicyDigest)
			canonicalDigest, digestErr := nativeprotocol.ControllerPolicyDigest(canonicalPolicy)
			if err != nil || digestErr != nil || canonicalDigest != policyDigest {
				return errors.New("finalized Native action authority policy differs from its predecessor")
			}
		}
	} else {
		if err := r.validateCanonicalAuthorityState(ctx, decoded.Action.AgentID, policyDigest, anchor.AuthorityState); err != nil {
			return errors.New("finalized Native capability action was not authorized by its canonical owner policy")
		}
		canonicalPolicy, err := nativeprotocol.DecodeControllerPolicy(anchor.AuthorityState.CurrentPolicyCBORBase64, anchor.AuthorityState.CurrentPolicyDigest)
		canonicalDigest, digestErr := nativeprotocol.ControllerPolicyDigest(canonicalPolicy)
		if err != nil || digestErr != nil || canonicalDigest != policyDigest {
			return errors.New("finalized Native capability authority policy differs from canonical owner state")
		}
	}
	if decoded.Action.Kind == nativeprotocol.ActionTransferCapability {
		if decoded.NewOwnerPolicy == nil {
			return errors.New("finalized Native transfer is missing the new-owner policy")
		}
		var payload nativeprotocol.TransferCapabilityPayload
		if err := nativeprotocol.DecodePayload(decoded.Action, &payload); err != nil {
			return err
		}
		newDigest, err := nativeprotocol.ControllerPolicyDigest(*decoded.NewOwnerPolicy)
		if err != nil || newDigest != payload.NewOwnerPolicyDigest {
			return errors.New("finalized Native transfer new-owner policy mismatch")
		}
		if err := r.validateCanonicalAuthorityState(ctx, payload.NewOwnerAgentID, newDigest, anchor.NewOwnerState); err != nil {
			return errors.New("finalized Native transfer was not accepted by the canonical new-owner policy")
		}
	} else if anchor.NewOwnerState != nil {
		return errors.New("non-transfer Native completion contains new-owner authority evidence")
	}
	if decoded.Action.Kind != nativeprotocol.ActionRecoverAgent {
		return nil
	}
	if decoded.Previous == nil || decoded.Previous.PendingRecovery.InitiationActionDigest == "" {
		return errors.New("finalized Native recovery has no immediate initiation predecessor")
	}
	initiation, err := r.ResolveAction(ctx, decoded.Previous.PendingRecovery.InitiationActionDigest)
	if err != nil {
		return fmt.Errorf("resolve finalized Native recovery initiation: %w", err)
	}
	initiationAnchor, err := r.resolveDecodedAnchor(ctx, initiation.ActionID)
	if err != nil || initiationAnchor.Decoded.Previous == nil {
		return errors.New("finalized Native recovery initiation predecessor is unavailable")
	}
	return nativeprotocol.ValidateRecoveryTransition(*initiationAnchor.Decoded.Previous, *decoded.Previous, decoded.Action,
		initiation.Action, initiation.Event, initiation.Observation, completionTime)
}

func (r *NativeRegistryResolver) validateCanonicalAuthorityState(ctx context.Context, agentID, policyDigest string, state *nativeprotocol.RegistryState) error {
	if state == nil || state.ObjectKind != "agent" || state.AgentID != agentID || state.Tombstoned || state.CurrentPolicyDigest != policyDigest {
		return errors.New("invalid Native completion authority state")
	}
	digest, err := nativeprotocol.StateDigest(*state)
	if err != nil {
		return err
	}
	canonical, err := r.ResolveState(ctx, agentID, digest)
	if err != nil {
		return err
	}
	canonicalDigest, err := nativeprotocol.StateDigest(canonical.State)
	if err != nil || canonicalDigest != digest {
		return errors.New("Native completion authority state is not canonical")
	}
	return nil
}

func (r *NativeRegistryResolver) ResolveState(ctx context.Context, objectID, expectedDigest string) (nativeregistry.Result, error) {
	identity, err := r.locator.LocateObject(objectID)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	vote, _, _, err := r.readAccount(ctx, identity.Address)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	if !vote.Found {
		return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	state, found, err := nativeexecution.DecodeObjectStateData(data, objectID)
	if err != nil {
		return nativeregistry.Result{}, err
	}
	if !found {
		return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
	}
	for steps := 0; steps < 65536; steps++ {
		digest, err := nativeprotocol.StateDigest(state)
		if err != nil {
			return nativeregistry.Result{}, err
		}
		result, err := r.ResolveAction(ctx, state.LastActionDigest)
		if err != nil {
			return nativeregistry.Result{}, fmt.Errorf("resolve Native state action %s: %w", state.LastActionDigest, err)
		}
		resolvedDigest, digestErr := nativeprotocol.StateDigest(result.State)
		if digestErr != nil || resolvedDigest != digest {
			return nativeregistry.Result{}, errors.New("Native object state does not match its canonical Action Anchor")
		}
		if expectedDigest == "" || digest == expectedDigest {
			return result, nil
		}
		anchor, err := r.resolveDecodedAnchor(ctx, state.LastActionDigest)
		if err != nil {
			return nativeregistry.Result{}, err
		}
		if anchor.Decoded.Previous == nil {
			return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
		}
		state = *anchor.Decoded.Previous
	}
	return nativeregistry.Result{}, errors.New("Native predecessor chain exceeds safety bound")
}

func (r *NativeRegistryResolver) resolveDecodedAnchor(ctx context.Context, actionID string) (nativeexecution.DecodedAnchor, error) {
	anchor, err := r.locator.LocateActionAnchor(actionID)
	if err != nil {
		return nativeexecution.DecodedAnchor{}, err
	}
	vote, _, _, err := r.readAccount(ctx, anchor.Address)
	if err != nil || !vote.Found {
		if err == nil {
			err = nativeregistry.ErrCanonicalNotFound
		}
		return nativeexecution.DecodedAnchor{}, err
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nativeexecution.DecodedAnchor{}, err
	}
	return nativeexecution.DecodeActionAnchorData(data, actionID)
}

func (r *NativeRegistryResolver) ObserveActionAnchor(ctx context.Context, s nativeregistry.Submission, identity nativeexecution.ContractIdentity) (nativeregistrypublisher.AnchorObservation, error) {
	id, _, err := nativeregistry.ValidateSubmission(s)
	if err != nil {
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	expected, err := r.locator.LocateActionAnchor(id)
	if err != nil || expected.Address != identity.Address {
		return nativeregistrypublisher.AnchorObservation{}, errors.New("Native Anchor selector mismatch")
	}
	vote, _, _, err := r.readAccount(ctx, identity.Address)
	if err != nil {
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	if !vote.Found {
		return nativeregistrypublisher.AnchorObservation{Found: false}, nil
	}
	data, err := decodeCellBOC(vote.Data)
	if err != nil {
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	anchor, err := nativeexecution.DecodeActionAnchorData(data, id)
	if err != nil {
		if nativeexecution.IsPristineActionAnchorData(data, id) {
			lt, hash, tupleErr := transactionTuple(vote)
			if tupleErr != nil {
				return nativeregistrypublisher.AnchorObservation{}, tupleErr
			}
			reference, formatErr := FormatTransactionReference(identity.Address, lt, hash)
			if formatErr != nil {
				return nativeregistrypublisher.AnchorObservation{}, formatErr
			}
			return nativeregistrypublisher.AnchorObservation{Found: true, Completed: false, TransactionReference: reference}, nil
		}
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	lt, hash, err := transactionTuple(vote)
	if err != nil {
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	reference, err := FormatTransactionReference(identity.Address, lt, hash)
	if err != nil {
		return nativeregistrypublisher.AnchorObservation{}, err
	}
	return nativeregistrypublisher.AnchorObservation{Found: true, Completed: anchor.Completed, TransactionReference: reference}, nil
}

func (r *NativeRegistryResolver) readAccount(ctx context.Context, address string) (nativeAccountVote, uint64, uint64, error) {
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nativeAccountVote{}, 0, 0, err
	}
	if err = r.advance(observation.seqno); err != nil {
		return nativeAccountVote{}, 0, 0, err
	}
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeAccountVote, error) {
		return readNativeAccountAt(ctx, node, address, observation.seqno, r.network, r.locator.CodeHash)
	})
	return vote, observation.seqno, uint64(observation.observedAt.Unix()), err
}

// readActionCompletionTransaction resolves the immutable Action completion by
// the logical time committed in Anchor state. It walks the complete account
// chain back to that boundary; a bounded recent-history miss is never treated
// as authoritative absence.
func (r *NativeRegistryResolver) readActionCompletionTransaction(ctx context.Context, address string, targetLT uint64, actionID string) (nativeTransactionVote, uint64, error) {
	if targetLT == 0 {
		return nativeTransactionVote{}, 0, errors.New("Native completion logical time is missing")
	}
	observation, nodes, err := r.chain.consensus(ctx)
	if err != nil {
		return nativeTransactionVote{}, 0, err
	}
	if err = r.advance(observation.seqno); err != nil {
		return nativeTransactionVote{}, 0, err
	}
	vote, _, err := quorumRead(ctx, nodes, r.chain.quorum, func(ctx context.Context, node *rpcNode) (nativeTransactionVote, error) {
		return findNativeCompletionTransaction(ctx, node, address, targetLT, actionID, observation.seqno, r.network, r.locator.CodeHash)
	})
	return vote, observation.seqno, err
}

func findNativeCompletionTransaction(ctx context.Context, node *rpcNode, address string, targetLT uint64, actionID string, seqno uint64, network nativeprotocol.NetworkDomain, allowedCodeHash string) (nativeTransactionVote, error) {
	account, err := readNativeAccountAt(ctx, node, address, seqno, network, allowedCodeHash)
	if err != nil || !account.Found {
		if err == nil {
			err = errors.New("Native Action Anchor disappeared")
		}
		return nativeTransactionVote{}, err
	}
	cursorLT, cursorHash, err := transactionTuple(account)
	if err != nil {
		return nativeTransactionVote{}, err
	}
	for cursorLT >= targetLT {
		if err := ctx.Err(); err != nil {
			return nativeTransactionVote{}, err
		}
		var values []rawTransaction
		if err := node.client.Call(ctx, "getTransactions", struct {
			Address  string `json:"address"`
			Limit    int    `json:"limit"`
			LT, Hash string
		}{address, 100, strconv.FormatUint(cursorLT, 10), base64.StdEncoding.EncodeToString(cursorHash)}, &values); err != nil {
			return nativeTransactionVote{}, err
		}
		if len(values) == 0 {
			return nativeTransactionVote{}, errors.New("Native completion transaction history is incomplete")
		}
		var previousLT uint64
		var previousHash []byte
		for _, raw := range values {
			tx, txHash, err := decodeNativeTransaction(raw, address)
			if err != nil {
				return nativeTransactionVote{}, err
			}
			if tx.LT == targetLT {
				if err := verifyNativeCompletionMessage(tx, address, actionID); err != nil {
					return nativeTransactionVote{}, err
				}
				root, err := decodeBase64Hash(raw.BlockID.RootHash)
				if err != nil {
					return nativeTransactionVote{}, err
				}
				file, err := decodeBase64Hash(raw.BlockID.FileHash)
				if err != nil {
					return nativeTransactionVote{}, err
				}
				return nativeTransactionVote{LT: tx.LT, TransactionHash: "sha256:" + hex.EncodeToString(txHash), TransactionTime: uint64(tx.Now), BlockRoot: "sha256:" + hex.EncodeToString(root), BlockFile: "sha256:" + hex.EncodeToString(file)}, nil
			}
			if tx.LT < targetLT {
				return nativeTransactionVote{}, errors.New("Native completion logical time is absent from complete account history")
			}
			previousLT, previousHash = tx.PrevTxLT, append(previousHash[:0], tx.PrevTxHash...)
		}
		if previousLT == 0 || len(previousHash) != 32 || previousLT >= cursorLT {
			return nativeTransactionVote{}, errors.New("Native completion transaction history did not make progress")
		}
		cursorLT, cursorHash = previousLT, previousHash
	}
	return nativeTransactionVote{}, errors.New("Native completion logical time is absent from complete account history")
}

func decodeNativeTransaction(raw rawTransaction, address string) (*tlb.Transaction, []byte, error) {
	if raw.Type != "raw.transaction" || raw.BlockID.Type != "tos.blockIdExt" || raw.BlockID.Seqno == 0 || raw.TransactionID.Type != "internal.transactionId" || raw.Data == "" {
		return nil, nil, errors.New("invalid Native historical transaction response")
	}
	hash, err := base64.StdEncoding.DecodeString(raw.TransactionID.Hash)
	if err != nil || len(hash) != 32 {
		return nil, nil, errors.New("invalid Native historical transaction hash")
	}
	boc, err := base64.StdEncoding.DecodeString(raw.Data)
	if err != nil {
		return nil, nil, errors.New("invalid Native historical transaction BOC")
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(root.Hash(), hash) {
		return nil, nil, errors.New("Native historical transaction BOC hash mismatch")
	}
	var tx tlb.Transaction
	if err := tlb.LoadFromCell(&tx, root.BeginParse()); err != nil {
		return nil, nil, err
	}
	lt, err := strconv.ParseUint(raw.TransactionID.LT, 10, 64)
	_, account, addressErr := parseRawAddress(address)
	if err != nil || addressErr != nil || tx.LT != lt || tx.Now == 0 || raw.Utime != tx.Now || !bytes.Equal(tx.AccountAddr, mustDecodeHex(account)) || !strings.EqualFold(raw.Account, account) {
		return nil, nil, errors.New("Native historical transaction tuple mismatch")
	}
	return &tx, hash, nil
}

func verifyNativeCompletionMessage(tx *tlb.Transaction, address, actionID string) error {
	if err := verifySuccessfulOrdinaryTransaction(tx); err != nil {
		return err
	}
	if tx.IO.In == nil || tx.IO.In.MsgType != tlb.MsgTypeInternal {
		return errors.New("Native completion transaction is not an internal call")
	}
	message := tx.IO.In.AsInternal()
	if message == nil || message.Bounced || message.DstAddr == nil || message.DstAddr.StringRaw() != address || message.Body == nil {
		return errors.New("Native completion inbound message is invalid")
	}
	body := message.Body.BeginParse()
	opcode, err := body.LoadUInt(32)
	if err != nil || opcode != 0x4e520003 {
		return errors.New("Native completion opcode mismatch")
	}
	if _, err = body.LoadUInt(64); err != nil {
		return errors.New("Native completion query ID is missing")
	}
	digest, err := body.LoadSlice(256)
	expected, decodeErr := hex.DecodeString(strings.TrimPrefix(actionID, "sha256:"))
	if err != nil || decodeErr != nil || !bytes.Equal(digest, expected) {
		return errors.New("Native completion Action ID mismatch")
	}
	return nil
}

func mustDecodeHex(value string) []byte {
	decoded, _ := hex.DecodeString(value)
	return decoded
}

func readNativeAccountAt(ctx context.Context, node *rpcNode, address string, seqno uint64, network nativeprotocol.NetworkDomain, allowedCodeHash string) (nativeAccountVote, error) {
	var master struct {
		Type          string  `json:"@type"`
		Last          blockID `json:"last"`
		StateRootHash string  `json:"state_root_hash"`
		Init          blockID `json:"init"`
	}
	if err := node.client.Call(ctx, "getMasterchainInfo", struct{}{}, &master); err != nil {
		return nativeAccountVote{}, err
	}
	if master.Type != "blocks.masterchainInfo" || master.Last.Seqno < seqno {
		return nativeAccountVote{}, errors.New("Native endpoint masterchain response is stale or malformed")
	}
	genesisRoot, err := decodeBase64Hash(master.Init.RootHash)
	if err != nil || "sha256:"+hex.EncodeToString(genesisRoot) != network.GenesisRootHash {
		return nativeAccountVote{}, errors.New("Native endpoint genesis root mismatch")
	}
	genesisFile, err := decodeBase64Hash(master.Init.FileHash)
	if err != nil || "sha256:"+hex.EncodeToString(genesisFile) != network.GenesisFileHash {
		return nativeAccountVote{}, errors.New("Native endpoint genesis file mismatch")
	}
	var info accountInformation
	if err := node.client.Call(ctx, "getAddressInformation", struct {
		Address string `json:"address"`
		Seqno   uint64 `json:"seqno"`
	}{address, seqno}, &info); err != nil {
		return nativeAccountVote{}, err
	}
	if info.BlockID.Type != "tos.blockIdExt" || info.BlockID.Workchain != -1 || info.BlockID.Seqno != seqno {
		return nativeAccountVote{}, errors.New("Native account response is not finalized")
	}
	root, err := decodeBase64Hash(info.BlockID.RootHash)
	if err != nil {
		return nativeAccountVote{}, err
	}
	file, err := decodeBase64Hash(info.BlockID.FileHash)
	if err != nil {
		return nativeAccountVote{}, err
	}
	vote := nativeAccountVote{BlockRoot: "sha256:" + hex.EncodeToString(root), BlockFile: "sha256:" + hex.EncodeToString(file)}
	if info.State != "active" {
		return vote, nil
	}
	if info.Code == "" || info.Data == "" {
		return nativeAccountVote{}, errors.New("Native account has incomplete state")
	}
	code, err := decodeCellBOC(info.Code)
	if err != nil || "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()) != allowedCodeHash {
		return nativeAccountVote{}, errors.New("Native account code hash mismatch")
	}
	vote.Found = true
	vote.Code = info.Code
	vote.Data = info.Data
	vote.LT = info.LastTransactionID.LT
	vote.TransactionHash = info.LastTransactionID.Hash
	transactionTime, err := verifyNativeLastTransactionTuple(ctx, node, address, info.LastTransactionID)
	if err != nil {
		return nativeAccountVote{}, err
	}
	vote.TransactionTime = transactionTime
	return vote, nil
}

// verifyNativeLastTransactionTuple verifies the RPC tuple and BOC hash. The
// transaction is an observation anchor for the account state at the requested
// finalized checkpoint, not a self-attested claim that it caused the stored
// registry transition. Registry success is derived from the independently
// included account data and its canonical Action Anchor.
func verifyNativeLastTransactionTuple(ctx context.Context, node *rpcNode, address string, id transactionID) (uint64, error) {
	if id.Type != "internal.transactionId" || id.LT == "" || id.Hash == "" {
		return 0, errors.New("Native account last transaction is missing")
	}
	var values []rawTransaction
	if err := node.client.Call(ctx, "getTransactions", struct {
		Address  string `json:"address"`
		Limit    int    `json:"limit"`
		LT, Hash string
	}{address, 1, id.LT, id.Hash}, &values); err != nil {
		return 0, err
	}
	if len(values) != 1 || values[0].Type != "raw.transaction" || values[0].Data == "" || values[0].TransactionID != id {
		return 0, errors.New("Native exact transaction query mismatch")
	}
	rawHash, err := base64.StdEncoding.DecodeString(id.Hash)
	if err != nil || len(rawHash) != 32 {
		return 0, errors.New("invalid Native transaction hash")
	}
	boc, err := base64.StdEncoding.DecodeString(values[0].Data)
	if err != nil {
		return 0, err
	}
	root, err := cell.FromBOC(boc)
	if err != nil || !bytes.Equal(root.Hash(), rawHash) {
		return 0, errors.New("Native transaction BOC hash mismatch")
	}
	var transaction tlb.Transaction
	if err := tlb.LoadFromCell(&transaction, root.BeginParse()); err != nil {
		return 0, err
	}
	lt, err := strconv.ParseUint(id.LT, 10, 64)
	if err != nil || transaction.LT != lt || !strings.EqualFold(values[0].Account, strings.Split(address, ":")[1]) {
		return 0, errors.New("Native transaction tuple mismatch")
	}
	if transaction.Now == 0 {
		return 0, errors.New("Native transaction time is missing")
	}
	return uint64(transaction.Now), nil
}

func decodeCellBOC(value string) (*cell.Cell, error) {
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	return cell.FromBOC(raw)
}
func transactionTuple(v nativeAccountVote) (uint64, []byte, error) {
	lt, err := strconv.ParseUint(v.LT, 10, 64)
	if err != nil || lt == 0 {
		return 0, nil, errors.New("invalid Native transaction logical time")
	}
	hash, err := base64.StdEncoding.DecodeString(v.TransactionHash)
	if err != nil || len(hash) != 32 || bytes.Equal(hash, make([]byte, 32)) {
		return 0, nil, errors.New("invalid Native transaction hash")
	}
	return lt, hash, nil
}
func parseRawAddress(value string) (int32, string, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 2 {
		return 0, "", errors.New("invalid Native address")
	}
	wc, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil || len(parts[1]) != 64 {
		return 0, "", errors.New("invalid Native address")
	}
	return int32(wc), parts[1], nil
}
