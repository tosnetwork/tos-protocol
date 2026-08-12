package economic

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const (
	DefaultTaskEscrowCallTimeout    = 30 * time.Second
	DefaultTaskEscrowActionLifetime = 5 * time.Minute
	DefaultTaskEscrowReviewPeriod   = time.Hour
	maxTaskEscrowCallTimeout        = 2 * time.Minute
	maxTaskEscrowActionLifetime     = 30 * time.Minute
	maxTaskEscrowReviewPeriod       = 30 * 24 * time.Hour
)

type TaskEscrowConfig struct {
	Observer          chain.TaskEscrowObserver
	Publisher         chain.TaskEscrowActionPublisher
	Network           string
	AllowedCodeHashes []string
	Verifier          string
	FundingOverhead   uint64
	ReviewPeriod      time.Duration
	CallTimeout       time.Duration
	ActionLifetime    time.Duration
	Now               func() time.Time
}

type TaskEscrowDriver struct {
	observer          chain.TaskEscrowObserver
	publisher         chain.TaskEscrowActionPublisher
	network           string
	allowedCodeHashes []string
	verifier          string
	fundingOverhead   uint64
	reviewPeriod      uint32
	callTimeout       time.Duration
	actionLifetime    time.Duration
	now               func() time.Time
	closeOnce         sync.Once
	closeErr          error
}

func NewTaskEscrowDriver(config TaskEscrowConfig) (*TaskEscrowDriver, error) {
	if config.Observer == nil || config.Publisher == nil || strings.TrimSpace(config.Network) == "" {
		return nil, errors.New("task escrow observer, publisher, and network are required")
	}
	verifier, err := toschain.CanonicalAddress(config.Verifier)
	if err != nil {
		return nil, fmt.Errorf("invalid task escrow verifier: %w", err)
	}
	if config.FundingOverhead == 0 {
		return nil, errors.New("task escrow funding overhead is required")
	}
	if config.ReviewPeriod == 0 {
		config.ReviewPeriod = DefaultTaskEscrowReviewPeriod
	}
	if config.ReviewPeriod < time.Hour || config.ReviewPeriod > maxTaskEscrowReviewPeriod ||
		config.ReviewPeriod%time.Second != 0 {
		return nil, errors.New("task escrow review period is outside bounds")
	}
	if config.CallTimeout == 0 {
		config.CallTimeout = DefaultTaskEscrowCallTimeout
	}
	if config.CallTimeout <= 0 || config.CallTimeout > maxTaskEscrowCallTimeout {
		return nil, errors.New("task escrow call timeout is outside bounds")
	}
	if config.ActionLifetime == 0 {
		config.ActionLifetime = DefaultTaskEscrowActionLifetime
	}
	if config.ActionLifetime <= 0 || config.ActionLifetime > maxTaskEscrowActionLifetime {
		return nil, errors.New("task escrow action lifetime is outside bounds")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if _, err := validateAllowedCodeHashes(config.AllowedCodeHashes); err != nil {
		return nil, err
	}
	return &TaskEscrowDriver{
		observer: config.Observer, publisher: config.Publisher,
		network: config.Network, allowedCodeHashes: append([]string(nil), config.AllowedCodeHashes...),
		verifier: verifier, fundingOverhead: config.FundingOverhead,
		reviewPeriod: uint32(config.ReviewPeriod / time.Second),
		callTimeout:  config.CallTimeout, actionLifetime: config.ActionLifetime,
		now: config.Now,
	}, nil
}

func (d *TaskEscrowDriver) Network() string {
	if d == nil {
		return ""
	}
	return d.network
}

func (d *TaskEscrowDriver) Supports(mode TrustMode) bool {
	return d != nil && mode == TrustModeVerified
}

func (d *TaskEscrowDriver) CheckReady(ctx context.Context) error {
	if d == nil || d.observer == nil || d.publisher == nil || d.now == nil {
		return errors.New("invalid task escrow driver")
	}
	callContext, cancel, err := d.callContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if _, _, err := d.observer.CheckChainReady(callContext, d.now().UTC()); err != nil {
		return fmt.Errorf("TOS task escrow chain is not ready: %w", err)
	}
	if err := d.publisher.CheckReady(callContext); err != nil {
		return fmt.Errorf("TOS task escrow publisher is not ready: %w", err)
	}
	return nil
}

func (d *TaskEscrowDriver) ReserveEscrow(
	ctx context.Context,
	request ReserveEscrowRequest,
) (Result, error) {
	action, err := d.reservationAction(request)
	if err != nil {
		return Result{}, err
	}
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: action.Creator, ExpectedKind: chain.TaskEscrowActionDeploy,
		ExpectedInboundMinimum: action.FundingNanoTOS,
	})
	if err != nil {
		return Result{}, err
	}
	if err := d.validateObservedState(transition.State, transition.State.ContractAddress); err != nil {
		return Result{}, err
	}
	if err := validateReservedState(transition.State, action); err != nil {
		return Result{}, err
	}
	contractRef, err := toschain.FormatTaskEscrowReference(transition.State.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	return Result{
		State: transition.State, ContractReference: contractRef,
		TransitionReference: transition.TransactionReference, ActionID: action.ActionID,
	}, nil
}

func (d *TaskEscrowDriver) ResolveEscrow(ctx context.Context, request ReserveEscrowRequest) (Result, bool, error) {
	action, err := d.reservationAction(request)
	if err != nil {
		return Result{}, false, err
	}
	callContext, cancel, err := d.callContext(ctx)
	if err != nil {
		return Result{}, false, err
	}
	defer cancel()
	minimum, _, err := d.observer.CheckChainReady(callContext, d.now().UTC())
	if err != nil {
		return Result{}, false, err
	}
	receipt, found, err := d.publisher.Resolve(callContext, action)
	if err != nil || !found {
		return Result{}, found, err
	}
	transition, err := d.observeReceipt(callContext, action, receipt, minimum, chain.TaskEscrowTransitionReference{ExpectedSender: action.Creator, ExpectedKind: chain.TaskEscrowActionDeploy, ExpectedInboundMinimum: action.FundingNanoTOS})
	if err != nil {
		return Result{}, false, err
	}
	if err := d.validateObservedState(transition.State, transition.State.ContractAddress); err != nil {
		return Result{}, false, err
	}
	if transition.State.Status == chain.TaskEscrowStatusOpen {
		if err := validateReservedState(transition.State, action); err != nil {
			return Result{}, false, err
		}
	} else if transition.State.Status == chain.TaskEscrowStatusSettled {
		if err := validateSettledReservationState(transition.State, action); err != nil {
			return Result{}, false, err
		}
	} else if transition.State.Status != chain.TaskEscrowStatusCancelled && transition.State.Status != chain.TaskEscrowStatusExpired && transition.State.Status != chain.TaskEscrowStatusRejected {
		return Result{}, false, errors.New("TaskEscrow is not in a recoverable reservation/release state")
	}
	contractRef, err := toschain.FormatTaskEscrowReference(transition.State.ContractAddress)
	if err != nil {
		return Result{}, false, err
	}
	return Result{State: transition.State, ContractReference: contractRef, TransitionReference: transition.TransactionReference, ActionID: action.ActionID}, true, nil
}

func (d *TaskEscrowDriver) reservationAction(request ReserveEscrowRequest) (chain.TaskEscrowAction, error) {
	if d == nil {
		return chain.TaskEscrowAction{}, errors.New("invalid task escrow driver")
	}
	creator, err := toschain.CanonicalAddress(request.Creator)
	if err != nil {
		return chain.TaskEscrowAction{}, fmt.Errorf("invalid escrow creator: %w", err)
	}
	agent, err := toschain.CanonicalAddress(request.Agent)
	if err != nil {
		return chain.TaskEscrowAction{}, fmt.Errorf("invalid escrow agent: %w", err)
	}
	verifier := d.verifier
	if strings.TrimSpace(request.Verifier) != "" {
		verifier, err = toschain.CanonicalAddress(request.Verifier)
		if err != nil {
			return chain.TaskEscrowAction{}, fmt.Errorf("invalid escrow verifier: %w", err)
		}
	}
	if creator == agent || verifier == creator || verifier == agent {
		return chain.TaskEscrowAction{}, errors.New("Task Escrow creator, agent, and verifier must be distinct")
	}
	if strings.TrimSpace(request.EscrowID) == "" || request.BudgetNanoTOS == 0 || request.DeadlineUnix <= uint64(d.now().Unix()) || !validDigest(request.PolicyHash) || !validDigest(request.PermissionHash) {
		return chain.TaskEscrowAction{}, errors.New("invalid task escrow reservation")
	}
	funding, ok := addNoOverflow(request.BudgetNanoTOS, d.fundingOverhead)
	if !ok {
		return chain.TaskEscrowAction{}, errors.New("task escrow funding overflows uint64")
	}
	action := chain.TaskEscrowAction{Version: chain.TaskEscrowActionVersion, Network: d.network, Kind: chain.TaskEscrowActionDeploy, EscrowID: request.EscrowID, Creator: creator, Agent: agent, Verifier: verifier, BudgetNanoTOS: request.BudgetNanoTOS, FundingNanoTOS: funding, DeadlineUnix: request.DeadlineUnix, ReviewPeriod: d.reviewPeriod, PolicyHash: request.PolicyHash, PermissionHash: request.PermissionHash}
	if err := d.finishAction(&action); err != nil {
		return chain.TaskEscrowAction{}, err
	}
	return action, nil
}

func (d *TaskEscrowDriver) AcceptEscrow(
	ctx context.Context,
	request AcceptEscrowRequest,
) (Result, error) {
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	if request.EscrowID == "" {
		return Result{}, errors.New("task escrow acceptance binding mismatch")
	}
	if request.ExpectedAgent != "" {
		expectedAgent, canonicalErr := toschain.CanonicalAddress(request.ExpectedAgent)
		if canonicalErr != nil || state.Agent != expectedAgent {
			return Result{}, errors.New("task escrow acceptance binding mismatch")
		}
	}
	switch state.Status {
	case chain.TaskEscrowStatusAccepted, chain.TaskEscrowStatusResultSubmitted,
		chain.TaskEscrowStatusSettled, chain.TaskEscrowStatusDisputed:
		return stateResult(state), nil
	case chain.TaskEscrowStatusOpen:
	default:
		return Result{}, errors.New("task escrow is not open for acceptance")
	}
	action, err := d.operationAction(state, request.EscrowID, state.BudgetNanoTOS, chain.TaskEscrowActionAccept, "", "", "", 0)
	if err != nil {
		return Result{}, err
	}
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Agent, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusAccepted {
		return Result{}, errors.New("task escrow acceptance did not reach accepted state")
	}
	result := transitionResult(transition)
	result.ActionID = action.ActionID
	return result, nil
}

func (d *TaskEscrowDriver) CommitResult(
	ctx context.Context,
	request CommitResultRequest,
) (Result, error) {
	if !validDigest(request.ResultHash) || !validDigest(request.EvidenceHash) {
		return Result{}, errors.New("invalid task escrow result commitment")
	}
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	switch state.Status {
	case chain.TaskEscrowStatusResultSubmitted, chain.TaskEscrowStatusSettled,
		chain.TaskEscrowStatusDisputed:
		if state.ResultHash != request.ResultHash || state.EvidenceHash != request.EvidenceHash {
			return Result{}, errors.New("task escrow already contains a different result")
		}
		return stateResult(state), nil
	case chain.TaskEscrowStatusAccepted:
	default:
		return Result{}, errors.New("task escrow is not accepted for a result")
	}
	action, err := d.operationAction(
		state, request.EscrowID, state.BudgetNanoTOS, chain.TaskEscrowActionResult,
		request.ResultHash, request.EvidenceHash, "", 0,
	)
	if err != nil {
		return Result{}, err
	}
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Agent, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusResultSubmitted ||
		transition.State.ResultHash != request.ResultHash ||
		transition.State.EvidenceHash != request.EvidenceHash ||
		transition.State.ReviewDeadlineUnix == 0 {
		return Result{}, errors.New("task escrow result transition mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) ReleaseEscrow(
	ctx context.Context,
	request ReleaseEscrowRequest,
) (Result, error) {
	return d.RefundPrincipal(ctx, RefundPrincipalRequest{
		EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
		BudgetNanoTOS: request.BudgetNanoTOS, ReleaseDigest: request.ReleaseDigest,
	})
}

func (d *TaskEscrowDriver) SettleProvider(
	ctx context.Context,
	request SettleProviderRequest,
) (Result, error) {
	if request.BudgetNanoTOS == 0 || request.PayoutNanoTOS > request.BudgetNanoTOS || !validDigest(request.ResultHash) ||
		!validDigest(request.EvidenceHash) {
		return Result{}, errors.New("invalid task escrow settlement")
	}
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	if state.Status == chain.TaskEscrowStatusOpen {
		accepted, err := d.AcceptEscrow(ctx, AcceptEscrowRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			ExpectedAgent: state.Agent,
		})
		if err != nil {
			return Result{}, err
		}
		state = accepted.State
	}
	if state.Status == chain.TaskEscrowStatusAccepted {
		committed, err := d.CommitResult(ctx, CommitResultRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			ResultHash: request.ResultHash, EvidenceHash: request.EvidenceHash,
		})
		if err != nil {
			return Result{}, err
		}
		state = committed.State
	}
	if state.Status == chain.TaskEscrowStatusSettled {
		if state.ResultHash != request.ResultHash || state.EvidenceHash != request.EvidenceHash {
			return Result{}, errors.New("settled task escrow result mismatch")
		}
		return d.replaySettlement(ctx, state, request)
	}
	if state.Status != chain.TaskEscrowStatusResultSubmitted ||
		state.ResultHash != request.ResultHash || state.EvidenceHash != request.EvidenceHash ||
		state.BudgetNanoTOS != request.BudgetNanoTOS ||
		request.PayoutNanoTOS > state.BudgetNanoTOS {
		return Result{}, errors.New("task escrow is not ready for settlement")
	}
	action, err := d.operationAction(
		state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionSettle,
		request.ResultHash, request.EvidenceHash, "", request.PayoutNanoTOS,
	)
	if err != nil {
		return Result{}, err
	}
	creatorMinimum := request.BudgetNanoTOS - request.PayoutNanoTOS
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Verifier, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
		ExpectedAgent: state.Agent, ExpectedAgentPayout: request.PayoutNanoTOS,
		ExpectedCreator: state.Creator, ExpectedCreatorMinimum: creatorMinimum,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusSettled ||
		transition.State.BudgetNanoTOS != 0 || transition.State.BalanceNanoTOS != 0 ||
		transition.AgentPaidNanoTOS != request.PayoutNanoTOS ||
		transition.CreatorPaidNanoTOS < creatorMinimum {
		return Result{}, errors.New("task escrow settlement transition mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) RefundPrincipal(
	ctx context.Context,
	request RefundPrincipalRequest,
) (Result, error) {
	if request.BudgetNanoTOS == 0 {
		return Result{}, errors.New("task escrow refund budget is required")
	}
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	switch state.Status {
	case chain.TaskEscrowStatusCancelled:
		return d.replayRefund(ctx, state, request, chain.TaskEscrowActionCancel)
	case chain.TaskEscrowStatusExpired:
		return d.replayRefund(ctx, state, request, chain.TaskEscrowActionTimeout)
	case chain.TaskEscrowStatusRejected:
		return d.replayRefund(ctx, state, request, chain.TaskEscrowActionReject)
	case chain.TaskEscrowStatusSettled:
		if state.DisputeHash == zeroDigest() ||
			(request.DisputeHash != "" && request.DisputeHash != state.DisputeHash) {
			return Result{}, errors.New("settled task escrow cannot be refunded")
		}
		return d.ResolveDispute(ctx, ResolveDisputeRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			BudgetNanoTOS: request.BudgetNanoTOS, PayoutNanoTOS: 0,
		})
	case chain.TaskEscrowStatusDisputed:
		return d.ResolveDispute(ctx, ResolveDisputeRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			BudgetNanoTOS: request.BudgetNanoTOS, PayoutNanoTOS: 0,
		})
	case chain.TaskEscrowStatusResultSubmitted:
		if !state.HasVerifier || !validDigest(request.DisputeHash) {
			return Result{}, errors.New("submitted result requires a verifier-backed dispute to refund")
		}
		disputed, err := d.OpenDispute(ctx, OpenDisputeRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			DisputeHash: request.DisputeHash,
		})
		if err != nil {
			return Result{}, err
		}
		if disputed.State.Status != chain.TaskEscrowStatusDisputed {
			return Result{}, errors.New("task escrow did not enter disputed state")
		}
		return d.ResolveDispute(ctx, ResolveDisputeRequest{
			EscrowID: request.EscrowID, ContractAddress: request.ContractAddress,
			BudgetNanoTOS: request.BudgetNanoTOS, PayoutNanoTOS: 0,
		})
	case chain.TaskEscrowStatusOpen:
		if state.BudgetNanoTOS != request.BudgetNanoTOS {
			return Result{}, errors.New("task escrow refund budget mismatch")
		}
		return d.refundAction(ctx, state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionCancel, request.ReleaseDigest)
	case chain.TaskEscrowStatusAccepted:
		if uint64(d.now().Unix()) < state.DeadlineUnix {
			return Result{}, errors.New("accepted task escrow cannot refund before its deadline")
		}
		if state.BudgetNanoTOS != request.BudgetNanoTOS {
			return Result{}, errors.New("task escrow refund budget mismatch")
		}
		return d.refundAction(ctx, state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionTimeout, request.ReleaseDigest)
	default:
		return Result{}, errors.New("task escrow cannot be refunded from current state")
	}
}

func (d *TaskEscrowDriver) OpenDispute(
	ctx context.Context,
	request OpenDisputeRequest,
) (Result, error) {
	if !validDigest(request.DisputeHash) {
		return Result{}, errors.New("invalid task escrow dispute commitment")
	}
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	if state.Status == chain.TaskEscrowStatusDisputed {
		if state.DisputeHash != request.DisputeHash {
			return Result{}, errors.New("task escrow already contains a different dispute")
		}
		return stateResult(state), nil
	}
	if state.Status != chain.TaskEscrowStatusResultSubmitted || !state.HasVerifier ||
		uint64(d.now().Unix()) > state.ReviewDeadlineUnix {
		return Result{}, errors.New("task escrow is not open for dispute")
	}
	action, err := d.operationAction(
		state, request.EscrowID, state.BudgetNanoTOS, chain.TaskEscrowActionDispute,
		"", "", request.DisputeHash, 0,
	)
	if err != nil {
		return Result{}, err
	}
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Creator, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusDisputed ||
		transition.State.DisputeHash != request.DisputeHash {
		return Result{}, errors.New("task escrow dispute transition mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) ResolveDispute(
	ctx context.Context,
	request ResolveDisputeRequest,
) (Result, error) {
	state, err := d.read(ctx, request.ContractAddress)
	if err != nil {
		return Result{}, err
	}
	if request.BudgetNanoTOS == 0 || request.PayoutNanoTOS > request.BudgetNanoTOS {
		return Result{}, errors.New("invalid task escrow dispute resolution")
	}
	if state.Status == chain.TaskEscrowStatusSettled {
		return d.replayResolution(ctx, state, request)
	}
	if state.Status != chain.TaskEscrowStatusDisputed ||
		state.BudgetNanoTOS != request.BudgetNanoTOS ||
		request.PayoutNanoTOS > state.BudgetNanoTOS {
		return Result{}, errors.New("task escrow is not ready for dispute resolution")
	}
	action, err := d.operationAction(
		state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionResolve,
		"", "", state.DisputeHash, request.PayoutNanoTOS,
	)
	if err != nil {
		return Result{}, err
	}
	creatorMinimum := request.BudgetNanoTOS - request.PayoutNanoTOS
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Verifier, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
		ExpectedAgent: state.Agent, ExpectedAgentPayout: request.PayoutNanoTOS,
		ExpectedCreator: state.Creator, ExpectedCreatorMinimum: creatorMinimum,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusSettled ||
		transition.State.BudgetNanoTOS != 0 || transition.State.BalanceNanoTOS != 0 ||
		transition.AgentPaidNanoTOS != request.PayoutNanoTOS ||
		transition.CreatorPaidNanoTOS < creatorMinimum {
		return Result{}, errors.New("task escrow dispute resolution mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) replaySettlement(
	ctx context.Context,
	state chain.TaskEscrowState,
	request SettleProviderRequest,
) (Result, error) {
	action, err := d.operationAction(
		state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionSettle,
		request.ResultHash, request.EvidenceHash, "", request.PayoutNanoTOS,
	)
	if err != nil {
		return Result{}, err
	}
	creatorMinimum := request.BudgetNanoTOS - request.PayoutNanoTOS
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Verifier, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
		ExpectedAgent: state.Agent, ExpectedAgentPayout: request.PayoutNanoTOS,
		ExpectedCreator: state.Creator, ExpectedCreatorMinimum: creatorMinimum,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusSettled ||
		transition.State.BudgetNanoTOS != 0 || transition.State.BalanceNanoTOS != 0 ||
		transition.AgentPaidNanoTOS != request.PayoutNanoTOS ||
		transition.CreatorPaidNanoTOS < creatorMinimum {
		return Result{}, errors.New("replayed task escrow settlement mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) replayResolution(
	ctx context.Context,
	state chain.TaskEscrowState,
	request ResolveDisputeRequest,
) (Result, error) {
	action, err := d.operationAction(
		state, request.EscrowID, request.BudgetNanoTOS, chain.TaskEscrowActionResolve,
		"", "", state.DisputeHash, request.PayoutNanoTOS,
	)
	if err != nil {
		return Result{}, err
	}
	creatorMinimum := request.BudgetNanoTOS - request.PayoutNanoTOS
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: state.Verifier, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
		ExpectedAgent: state.Agent, ExpectedAgentPayout: request.PayoutNanoTOS,
		ExpectedCreator: state.Creator, ExpectedCreatorMinimum: creatorMinimum,
	})
	if err != nil {
		return Result{}, err
	}
	if transition.State.Status != chain.TaskEscrowStatusSettled ||
		transition.State.BudgetNanoTOS != 0 || transition.State.BalanceNanoTOS != 0 ||
		transition.AgentPaidNanoTOS != request.PayoutNanoTOS ||
		transition.CreatorPaidNanoTOS < creatorMinimum {
		return Result{}, errors.New("replayed task escrow resolution mismatch")
	}
	return transitionResult(transition), nil
}

func (d *TaskEscrowDriver) replayRefund(
	ctx context.Context,
	state chain.TaskEscrowState,
	request RefundPrincipalRequest,
	kind chain.TaskEscrowActionKind,
) (Result, error) {
	return d.refundAction(ctx, state, request.EscrowID, request.BudgetNanoTOS, kind, request.ReleaseDigest)
}

func (d *TaskEscrowDriver) ReadEconomicState(
	ctx context.Context,
	contractAddress string,
) (chain.TaskEscrowState, error) {
	return d.read(ctx, contractAddress)
}

func (d *TaskEscrowDriver) refundAction(
	ctx context.Context,
	state chain.TaskEscrowState,
	escrowID string,
	budget uint64,
	kind chain.TaskEscrowActionKind,
	releaseDigest string,
) (Result, error) {
	if !validDigest(releaseDigest) {
		return Result{}, errors.New("verified escrow release digest is required")
	}
	action := chain.TaskEscrowAction{
		Version: chain.TaskEscrowActionVersion, Network: d.network,
		Kind: kind, EscrowID: escrowID, ContractAddress: state.ContractAddress,
		Creator: state.Creator, Agent: state.Agent, Verifier: state.Verifier,
		BudgetNanoTOS: budget, DeadlineUnix: state.DeadlineUnix,
		ReviewPeriod: state.ReviewPeriod, PolicyHash: state.PolicyHash,
		PermissionHash: state.PermissionHash,
		ReleaseDigest:  releaseDigest,
	}
	err := d.finishAction(&action)
	if err != nil {
		return Result{}, err
	}
	expectedSender := state.Creator
	switch kind {
	case chain.TaskEscrowActionTimeout:
		// timeout is permissionless; the private publisher uses the configured
		// executor account while state and refund outputs remain authoritative.
		expectedSender = ""
	case chain.TaskEscrowActionReject:
		expectedSender = state.Agent
	}
	transition, err := d.publishAndObserve(ctx, action, chain.TaskEscrowTransitionReference{
		ExpectedSender: expectedSender, ExpectedKind: action.Kind,
		ExpectedQueryID: action.QueryID, ExpectedBodyHash: action.ExpectedBodyHash,
		ExpectedCreator: state.Creator, ExpectedCreatorMinimum: budget,
	})
	if err != nil {
		return Result{}, err
	}
	if (transition.State.Status != chain.TaskEscrowStatusCancelled &&
		transition.State.Status != chain.TaskEscrowStatusExpired &&
		transition.State.Status != chain.TaskEscrowStatusRejected) ||
		transition.State.BudgetNanoTOS != 0 || transition.State.BalanceNanoTOS != 0 ||
		transition.CreatorPaidNanoTOS < budget {
		return Result{}, errors.New("task escrow refund transition mismatch")
	}
	result := transitionResult(transition)
	result.ActionID = action.ActionID
	return result, nil
}

func (d *TaskEscrowDriver) read(
	ctx context.Context,
	contractAddress string,
) (chain.TaskEscrowState, error) {
	contractAddress, err := toschain.CanonicalAddress(contractAddress)
	if err != nil {
		return chain.TaskEscrowState{}, err
	}
	callContext, cancel, err := d.callContext(ctx)
	if err != nil {
		return chain.TaskEscrowState{}, err
	}
	defer cancel()
	state, err := d.observer.ReadTaskEscrow(callContext, chain.TaskEscrowReference{
		Network: d.network, ContractAddress: contractAddress,
		AllowedCodeHashes: append([]string(nil), d.allowedCodeHashes...),
	})
	if err != nil {
		return chain.TaskEscrowState{}, err
	}
	if err := d.validateObservedState(state, contractAddress); err != nil {
		return chain.TaskEscrowState{}, err
	}
	return state, nil
}

func (d *TaskEscrowDriver) validateObservedState(
	state chain.TaskEscrowState,
	expectedAddress string,
) error {
	if state.Network != d.network || state.ContractAddress != expectedAddress ||
		state.ObservedMasterSeqno == 0 || state.ObservedAt.IsZero() ||
		state.DeadlineUnix == 0 || state.ReviewPeriod != d.reviewPeriod ||
		state.Status > chain.TaskEscrowStatusDisputed ||
		!validDigest(state.ResultHash) || !validDigest(state.EvidenceHash) ||
		!validDigest(state.PolicyHash) || !validDigest(state.PermissionHash) ||
		!validDigest(state.DisputeHash) || state.AttestorPublicKey != "" {
		return errors.New("observed Task Escrow state violates driver policy")
	}
	creator, err := toschain.CanonicalAddress(state.Creator)
	if err != nil || creator != state.Creator {
		return errors.New("observed Task Escrow creator is invalid")
	}
	if !state.HasAgent {
		return errors.New("observed Task Escrow has no assigned agent")
	}
	agent, err := toschain.CanonicalAddress(state.Agent)
	if err != nil || agent != state.Agent || agent == creator {
		return errors.New("observed Task Escrow agent is invalid")
	}
	if !state.HasVerifier {
		return errors.New("observed Task Escrow has no verifier")
	}
	verifier, err := toschain.CanonicalAddress(state.Verifier)
	if err != nil || verifier != state.Verifier || verifier != d.verifier ||
		verifier == creator || verifier == agent {
		return errors.New("observed Task Escrow verifier is invalid")
	}
	allowed, err := validateAllowedCodeHashes(d.allowedCodeHashes)
	if err != nil {
		return err
	}
	if _, ok := allowed[state.CodeHash]; !ok {
		return errors.New("observed Task Escrow code hash is not allowed")
	}
	return nil
}

func (d *TaskEscrowDriver) operationAction(
	state chain.TaskEscrowState,
	escrowID string,
	budget uint64,
	kind chain.TaskEscrowActionKind,
	resultHash, evidenceHash, disputeHash string,
	payout uint64,
) (chain.TaskEscrowAction, error) {
	action := chain.TaskEscrowAction{
		Version: chain.TaskEscrowActionVersion, Network: d.network,
		Kind: kind, EscrowID: escrowID, ContractAddress: state.ContractAddress,
		Creator: state.Creator, Agent: state.Agent, Verifier: state.Verifier,
		BudgetNanoTOS: budget, DeadlineUnix: state.DeadlineUnix,
		ReviewPeriod: state.ReviewPeriod, PolicyHash: state.PolicyHash,
		PermissionHash: state.PermissionHash, ResultHash: resultHash,
		EvidenceHash: evidenceHash, DisputeHash: disputeHash, PayoutNanoTOS: payout,
	}
	if err := d.finishAction(&action); err != nil {
		return chain.TaskEscrowAction{}, err
	}
	return action, nil
}

func (d *TaskEscrowDriver) finishAction(action *chain.TaskEscrowAction) error {
	if action == nil {
		return errors.New("task escrow action is required")
	}
	stable := stableAction(*action)
	if action.Kind != chain.TaskEscrowActionDeploy {
		queryDigest, err := codec.Digest("tos.task-escrow.query.v1", stable)
		if err != nil {
			return err
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(queryDigest, "sha256:"))
		if err != nil || len(raw) < 8 {
			return errors.New("invalid task escrow query digest")
		}
		action.QueryID = binary.BigEndian.Uint64(raw[:8])
		if action.QueryID == 0 {
			action.QueryID = 1
		}
		bodyHash, err := taskEscrowBodyHash(*action)
		if err != nil {
			return err
		}
		action.ExpectedBodyHash = bodyHash
		stable = stableAction(*action)
	}
	actionID, err := chain.TaskEscrowActionID(*action)
	if err != nil {
		return err
	}
	action.ActionID = actionID
	action.ExpiresUnixMillis = d.now().Add(d.actionLifetime).UnixMilli()
	return nil
}

type stableTaskEscrowAction struct {
	Version          string                     `json:"version"`
	Network          string                     `json:"network"`
	Kind             chain.TaskEscrowActionKind `json:"kind"`
	EscrowID         string                     `json:"escrow_id"`
	ContractAddress  string                     `json:"contract_address,omitempty"`
	Creator          string                     `json:"creator"`
	Agent            string                     `json:"agent"`
	Verifier         string                     `json:"verifier,omitempty"`
	BudgetNanoTOS    uint64                     `json:"budget_nano_tos"`
	FundingNanoTOS   uint64                     `json:"funding_nano_tos,omitempty"`
	DeadlineUnix     uint64                     `json:"deadline_unix"`
	ReviewPeriod     uint32                     `json:"review_period"`
	PolicyHash       string                     `json:"policy_hash"`
	PermissionHash   string                     `json:"permission_hash"`
	QueryID          uint64                     `json:"query_id,omitempty"`
	ResultHash       string                     `json:"result_hash,omitempty"`
	EvidenceHash     string                     `json:"evidence_hash,omitempty"`
	DisputeHash      string                     `json:"dispute_hash,omitempty"`
	PayoutNanoTOS    uint64                     `json:"payout_nano_tos,omitempty"`
	ExpectedBodyHash string                     `json:"expected_body_hash,omitempty"`
	ReleaseDigest    string                     `json:"release_digest,omitempty"`
}

func stableAction(action chain.TaskEscrowAction) stableTaskEscrowAction {
	return stableTaskEscrowAction{
		Version: action.Version, Network: action.Network, Kind: action.Kind,
		EscrowID: action.EscrowID, ContractAddress: action.ContractAddress,
		Creator: action.Creator, Agent: action.Agent, Verifier: action.Verifier,
		BudgetNanoTOS: action.BudgetNanoTOS, FundingNanoTOS: action.FundingNanoTOS,
		DeadlineUnix: action.DeadlineUnix, ReviewPeriod: action.ReviewPeriod,
		PolicyHash: action.PolicyHash, PermissionHash: action.PermissionHash,
		QueryID: action.QueryID, ResultHash: action.ResultHash,
		EvidenceHash: action.EvidenceHash, DisputeHash: action.DisputeHash,
		PayoutNanoTOS: action.PayoutNanoTOS, ExpectedBodyHash: action.ExpectedBodyHash,
		ReleaseDigest: action.ReleaseDigest,
	}
}

func taskEscrowBodyHash(action chain.TaskEscrowAction) (string, error) {
	opcode, ok := map[chain.TaskEscrowActionKind]uint64{
		chain.TaskEscrowActionAccept:  0x54415301,
		chain.TaskEscrowActionResult:  0x54415302,
		chain.TaskEscrowActionSettle:  0x54415303,
		chain.TaskEscrowActionCancel:  0x54415304,
		chain.TaskEscrowActionTimeout: 0x54415305,
		chain.TaskEscrowActionReject:  0x54415306,
		chain.TaskEscrowActionDispute: 0x54415308,
		chain.TaskEscrowActionResolve: 0x54415309,
	}[action.Kind]
	if !ok || action.QueryID == 0 {
		return "", errors.New("unsupported task escrow operation")
	}
	builder := cell.BeginCell().MustStoreUInt(opcode, 32).MustStoreUInt(action.QueryID, 64)
	switch action.Kind {
	case chain.TaskEscrowActionResult:
		result, err := digestBytes(action.ResultHash)
		if err != nil {
			return "", err
		}
		evidence, err := digestBytes(action.EvidenceHash)
		if err != nil {
			return "", err
		}
		builder.MustStoreSlice(result, 256).MustStoreSlice(evidence, 256)
	case chain.TaskEscrowActionSettle, chain.TaskEscrowActionResolve:
		if err := builder.StoreBigCoins(new(big.Int).SetUint64(action.PayoutNanoTOS)); err != nil {
			return "", err
		}
	case chain.TaskEscrowActionDispute:
		dispute, err := digestBytes(action.DisputeHash)
		if err != nil {
			return "", err
		}
		builder.MustStoreSlice(dispute, 256)
	}
	return "tvm-cell-sha256:" + hex.EncodeToString(builder.EndCell().Hash()), nil
}

func (d *TaskEscrowDriver) publishAndObserve(
	ctx context.Context,
	action chain.TaskEscrowAction,
	expectation chain.TaskEscrowTransitionReference,
) (chain.TaskEscrowTransition, error) {
	callContext, cancel, err := d.callContext(ctx)
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	defer cancel()
	minimum, _, err := d.observer.CheckChainReady(callContext, d.now().UTC())
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	// Always query the enrolled durable journal before mutation. A typed,
	// Action-ID-bound absence is the only result that authorizes Publish;
	// pending/unknown/transport failures remain ambiguous and fail closed.
	receipt, found, err := d.publisher.Resolve(callContext, action)
	if err != nil {
		return chain.TaskEscrowTransition{}, err
	}
	if !found {
		receipt, err = d.publisher.Publish(callContext, action)
		if err != nil {
			return chain.TaskEscrowTransition{}, err
		}
	}
	return d.observeReceipt(callContext, action, receipt, minimum, expectation)
}

func (d *TaskEscrowDriver) observeReceipt(callContext context.Context, action chain.TaskEscrowAction, receipt chain.TaskEscrowActionReceipt, minimum uint64, expectation chain.TaskEscrowTransitionReference) (chain.TaskEscrowTransition, error) {
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID ||
		receipt.Network != action.Network || receipt.Kind != action.Kind ||
		receipt.EscrowID != action.EscrowID || receipt.Reference == "" {
		return chain.TaskEscrowTransition{}, errors.New("task escrow publisher receipt mismatch")
	}
	if action.ContractAddress != "" && receipt.ContractAddress != action.ContractAddress {
		return chain.TaskEscrowTransition{}, errors.New("task escrow publisher changed contract address")
	}
	expectation.TaskEscrowReference = chain.TaskEscrowReference{
		Network: d.network, ContractAddress: receipt.ContractAddress,
		AllowedCodeHashes:  append([]string(nil), d.allowedCodeHashes...),
		MinimumMasterSeqno: minimum,
	}
	expectation.TransactionReference = receipt.Reference
	return d.observer.ObserveTaskEscrowTransition(callContext, expectation)
}

func validateReservedState(state chain.TaskEscrowState, action chain.TaskEscrowAction) error {
	if state.Status != chain.TaskEscrowStatusOpen || state.Creator != action.Creator ||
		!state.HasAgent || state.Agent != action.Agent || !state.HasVerifier ||
		state.Verifier != action.Verifier || state.BudgetNanoTOS != action.BudgetNanoTOS ||
		state.BalanceNanoTOS < action.BudgetNanoTOS || state.DeadlineUnix != action.DeadlineUnix ||
		state.ReviewPeriod != action.ReviewPeriod || state.PolicyHash != action.PolicyHash ||
		state.PermissionHash != action.PermissionHash || state.ResultHash != zeroDigest() ||
		state.EvidenceHash != zeroDigest() || state.DisputeHash != zeroDigest() ||
		state.ReviewDeadlineUnix != 0 || state.AttestorPublicKey != "" {
		return errors.New("deployed Task Escrow state does not match reservation")
	}
	return nil
}

func validateSettledReservationState(state chain.TaskEscrowState, action chain.TaskEscrowAction) error {
	if state.Status != chain.TaskEscrowStatusSettled || state.Creator != action.Creator ||
		!state.HasAgent || state.Agent != action.Agent || !state.HasVerifier ||
		state.Verifier != action.Verifier || state.BudgetNanoTOS != 0 ||
		state.BalanceNanoTOS != 0 || state.DeadlineUnix != action.DeadlineUnix ||
		state.ReviewPeriod != action.ReviewPeriod || state.PolicyHash != action.PolicyHash ||
		state.PermissionHash != action.PermissionHash || state.ResultHash == zeroDigest() ||
		state.EvidenceHash == zeroDigest() || state.ReviewDeadlineUnix == 0 ||
		state.AttestorPublicKey != "" {
		return errors.New("settled Task Escrow state does not match reservation")
	}
	return nil
}

func (d *TaskEscrowDriver) callContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil task escrow context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, d.callTimeout)
	return bounded, cancel, nil
}

func (d *TaskEscrowDriver) Close() error {
	if d == nil {
		return nil
	}
	d.closeOnce.Do(func() {
		if d.publisher != nil {
			d.closeErr = d.publisher.Close()
		}
	})
	return d.closeErr
}

func transitionResult(value chain.TaskEscrowTransition) Result {
	contractRef, _ := toschain.FormatTaskEscrowReference(value.State.ContractAddress)
	return Result{
		State: value.State, ContractReference: contractRef,
		TransitionReference: value.TransactionReference,
		AgentPaidNanoTOS:    value.AgentPaidNanoTOS,
		CreatorPaidNanoTOS:  value.CreatorPaidNanoTOS,
	}
}

func stateResult(state chain.TaskEscrowState) Result {
	contractRef, _ := toschain.FormatTaskEscrowReference(state.ContractAddress)
	return Result{State: state, ContractReference: contractRef}
}

func validDigest(value string) bool {
	_, err := digestBytes(value)
	return err == nil
}

func digestBytes(value string) ([]byte, error) {
	if !strings.HasPrefix(value, "sha256:") {
		return nil, errors.New("digest must use sha256")
	}
	raw := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 32 || raw != strings.ToLower(raw) {
		return nil, errors.New("invalid sha256 digest")
	}
	return decoded, nil
}

func zeroDigest() string { return "sha256:" + strings.Repeat("0", 64) }

func validateAllowedCodeHashes(values []string) (map[string]struct{}, error) {
	if len(values) == 0 || len(values) > 16 {
		return nil, errors.New("Task Escrow code hash allowlist is required")
	}
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !strings.HasPrefix(value, "tvm-cell-sha256:") {
			return nil, errors.New("invalid Task Escrow code hash")
		}
		raw := strings.TrimPrefix(value, "tvm-cell-sha256:")
		decoded, err := hex.DecodeString(raw)
		if err != nil || len(decoded) != 32 || raw != strings.ToLower(raw) {
			return nil, errors.New("invalid Task Escrow code hash")
		}
		result[value] = struct{}{}
	}
	return result, nil
}

func addNoOverflow(left, right uint64) (uint64, bool) {
	if ^uint64(0)-left < right {
		return 0, false
	}
	return left + right, true
}

var _ Driver = (*TaskEscrowDriver)(nil)
