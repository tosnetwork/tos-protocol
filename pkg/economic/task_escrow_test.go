package economic

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

const (
	testNetwork  = "tos-test"
	testCreator  = "0:1111111111111111111111111111111111111111111111111111111111111111"
	testAgent    = "0:2222222222222222222222222222222222222222222222222222222222222222"
	testVerifier = "0:3333333333333333333333333333333333333333333333333333333333333333"
	testContract = "0:4444444444444444444444444444444444444444444444444444444444444444"
	testCodeHash = "tvm-cell-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type taskEscrowHarness struct {
	now             time.Time
	state           chain.TaskEscrowState
	actions         []chain.TaskEscrowAction
	references      map[string]string
	last            chain.TaskEscrowAction
	lastExpectation chain.TaskEscrowTransitionReference
	publishCalls    int
	closed          bool
}

func newTaskEscrowHarness(now time.Time) *taskEscrowHarness {
	return &taskEscrowHarness{now: now, references: make(map[string]string)}
}

func (h *taskEscrowHarness) CheckReady(context.Context) error { return nil }
func (h *taskEscrowHarness) Close() error                     { h.closed = true; return nil }

func (h *taskEscrowHarness) Resolve(_ context.Context, action chain.TaskEscrowAction) (chain.TaskEscrowActionReceipt, bool, error) {
	reference, ok := h.references[action.ActionID]
	if !ok {
		return chain.TaskEscrowActionReceipt{}, false, nil
	}
	h.last = action
	return chain.TaskEscrowActionReceipt{Version: action.Version, ActionID: action.ActionID, Network: action.Network, Kind: action.Kind, EscrowID: action.EscrowID, ContractAddress: testContract, Reference: reference}, true, nil
}

func (h *taskEscrowHarness) Publish(
	_ context.Context,
	action chain.TaskEscrowAction,
) (chain.TaskEscrowActionReceipt, error) {
	h.publishCalls++
	if existing, ok := h.references[action.ActionID]; ok {
		h.last = action
		h.actions = append(h.actions, action)
		return chain.TaskEscrowActionReceipt{
			Version: action.Version, ActionID: action.ActionID,
			Network: action.Network, Kind: action.Kind, EscrowID: action.EscrowID,
			ContractAddress: testContract, Reference: existing,
		}, nil
	}
	if h.state.Status == chain.TaskEscrowStatusSettled ||
		h.state.Status == chain.TaskEscrowStatusCancelled ||
		h.state.Status == chain.TaskEscrowStatusExpired ||
		h.state.Status == chain.TaskEscrowStatusRejected {
		return chain.TaskEscrowActionReceipt{}, errors.New("contract is terminal")
	}
	reference := "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":" +
		string(rune('1'+len(h.references))) + ":" + strings.Repeat("55", 32)
	h.references[action.ActionID] = reference
	h.last = action
	h.actions = append(h.actions, action)
	return chain.TaskEscrowActionReceipt{
		Version: action.Version, ActionID: action.ActionID,
		Network: action.Network, Kind: action.Kind, EscrowID: action.EscrowID,
		ContractAddress: testContract, Reference: reference,
	}, nil
}

func (h *taskEscrowHarness) CheckChainReady(
	context.Context,
	time.Time,
) (uint64, time.Time, error) {
	return 100, h.now, nil
}

func (h *taskEscrowHarness) ReadTaskEscrow(
	context.Context,
	chain.TaskEscrowReference,
) (chain.TaskEscrowState, error) {
	if h.state.ContractAddress == "" {
		return chain.TaskEscrowState{}, errors.New("not deployed")
	}
	return h.state, nil
}

func (h *taskEscrowHarness) ObserveTaskEscrowTransition(
	_ context.Context,
	reference chain.TaskEscrowTransitionReference,
) (chain.TaskEscrowTransition, error) {
	action := h.last
	h.lastExpectation = reference
	transition := chain.TaskEscrowTransition{
		TransactionReference: reference.TransactionReference,
		Sender:               reference.ExpectedSender, BodyHash: action.ExpectedBodyHash,
		QueryID: action.QueryID, ObservedMasterSeqno: 101, ObservedAt: h.now,
	}
	if action.Kind != chain.TaskEscrowActionDeploy && h.state.ContractAddress == "" {
		return chain.TaskEscrowTransition{}, errors.New("contract is absent")
	}
	switch action.Kind {
	case chain.TaskEscrowActionDeploy:
		if h.state.ContractAddress == "" {
			h.state = chain.TaskEscrowState{
				Network: testNetwork, ContractAddress: testContract,
				Creator: action.Creator, Agent: action.Agent, HasAgent: true,
				Verifier: action.Verifier, HasVerifier: true,
				BudgetNanoTOS: action.BudgetNanoTOS, BalanceNanoTOS: action.FundingNanoTOS,
				DeadlineUnix: action.DeadlineUnix, Status: chain.TaskEscrowStatusOpen,
				ResultHash: zeroDigest(), EvidenceHash: zeroDigest(),
				PolicyHash: action.PolicyHash, PermissionHash: action.PermissionHash,
				ReviewPeriod: action.ReviewPeriod, DisputeHash: zeroDigest(),
				CodeHash: testCodeHash, ObservedMasterSeqno: 101, ObservedAt: h.now,
			}
		}
	case chain.TaskEscrowActionAccept:
		if h.state.Status != chain.TaskEscrowStatusOpen {
			return chain.TaskEscrowTransition{}, errors.New("accept rejected")
		}
		h.state.Status = chain.TaskEscrowStatusAccepted
	case chain.TaskEscrowActionResult:
		if h.state.Status != chain.TaskEscrowStatusAccepted {
			return chain.TaskEscrowTransition{}, errors.New("result rejected")
		}
		h.state.Status = chain.TaskEscrowStatusResultSubmitted
		h.state.ResultHash = action.ResultHash
		h.state.EvidenceHash = action.EvidenceHash
		h.state.ReviewDeadlineUnix = uint64(h.now.Add(time.Hour).Unix())
	case chain.TaskEscrowActionSettle:
		if h.state.Status != chain.TaskEscrowStatusResultSubmitted {
			// Exact replay is accepted only when this action ID already exists.
			if _, ok := h.references[action.ActionID]; !ok || h.state.Status != chain.TaskEscrowStatusSettled {
				return chain.TaskEscrowTransition{}, errors.New("settle rejected")
			}
		}
		transition.AgentPaidNanoTOS = action.PayoutNanoTOS
		transition.CreatorPaidNanoTOS = 1_000 - action.PayoutNanoTOS
		h.state.Status = chain.TaskEscrowStatusSettled
		h.state.BudgetNanoTOS = 0
		h.state.BalanceNanoTOS = 0
	case chain.TaskEscrowActionCancel:
		transition.CreatorPaidNanoTOS = action.BudgetNanoTOS
		h.state.Status = chain.TaskEscrowStatusCancelled
		h.state.BudgetNanoTOS = 0
		h.state.BalanceNanoTOS = 0
	case chain.TaskEscrowActionTimeout:
		transition.CreatorPaidNanoTOS = action.BudgetNanoTOS
		h.state.Status = chain.TaskEscrowStatusExpired
		h.state.BudgetNanoTOS = 0
		h.state.BalanceNanoTOS = 0
	case chain.TaskEscrowActionReject:
		transition.CreatorPaidNanoTOS = action.BudgetNanoTOS
		h.state.Status = chain.TaskEscrowStatusRejected
		h.state.BudgetNanoTOS = 0
		h.state.BalanceNanoTOS = 0
	case chain.TaskEscrowActionDispute:
		h.state.Status = chain.TaskEscrowStatusDisputed
		h.state.DisputeHash = action.DisputeHash
	case chain.TaskEscrowActionResolve:
		if h.state.Status != chain.TaskEscrowStatusDisputed {
			if _, ok := h.references[action.ActionID]; !ok || h.state.Status != chain.TaskEscrowStatusSettled {
				return chain.TaskEscrowTransition{}, errors.New("resolve rejected")
			}
		}
		transition.AgentPaidNanoTOS = action.PayoutNanoTOS
		transition.CreatorPaidNanoTOS = 1_000 - action.PayoutNanoTOS
		h.state.Status = chain.TaskEscrowStatusSettled
		h.state.BudgetNanoTOS = 0
		h.state.BalanceNanoTOS = 0
	default:
		return chain.TaskEscrowTransition{}, errors.New("unsupported transition")
	}
	h.state.ObservedMasterSeqno = 101
	h.state.ObservedAt = h.now
	transition.State = h.state
	return transition, nil
}

func TestTaskEscrowDriverVerifiedLifecycleAndSettlementReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	reserved, err := driver.ReserveEscrow(context.Background(), ReserveEscrowRequest{
		EscrowID: "esc-test", Creator: testCreator, Agent: testAgent,
		BudgetNanoTOS: 1_000, DeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if reserved.State.Status != chain.TaskEscrowStatusOpen || reserved.TransitionReference == "" {
		t.Fatalf("unexpected reservation: %#v", reserved)
	}
	if _, err := driver.AcceptEscrow(context.Background(), AcceptEscrowRequest{
		EscrowID: "esc-test", ContractAddress: testContract, ExpectedAgent: testAgent,
	}); err != nil {
		t.Fatal(err)
	}
	resultHash := "sha256:" + strings.Repeat("33", 32)
	evidenceHash := "sha256:" + strings.Repeat("44", 32)
	settlement := SettleProviderRequest{
		EscrowID: "esc-test", ContractAddress: testContract,
		BudgetNanoTOS: 1_000, ResultHash: resultHash,
		EvidenceHash: evidenceHash, PayoutNanoTOS: 700,
	}
	first, err := driver.SettleProvider(context.Background(), settlement)
	if err != nil {
		t.Fatal(err)
	}
	if first.AgentPaidNanoTOS != 700 || first.CreatorPaidNanoTOS < 300 ||
		first.State.Status != chain.TaskEscrowStatusSettled || first.TransitionReference == "" {
		t.Fatalf("unexpected settlement: %#v", first)
	}
	firstSettleAction := harness.actions[len(harness.actions)-1]
	second, err := driver.SettleProvider(context.Background(), settlement)
	if err != nil {
		t.Fatal(err)
	}
	secondSettleAction := harness.actions[len(harness.actions)-1]
	if firstSettleAction.ActionID != secondSettleAction.ActionID ||
		firstSettleAction.QueryID != secondSettleAction.QueryID ||
		first.TransitionReference != second.TransitionReference {
		t.Fatalf("settlement replay changed identity: first=%#v second=%#v", firstSettleAction, secondSettleAction)
	}
	if firstSettleAction.ExpiresUnixMillis != secondSettleAction.ExpiresUnixMillis {
		// The fixed test clock makes expiry equal; this assertion documents that
		// expiry is not required to differ for an exact replay.
	}
	recovered, found, err := driver.ResolveEscrow(context.Background(), ReserveEscrowRequest{
		EscrowID: "esc-test", Creator: testCreator, Agent: testAgent,
		BudgetNanoTOS: 1_000, DeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	})
	if err != nil {
		t.Fatalf("resolve settled escrow through production driver: %v", err)
	}
	if !found || recovered.State.Status != chain.TaskEscrowStatusSettled ||
		recovered.State.BudgetNanoTOS != 0 || recovered.State.BalanceNanoTOS != 0 ||
		recovered.ContractReference != first.ContractReference {
		t.Fatalf("unexpected settled escrow recovery: found=%v result=%#v", found, recovered)
	}
	harness.state.PermissionHash = "sha256:" + strings.Repeat("99", 32)
	if _, _, err := driver.ResolveEscrow(context.Background(), ReserveEscrowRequest{
		EscrowID: "esc-test", Creator: testCreator, Agent: testAgent,
		BudgetNanoTOS: 1_000, DeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	}); err == nil {
		t.Fatal("settled escrow with substituted reservation binding was recovered")
	}
	if !driver.Supports(TrustModeVerified) || driver.Supports(TrustModeNative) {
		t.Fatal("task escrow driver advertised the wrong trust modes")
	}
}

func TestTaskEscrowDriverRejectsDifferentPayoutAfterSettlement(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	harness.state = chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, HasAgent: true,
		Verifier: testVerifier, HasVerifier: true,
		Status: chain.TaskEscrowStatusSettled, BudgetNanoTOS: 0, BalanceNanoTOS: 0,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		ResultHash:     "sha256:" + strings.Repeat("33", 32),
		EvidenceHash:   "sha256:" + strings.Repeat("44", 32),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
		DisputeHash:    zeroDigest(), CodeHash: testCodeHash,
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = driver.SettleProvider(context.Background(), SettleProviderRequest{
		EscrowID: "esc-test", ContractAddress: testContract,
		BudgetNanoTOS: 1_000, ResultHash: harness.state.ResultHash,
		EvidenceHash: harness.state.EvidenceHash, PayoutNanoTOS: 999,
	})
	if err == nil {
		t.Fatal("different payout after terminal settlement was accepted")
	}
}

func TestTaskEscrowDriverDoesNotReplaySettlementAfterDisputeResolution(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	resultHash := "sha256:" + strings.Repeat("33", 32)
	evidenceHash := "sha256:" + strings.Repeat("44", 32)
	harness := newTaskEscrowHarness(now)
	harness.state = chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, HasAgent: true,
		Verifier: testVerifier, HasVerifier: true,
		Status: chain.TaskEscrowStatusSettled, BudgetNanoTOS: 0, BalanceNanoTOS: 0,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		ReviewDeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		ResultHash:         resultHash, EvidenceHash: evidenceHash,
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
		DisputeHash:    "sha256:" + strings.Repeat("55", 32),
		CodeHash:       testCodeHash, ObservedMasterSeqno: 101, ObservedAt: now,
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()

	_, err = driver.SettleProvider(context.Background(), SettleProviderRequest{
		EscrowID: "esc-disputed", ContractAddress: testContract,
		BudgetNanoTOS: 1_000, ResultHash: resultHash,
		EvidenceHash: evidenceHash, PayoutNanoTOS: 700,
	})
	if err == nil {
		t.Fatal("dispute-resolved escrow entered ordinary settlement replay")
	}
	if harness.publishCalls != 0 {
		t.Fatalf("ordinary settlement replay published %d action(s) after dispute resolution", harness.publishCalls)
	}
}

func TestTaskEscrowDriverTerminalSettlementAbsenceNeverPublishes(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	harness.state = chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, HasAgent: true,
		Verifier: testVerifier, HasVerifier: true,
		Status: chain.TaskEscrowStatusSettled, BudgetNanoTOS: 0, BalanceNanoTOS: 0,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		ResultHash:     "sha256:" + strings.Repeat("33", 32),
		EvidenceHash:   "sha256:" + strings.Repeat("44", 32),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
		DisputeHash:    zeroDigest(), CodeHash: testCodeHash,
		ObservedMasterSeqno: 101, ObservedAt: now,
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()

	_, err = driver.SettleProvider(context.Background(), SettleProviderRequest{
		EscrowID: "esc-terminal", ContractAddress: testContract,
		BudgetNanoTOS: 1_000, ResultHash: harness.state.ResultHash,
		EvidenceHash: harness.state.EvidenceHash, PayoutNanoTOS: 700,
	})
	if err == nil {
		t.Fatal("terminal settlement without its original journal receipt was accepted")
	}
	if harness.publishCalls != 0 {
		t.Fatalf("terminal settlement recovery published %d action(s)", harness.publishCalls)
	}
}

func TestTaskEscrowDriverRejectsZeroDisputeCommitment(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	if _, err := driver.OpenDispute(context.Background(), OpenDisputeRequest{
		EscrowID: "esc-zero", ContractAddress: testContract, DisputeHash: zeroDigest(),
	}); err == nil {
		t.Fatal("all-zero dispute commitment was accepted")
	}
	if harness.publishCalls != 0 {
		t.Fatalf("invalid dispute published %d action(s)", harness.publishCalls)
	}
}

func TestTaskEscrowDriverSettlesZeroProviderPayoutAndFullRefundIdempotently(t *testing.T) {
	now := time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC)
	resultHash := "sha256:" + strings.Repeat("33", 32)
	evidenceHash := "sha256:" + strings.Repeat("44", 32)
	harness := newTaskEscrowHarness(now)
	harness.state = chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, HasAgent: true,
		Verifier: testVerifier, HasVerifier: true,
		BudgetNanoTOS: 1_000, BalanceNanoTOS: 1_050,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), Status: chain.TaskEscrowStatusResultSubmitted,
		ResultHash: resultHash, EvidenceHash: evidenceHash,
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
		ReviewPeriod:   3600, ReviewDeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		DisputeHash: zeroDigest(), CodeHash: testCodeHash,
		ObservedMasterSeqno: 101, ObservedAt: now,
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, ReviewPeriod: time.Hour, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	request := SettleProviderRequest{
		EscrowID: "esc-zero", ContractAddress: testContract, BudgetNanoTOS: 1_000,
		ResultHash: resultHash, EvidenceHash: evidenceHash, PayoutNanoTOS: 0,
	}
	first, err := driver.SettleProvider(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if first.AgentPaidNanoTOS != 0 || first.CreatorPaidNanoTOS < 1_000 ||
		first.State.Status != chain.TaskEscrowStatusSettled || first.State.BudgetNanoTOS != 0 ||
		first.State.BalanceNanoTOS != 0 {
		t.Fatalf("zero-charge settlement did not fully refund requester: %#v", first)
	}
	firstAction := harness.actions[len(harness.actions)-1]
	second, err := driver.SettleProvider(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	secondAction := harness.actions[len(harness.actions)-1]
	if firstAction.ActionID != secondAction.ActionID || first.TransitionReference != second.TransitionReference ||
		second.AgentPaidNanoTOS != 0 || second.CreatorPaidNanoTOS < 1_000 {
		t.Fatalf("zero-charge replay diverged: first=%#v second=%#v", first, second)
	}
}

func TestTaskEscrowActionIdentityExcludesFreshnessButBindsPayout(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return harness.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	state := chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, Verifier: testVerifier,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	}
	one, err := driver.operationAction(state, "esc-test", 1_000, chain.TaskEscrowActionSettle,
		"sha256:"+strings.Repeat("33", 32), "sha256:"+strings.Repeat("44", 32), "", 700)
	if err != nil {
		t.Fatal(err)
	}
	harness.now = harness.now.Add(time.Minute)
	two, err := driver.operationAction(state, "esc-test", 1_000, chain.TaskEscrowActionSettle,
		one.ResultHash, one.EvidenceHash, "", 700)
	if err != nil {
		t.Fatal(err)
	}
	if one.ActionID != two.ActionID || one.QueryID != two.QueryID || one.ExpectedBodyHash != two.ExpectedBodyHash {
		t.Fatal("freshness changed stable action identity")
	}
	if one.ExpiresUnixMillis == two.ExpiresUnixMillis {
		t.Fatal("freshness window was not refreshed")
	}
	three, err := driver.operationAction(state, "esc-test", 1_000, chain.TaskEscrowActionSettle,
		one.ResultHash, one.EvidenceHash, "", 701)
	if err != nil {
		t.Fatal(err)
	}
	if one.ActionID == three.ActionID {
		t.Fatal("payout was not bound into action identity")
	}
}

func TestTaskEscrowDriverRequiresDistinctEconomicParties(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	_, err = driver.ReserveEscrow(context.Background(), ReserveEscrowRequest{
		EscrowID: "esc-same-party", Creator: testCreator, Agent: testCreator,
		BudgetNanoTOS: 1_000, DeadlineUnix: uint64(now.Add(time.Hour).Unix()),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
	})
	if err == nil {
		t.Fatal("Task Escrow accepted the same account as creator and agent")
	}
}

func TestTaskEscrowRejectedReplayIsBoundToAgentSender(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	harness := newTaskEscrowHarness(now)
	harness.state = chain.TaskEscrowState{
		Network: testNetwork, ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, HasAgent: true,
		Verifier: testVerifier, HasVerifier: true,
		Status: chain.TaskEscrowStatusRejected, BudgetNanoTOS: 0, BalanceNanoTOS: 0,
		DeadlineUnix: uint64(now.Add(time.Hour).Unix()), ReviewPeriod: 3600,
		ResultHash: zeroDigest(), EvidenceHash: zeroDigest(),
		PolicyHash:     "sha256:" + strings.Repeat("11", 32),
		PermissionHash: "sha256:" + strings.Repeat("22", 32),
		DisputeHash:    zeroDigest(), CodeHash: testCodeHash,
		ObservedMasterSeqno: 101, ObservedAt: now,
	}
	driver, err := NewTaskEscrowDriver(TaskEscrowConfig{
		Observer: harness, Publisher: harness, Network: testNetwork,
		AllowedCodeHashes: []string{testCodeHash}, Verifier: testVerifier,
		FundingOverhead: 50, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer driver.Close()
	// Seed the exact reject action so the fake sidecar can replay the original
	// terminal transaction rather than attempting a second contract call.
	releaseDigest := "sha256:" + strings.Repeat("ab", 32)
	action := chain.TaskEscrowAction{Version: chain.TaskEscrowActionVersion, Network: testNetwork,
		Kind: chain.TaskEscrowActionReject, EscrowID: "esc-rejected", ContractAddress: testContract,
		Creator: testCreator, Agent: testAgent, Verifier: testVerifier, BudgetNanoTOS: 1_000,
		DeadlineUnix: harness.state.DeadlineUnix, ReviewPeriod: 3600,
		PolicyHash: harness.state.PolicyHash, PermissionHash: harness.state.PermissionHash,
		ReleaseDigest: releaseDigest}
	err = driver.finishAction(&action)
	if err != nil {
		t.Fatal(err)
	}
	harness.references[action.ActionID] = "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":7:" + strings.Repeat("55", 32)
	result, err := driver.RefundPrincipal(context.Background(), RefundPrincipalRequest{
		EscrowID: "esc-rejected", ContractAddress: testContract, BudgetNanoTOS: 1_000,
		ReleaseDigest: releaseDigest,
	})
	if err != nil {
		t.Fatal(err)
	}
	if harness.last.Kind != chain.TaskEscrowActionReject ||
		harness.lastExpectation.ExpectedSender != testAgent || result.TransitionReference == "" {
		t.Fatalf("unexpected rejected replay: action=%#v sender=%q result=%#v", harness.last, harness.lastExpectation.ExpectedSender, result)
	}
}

func TestNormativeReleaseQueryAndBodyVector(t *testing.T) {
	driver := &TaskEscrowDriver{network: "tos-test", now: func() time.Time { return time.Unix(1_800_000_000, 0) }, actionLifetime: time.Minute}
	action := chain.TaskEscrowAction{
		Version: chain.TaskEscrowActionVersion, Network: "tos-test", Kind: chain.TaskEscrowActionCancel,
		EscrowID: "esc_07dc7a9bb743b890a44312c5d6d85a8a", ContractAddress: "0:" + strings.Repeat("55", 32),
		Creator: "0:" + strings.Repeat("11", 32), Agent: "0:" + strings.Repeat("22", 32),
		Verifier: "0:" + strings.Repeat("33", 32), BudgetNanoTOS: 1_050_000_000,
		DeadlineUnix: 1_800_000_300, ReviewPeriod: 3600,
		PolicyHash:     "sha256:" + strings.Repeat("44", 32),
		PermissionHash: "sha256:271b8392229e741f86cbd9366f4fd35c09ce22b4a6a92f96bb7cdc68932149b5",
		ReleaseDigest:  "sha256:8a38d8920a287d1d2401285f814abb4c409a3bd866ab3a330e74df9ba1a16b1a",
	}
	if err := driver.finishAction(&action); err != nil {
		t.Fatal(err)
	}
	if action.QueryID != 8076693888132313379 ||
		action.ExpectedBodyHash != "tvm-cell-sha256:2a8ece876e9cfa1ef9bd9062b6c5ecbbee07bbea1ac8283fba8e5639522c80d8" ||
		action.ActionID != "task-action-762de1e789d3f797f6bff0e6abff99d3cae158c924c7626297dd97eeefdfbc47" {
		t.Fatalf("release query vector: query_id=%d body=%s action=%s", action.QueryID, action.ExpectedBodyHash, action.ActionID)
	}
}
