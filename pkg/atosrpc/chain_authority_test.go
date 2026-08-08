package atosrpc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	testChainPayer = "0:1111111111111111111111111111111111111111111111111111111111111111"
	testChainPayee = "0:2222222222222222222222222222222222222222222222222222222222222222"
)

type testChainAuthorityRuntime struct {
	readiness  toschain.ReadinessSnapshot
	state      chain.PaymentState
	readyErr   error
	observeErr error
	observed   chain.PaymentReference
	readyCalls int
}

func (r *testChainAuthorityRuntime) CheckServiceReady(
	_ context.Context,
	_ authorization.Reference,
	_ time.Time,
) (toschain.ReadinessSnapshot, error) {
	r.readyCalls++
	if r.readyErr != nil {
		return toschain.ReadinessSnapshot{}, r.readyErr
	}
	return r.readiness, nil
}

func (r *testChainAuthorityRuntime) ObservePayment(
	_ context.Context,
	reference chain.PaymentReference,
) (chain.PaymentState, error) {
	r.observed = reference
	if r.observeErr != nil {
		return chain.PaymentState{}, r.observeErr
	}
	state := r.state
	if state.Network == "" {
		state = chain.PaymentState{
			Network: reference.Network, AuthorizationID: reference.AuthorizationID,
			QuoteID: reference.QuoteID, RequestID: reference.RequestID,
			Reference: reference.Reference, Confirmed: true, Finalized: true,
			Payer: reference.Payer, Payee: reference.Payee,
			AmountNanoTOS: reference.AmountNanoTOS, Comment: reference.Comment,
			ObservedMasterSeqno: reference.MinimumMasterSeqno + 1,
			ObservedAt:          time.Unix(1_800_000_001, 0).UTC(),
		}
	}
	if state.ObservedMasterSeqno > r.readiness.ObservedMasterSeqno {
		r.readiness.ObservedMasterSeqno = state.ObservedMasterSeqno
	}
	return state, nil
}

type testChainActionPublisher struct {
	actions       []chain.Action
	readyErr      error
	publishErr    error
	changeReceipt func(*chain.ActionReceipt)
	closed        bool
}

func (p *testChainActionPublisher) CheckReady(context.Context) error { return p.readyErr }

func (p *testChainActionPublisher) Publish(
	_ context.Context,
	action chain.Action,
) (chain.ActionReceipt, error) {
	if p.publishErr != nil {
		return chain.ActionReceipt{}, p.publishErr
	}
	p.actions = append(p.actions, action)
	receipt := chain.ActionReceipt{
		Version: action.Version, ActionID: action.ActionID,
		Network: action.Network, Kind: action.Kind, ObjectID: action.ObjectID,
		Digest:    action.Digest,
		Reference: "tos:tx:v1:0:2222222222222222222222222222222222222222222222222222222222222222:1:3333333333333333333333333333333333333333333333333333333333333333",
		Payer:     action.Payer, Payee: action.Payee,
		AmountNanoTOS: action.AmountNanoTOS, Comment: action.Comment,
	}
	if p.changeReceipt != nil {
		p.changeReceipt(&receipt)
	}
	return receipt, nil
}

func (p *testChainActionPublisher) Close() error { p.closed = true; return nil }

func TestChainAuthorityPublishesAndIndependentlyVerifiesFinalizedCommitment(t *testing.T) {
	now := time.Unix(1_800_000_001, 0).UTC()
	runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
		Network: "tos-test", ObservedMasterSeqno: 700,
		ObservedAt: now.Add(-time.Second), QuorumEndpoints: 2,
	}}
	publisher := new(testChainActionPublisher)
	authority, err := newTestChainAuthority(runtime, publisher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if !authority.Supports(TrustModeManaged) || authority.Supports(TrustModeVerified) ||
		authority.Supports(TrustModeNative) {
		t.Fatal("chain commitment Authority activated an unsupported trust mode")
	}
	ref, err := authority.Commit(
		context.Background(), "capability-manifest", "cap-test@1.0.0",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Network != "tos-test" || ref.Reference == "" || len(publisher.actions) != 1 {
		t.Fatalf("unexpected chain commitment: network=%q reference=%q actions=%d", ref.Network, ref.Reference, len(publisher.actions))
	}
	action := publisher.actions[0]
	if action.Kind != chain.ActionKindAnchor || action.Comment == "" ||
		runtime.observed.Comment != action.Comment ||
		runtime.observed.MinimumMasterSeqno != 700 || runtime.readyCalls < 2 {
		t.Fatalf("commitment was not independently finality-bound: action=%#v observed=%#v ready=%d", action, runtime.observed, runtime.readyCalls)
	}
	if err := authority.Close(); err != nil || !publisher.closed {
		t.Fatalf("authority did not close publisher: err=%v closed=%v", err, publisher.closed)
	}
}

func TestChainAuthorityRejectsPublisherSubstitution(t *testing.T) {
	now := time.Unix(1_800_000_001, 0).UTC()
	runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
		Network: "tos-test", ObservedMasterSeqno: 700,
		ObservedAt: now, QuorumEndpoints: 2,
	}}
	publisher := &testChainActionPublisher{changeReceipt: func(receipt *chain.ActionReceipt) {
		receipt.Comment = "other"
	}}
	authority, err := newTestChainAuthority(runtime, publisher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if _, err := authority.Commit(
		context.Background(), "quote", "quote-test",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	); err == nil {
		t.Fatal("publisher substitution was accepted")
	}
}

func TestChainAuthorityRejectsFinalityBindingMismatch(t *testing.T) {
	now := time.Unix(1_800_000_001, 0).UTC()
	runtime := &testChainAuthorityRuntime{
		readiness: toschain.ReadinessSnapshot{
			Network: "tos-test", ObservedMasterSeqno: 700,
			ObservedAt: now, QuorumEndpoints: 2,
		},
		state: chain.PaymentState{
			Network: "tos-test", AuthorizationID: "wrong",
			Confirmed: true, Finalized: true, Payer: testChainPayer,
			Payee: testChainPayee, AmountNanoTOS: 1,
			ObservedMasterSeqno: 701, ObservedAt: now,
		},
	}
	authority, err := newTestChainAuthority(runtime, new(testChainActionPublisher), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if _, err := authority.Commit(
		context.Background(), "quote", "quote-test",
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
	); err == nil {
		t.Fatal("mismatched finalized transaction was accepted")
	}
}

func TestChainAuthorityReadinessFailsClosed(t *testing.T) {
	runtime := &testChainAuthorityRuntime{readyErr: errors.New("no quorum")}
	authority, err := newTestChainAuthority(runtime, new(testChainActionPublisher), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	if err := authority.CheckReady(context.Background()); err == nil {
		t.Fatal("unready chain Authority was accepted")
	}
}

func TestChainAuthorityActionIDBindsStableSemanticsButNotRetryWindow(t *testing.T) {
	now := time.Unix(1_800_000_001, 0).UTC()
	clock := now
	runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
		Network: "tos-test", ObservedMasterSeqno: 700,
		ObservedAt: now, QuorumEndpoints: 2,
	}}
	publisher := new(testChainActionPublisher)
	authority, err := newTestChainAuthority(runtime, publisher, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	for attempt := range 2 {
		if _, err := authority.Commit(
			context.Background(), "quote", "quote-test",
			"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(time.Duration(attempt+1) * time.Second)
	}
	if len(publisher.actions) != 2 || publisher.actions[0].ActionID != publisher.actions[1].ActionID ||
		publisher.actions[0].Comment != publisher.actions[1].Comment ||
		publisher.actions[0].ExpiresUnixMillis == publisher.actions[1].ExpiresUnixMillis {
		t.Fatalf("retry did not preserve stable identity while refreshing expiry: %#v", publisher.actions)
	}
	concrete := authority.(*chainAuthority)
	original := concrete.anchorAction(
		"quote", "quote-test",
		"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		now,
	)
	concrete.anchorAmountNano++
	changed := concrete.anchorAction(
		"quote", "quote-test",
		"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		now,
	)
	if original.ActionID == changed.ActionID || original.Comment == changed.Comment {
		t.Fatal("action identity did not bind anchor economics")
	}
}

func TestChainAuthorityKeepsManagedEconomicTransitionsLocal(t *testing.T) {
	now := time.Unix(1_800_000_001, 0).UTC()
	runtime := &testChainAuthorityRuntime{readiness: toschain.ReadinessSnapshot{
		Network: "tos-test", ObservedMasterSeqno: 700,
		ObservedAt: now, QuorumEndpoints: 2,
	}}
	publisher := new(testChainActionPublisher)
	authority, err := newTestChainAuthority(runtime, publisher, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	defer authority.Close()
	runtime.readyErr = errors.New("chain observers unavailable after startup")
	for _, kind := range []string{"escrow", "escrow-release", "settlement"} {
		ref, err := authority.Commit(
			context.Background(), kind, "managed-object",
			"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
		)
		if err != nil {
			t.Fatal(err)
		}
		if ref.Network != "tos-local" || !strings.HasPrefix(ref.Reference, "atosrpc:"+kind+":") {
			t.Fatalf("managed economic transition claimed a chain reference: network=%q reference=%q", ref.Network, ref.Reference)
		}
	}
	if len(publisher.actions) != 0 {
		t.Fatalf("managed economic transitions were published as TOS anchors: %d", len(publisher.actions))
	}
}

func newTestChainAuthority(
	runtime chainAuthorityRuntime,
	publisher chain.ActionPublisher,
	now func() time.Time,
) (Authority, error) {
	return newChainAuthority(
		runtime,
		authorization.Reference{
			Network:   "tos-test",
			Address:   "0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ServiceID: "service-test",
		},
		publisher, testChainPayer, testChainPayee, 1,
		time.Second, time.Minute, now,
	)
}
