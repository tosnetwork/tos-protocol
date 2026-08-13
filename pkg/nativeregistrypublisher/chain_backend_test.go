package nativeregistrypublisher

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type anchorResolverStub struct{ observations []AnchorObservation }

func (*anchorResolverStub) CheckReady(context.Context) error { return nil }
func (*anchorResolverStub) EnrollmentBinding() string        { return "sha256:resolver" }
func (*anchorResolverStub) Head(context.Context) (nativeregistry.FinalizedHead, error) {
	return nativeregistry.FinalizedHead{}, errors.New("unavailable")
}
func (*anchorResolverStub) ResolveAction(context.Context, string) (nativeregistry.Result, error) {
	return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
}
func (*anchorResolverStub) ResolveState(context.Context, string, string) (nativeregistry.Result, error) {
	return nativeregistry.Result{}, nativeregistry.ErrCanonicalNotFound
}
func (r *anchorResolverStub) ObserveActionAnchor(context.Context, nativeregistry.Submission, nativeexecution.ContractIdentity) (AnchorObservation, error) {
	if len(r.observations) == 0 {
		return AnchorObservation{}, errors.New("unavailable")
	}
	v := r.observations[0]
	if len(r.observations) > 1 {
		r.observations = r.observations[1:]
	}
	return v, nil
}

type contractSenderStub struct{ calls, prepareCalls int }

func (*contractSenderStub) CheckContractCellReady(context.Context) error { return nil }
func (*contractSenderStub) EnrollmentBinding() string                    { return "sha256:sender" }
func (*contractSenderStub) PayerIdentity() string                        { return "0:" + string(make([]byte, 64)) }
func (s *contractSenderStub) PrepareContractCell(context.Context, string, uint64, string, string) (string, string, error) {
	s.prepareCalls++
	return "Ym9j", "sha256:prepared", nil
}

func TestChainBackendRejectsUnvalidatedDirectSocketEnvelopeBeforeSpending(t *testing.T) {
	submission := validPublisherSubmission(t) // portable action is valid; TVM execution is intentionally absent
	code := cell.BeginCell().MustStoreUInt(1, 1).EndCell()
	codeHash := "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
	locator, err := nativeexecution.NewObjectLocator(submission.Action.Network, 0, base64.StdEncoding.EncodeToString(code.ToBOC()), codeHash)
	if err != nil {
		t.Fatal(err)
	}
	resolver := &anchorResolverStub{}
	sender := &contractSenderStub{}
	backend, err := NewChainBackend(locator, resolver, sender, MinimumFundingNanoTOS, time.Second, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Prepare(context.Background(), submission); err == nil {
		t.Fatal("direct publisher request bypassed full authority validation")
	}
	if sender.prepareCalls != 0 || sender.calls != 0 {
		t.Fatalf("invalid direct request reached key custody: prepare=%d broadcast=%d", sender.prepareCalls, sender.calls)
	}
}
func (s *contractSenderStub) BroadcastPreparedContractCell(context.Context, string, string) error {
	s.calls++
	return nil
}

func TestChainBackendBroadcastsOnlyAfterCanonicalAbsence(t *testing.T) {
	// Locator/execution construction is covered in nativeexecution; this
	// control proves an unavailable/pending observation cannot reach sender.
	resolver := &anchorResolverStub{observations: []AnchorObservation{{Found: true, Completed: false}}}
	sender := &contractSenderStub{}
	backend := &ChainBackend{resolver: resolver, sender: sender, poll: time.Millisecond, timeout: time.Millisecond, binding: "x"}
	if _, err := backend.Publish(context.Background(), nativeregistry.Submission{}, PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: "Ym9j", MessageDigest: "sha256:prepared"}, true); err == nil {
		t.Fatal("pending anchor accepted")
	}
	if sender.calls != 0 {
		t.Fatalf("pending anchor caused %d broadcasts", sender.calls)
	}
}

func TestChainBackendRejectsFundingWithoutForwardFeeMargin(t *testing.T) {
	resolver := &anchorResolverStub{}
	sender := &contractSenderStub{}
	locator := &nativeexecution.ObjectLocator{}
	if _, err := NewChainBackend(locator, resolver, sender, MinimumFundingNanoTOS-1, time.Second, time.Second); err == nil {
		t.Fatal("funding below the frozen Anchor fee margin was accepted")
	}
}
