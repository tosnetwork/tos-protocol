package chainactionpublisher_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/chainactionpublisher"
	"github.com/tosnetwork/tos-protocol/pkg/localrpc"
	"github.com/tosnetwork/tos-protocol/pkg/receiptsigner"
)

type backend struct {
	calls int
	lose  bool
}

func (*backend) CheckReady(context.Context) (chainactionpublisher.BackendCapabilities, error) {
	return chainactionpublisher.BackendCapabilities{Version: "1", Network: "tos-test", RecoverByActionID: true, SearchBeforeBroadcast: true}, nil
}
func (*backend) EnrollmentBinding() string { return "sha256:test-backend-binding" }

type substitutedBackend struct{ backend }

func (*substitutedBackend) EnrollmentBinding() string { return "sha256:substituted-backend-binding" }
func (*backend) Close() error                         { return nil }
func (b *backend) Publish(_ context.Context, a chain.Action, recovering bool) (chain.ActionReceipt, error) {
	b.calls++
	if b.lose && !recovering {
		return chain.ActionReceipt{}, errors.New("lost response after broadcast")
	}
	return chain.ActionReceipt{Version: a.Version, ActionID: a.ActionID, Network: a.Network, Kind: a.Kind, CommitmentKind: a.CommitmentKind, ObjectID: a.ObjectID, Digest: a.Digest, Reference: "tos:tx:v1:0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payer: a.Payer, Payee: a.Payee, AmountNanoTOS: a.AmountNanoTOS, Comment: a.Comment}, nil
}
func policy() chainactionpublisher.SpendingPolicy {
	return chainactionpublisher.SpendingPolicy{ServiceAddress: "0:3333333333333333333333333333333333333333333333333333333333333333", ServiceID: "service-test", Payer: "0:1111111111111111111111111111111111111111111111111111111111111111", Payee: "0:2222222222222222222222222222222222222222222222222222222222222222", AmountNanoTOS: 1}
}
func action() chain.Action {
	a := chain.Action{Version: "1", Network: "tos-test", Kind: chain.ActionKindAnchor, CommitmentKind: "quote", ObjectID: "quote-1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payer: policy().Payer, Payee: policy().Payee, AmountNanoTOS: 1, ExpiresUnixMillis: 4_000_000_000_000}
	h := sha256.New()
	for _, v := range []string{"ATOS-TOS-CHAIN-AUTHORITY-V1", "1", a.Network, policy().ServiceAddress, policy().ServiceID, "anchor", a.CommitmentKind, a.ObjectID, a.Digest, a.Payer, a.Payee, strconv.FormatUint(a.AmountNanoTOS, 10)} {
		_, _ = h.Write([]byte(v))
		_, _ = h.Write([]byte{0})
	}
	d := hex.EncodeToString(h.Sum(nil))
	a.ActionID, a.Comment = "anchor-"+d, "atos:v1:"+d
	return a
}
func start(t *testing.T, state, socket string, b *backend) (*chainactionpublisher.Server, *localrpc.ChainActionPublisherClient) {
	t.Helper()
	s, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: "tos-test", StatePath: state, JournalIdentity: "test-journal", Policy: policy(), Backend: b})
	if err != nil {
		t.Fatal(err)
	}
	l, err := receiptsigner.ListenPrivateUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: s.Handler()}
	go func() { _ = httpServer.Serve(l) }()
	c, err := localrpc.NewChainActionPublisherClient(localrpc.DefaultChainActionPublisherClientConfig(socket, "tos-test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(); _ = httpServer.Close(); _ = l.Close(); _ = os.Remove(socket) })
	return s, c
}
func TestRealServerTypedAbsenceAndDurableCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "journal.db")
	b := &backend{lose: true}
	if err := chainactionpublisher.InitializeJournal(state, "test-journal", "tos-test", policy(), b.EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	s, c := start(t, state, filepath.Join(dir, "one.sock"), b)
	if err := c.CheckReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.Resolve(context.Background(), action()); err != nil || found {
		t.Fatalf("typed absence found=%v err=%v", found, err)
	}
	if _, err := c.Publish(context.Background(), action()); err == nil {
		t.Fatal("expected lost response")
	}
	if _, found, err := c.Resolve(context.Background(), action()); err == nil || found {
		t.Fatalf("pending journal was reported absent: found=%v err=%v", found, err)
	}
	_ = c.Close()
	_ = s.Close()
	s2, c2 := start(t, state, filepath.Join(dir, "two.sock"), b)
	defer s2.Close()
	got, err := c2.Publish(context.Background(), action())
	if err != nil {
		t.Fatal(err)
	}
	resolved, found, err := c2.Resolve(context.Background(), action())
	if err != nil || !found || resolved.Reference != got.Reference || b.calls != 2 {
		t.Fatalf("resolved=%+v found=%v calls=%d err=%v", resolved, found, b.calls, err)
	}
}
func TestMissingOrSubstitutedJournalFailsClosed(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	path := filepath.Join(dir, "journal.db")
	if _, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: "tos-test", StatePath: path, JournalIdentity: "enrolled", Policy: policy(), Backend: &backend{}}); err == nil {
		t.Fatal("missing journal started")
	}
	if err := chainactionpublisher.InitializeJournal(path, "enrolled", "tos-test", policy(), (&backend{}).EnrollmentBinding()); err != nil {
		t.Fatal(err)
	}
	if _, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: "tos-test", StatePath: path, JournalIdentity: "other", Policy: policy(), Backend: &backend{}}); err == nil {
		t.Fatal("substituted journal started")
	}
	if _, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: "tos-test", StatePath: path, JournalIdentity: "enrolled", Policy: policy(), Backend: &substitutedBackend{}}); err == nil {
		t.Fatal("journal accepted substituted executable/config/backend enrollment")
	}
}
func TestSpendingPolicyRejectsSubstitution(t *testing.T) {
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o700)
	state := filepath.Join(dir, "journal.db")
	b := &backend{}
	_ = chainactionpublisher.InitializeJournal(state, "test-journal", "tos-test", policy(), b.EnrollmentBinding())
	s, c := start(t, state, filepath.Join(dir, "policy.sock"), b)
	defer s.Close()
	for _, mutate := range []func(*chain.Action){func(a *chain.Action) { a.Payee = a.Payer }, func(a *chain.Action) { a.AmountNanoTOS++ }, func(a *chain.Action) { a.ActionID = "anchor-" + string(make([]byte, 64)) }} {
		a := action()
		mutate(&a)
		if _, err := c.Publish(context.Background(), a); err == nil {
			t.Fatal("substituted spend accepted")
		}
	}
	if b.calls != 0 {
		t.Fatalf("backend called %d times", b.calls)
	}
}
