package chainactionpublisher_test

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
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

func (*backend) CheckReady(context.Context) error { return nil }
func (*backend) Close() error                     { return nil }
func (b *backend) Publish(_ context.Context, a chain.Action, recovering bool) (chain.ActionReceipt, error) {
	b.calls++
	if b.lose && !recovering {
		return chain.ActionReceipt{}, errors.New("lost response after broadcast")
	}
	return receipt(a), nil
}
func receipt(a chain.Action) chain.ActionReceipt {
	return chain.ActionReceipt{Version: a.Version, ActionID: a.ActionID, Network: a.Network, Kind: a.Kind, ObjectID: a.ObjectID, Digest: a.Digest, Reference: "tos:tx:v1:0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Payer: a.Payer, Payee: a.Payee, AmountNanoTOS: a.AmountNanoTOS, Comment: a.Comment}
}
func action() chain.Action {
	return chain.Action{Version: "1", ActionID: "anchor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Network: "tos-test", Kind: chain.ActionKindAnchor, ObjectID: "quote-1", Digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Payer: "0:1111111111111111111111111111111111111111111111111111111111111111", Payee: "0:2222222222222222222222222222222222222222222222222222222222222222", AmountNanoTOS: 1, Comment: "atos:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ExpiresUnixMillis: 4_000_000_000_000}
}

func start(t *testing.T, state, socket string, b *backend) (*chainactionpublisher.Server, *localrpc.ChainActionPublisherClient) {
	t.Helper()
	s, err := chainactionpublisher.Open(chainactionpublisher.Config{Network: "tos-test", StatePath: state, Backend: b})
	if err != nil {
		t.Fatal(err)
	}
	l, err := receiptsigner.ListenPrivateUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: s.Handler()}
	go httpServer.Serve(l)
	c, err := localrpc.NewChainActionPublisherClient(localrpc.DefaultChainActionPublisherClientConfig(socket, "tos-test"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); httpServer.Close(); l.Close(); os.Remove(socket) })
	return s, c
}

func TestRealServerTypedAbsenceAndDurableCrashRecovery(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "journal.db")
	b := &backend{lose: true}
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
