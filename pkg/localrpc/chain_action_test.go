package localrpc

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

func TestChainActionPublisherClientPublishesExactRequest(t *testing.T) {
	action := testChainAction()
	var calls int
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json; charset=utf-8")
			switch {
			case request.Method == http.MethodGet && request.URL.Path == ChainActionHealthPath:
				_ = json.NewEncoder(writer).Encode(chainActionHealth{
					Status: "ready", Version: chain.ChainActionVersion,
					Network: action.Network, PublishPath: ChainActionPath, ResolvePath: ChainActionResolvePath, JournalVersion: "1", Capabilities: []string{"durable_intent_before_publish", "typed_action_not_found", "read_only_resolve"},
				})
			case request.Method == http.MethodPost && request.URL.Path == ChainActionPath:
				var got chain.Action
				if err := json.NewDecoder(request.Body).Decode(&got); err != nil || got != action {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				calls++
				_ = json.NewEncoder(writer).Encode(chain.ActionReceipt{
					Version: got.Version, ActionID: got.ActionID,
					Network: got.Network, Kind: got.Kind, ObjectID: got.ObjectID,
					Digest: got.Digest, Reference: "tos:tx:v1:0:" + repeatHex("ab", 32) + ":1:" + repeatHex("cd", 32),
					Payer: got.Payer, Payee: got.Payee,
					AmountNanoTOS: got.AmountNanoTOS, Comment: got.Comment,
				})
			default:
				writer.WriteHeader(http.StatusNotFound)
			}
		},
	))
	defer stop()
	client, err := NewChainActionPublisherClient(
		DefaultChainActionPublisherClientConfig(socketPath, action.Network),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.CheckReady(context.Background()); err != nil {
		t.Fatal(err)
	}
	receipt, err := client.Publish(context.Background(), action)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ActionID != action.ActionID || calls != 1 {
		t.Fatalf("unexpected publish result: receipt=%#v calls=%d", receipt, calls)
	}
}

func TestChainActionPublisherClientRejectsChangedReceipt(t *testing.T) {
	action := testChainAction()
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			if request.Method != http.MethodPost || request.URL.Path != ChainActionPath {
				writer.WriteHeader(http.StatusNotFound)
				return
			}
			changed := chain.ActionReceipt{
				Version: action.Version, ActionID: action.ActionID,
				Network: action.Network, Kind: action.Kind, ObjectID: action.ObjectID,
				Digest: action.Digest, Reference: "tos:tx:v1:changed",
				Payer: action.Payer, Payee: action.Payee,
				AmountNanoTOS: action.AmountNanoTOS + 1, Comment: action.Comment,
			}
			_ = json.NewEncoder(writer).Encode(changed)
		},
	))
	defer stop()
	client, err := NewChainActionPublisherClient(
		DefaultChainActionPublisherClientConfig(socketPath, action.Network),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Publish(context.Background(), action); err == nil {
		t.Fatal("publisher receipt that changed the amount was accepted")
	}
}

func TestChainActionPublisherClientResolvesWithoutPublishing(t *testing.T) {
	action := testChainAction()
	var resolveCalls, publishCalls int
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodPost && request.URL.Path == ChainActionResolvePath {
			resolveCalls++
			var got chain.Action
			if json.NewDecoder(request.Body).Decode(&got) != nil || got != action {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(writer).Encode(chain.ActionReceipt{Version: got.Version, ActionID: got.ActionID, Network: got.Network, Kind: got.Kind, ObjectID: got.ObjectID, Digest: got.Digest, Reference: "tos:tx:v1:0:" + repeatHex("ab", 32) + ":1:" + repeatHex("cd", 32), Payer: got.Payer, Payee: got.Payee, AmountNanoTOS: got.AmountNanoTOS, Comment: got.Comment})
			return
		}
		if request.URL.Path == ChainActionPath {
			publishCalls++
		}
		writer.WriteHeader(http.StatusNotFound)
	}))
	defer stop()
	client, err := NewChainActionPublisherClient(DefaultChainActionPublisherClientConfig(socketPath, action.Network))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	receipt, found, err := client.Resolve(context.Background(), action)
	if err != nil || !found || receipt.ActionID != action.ActionID || resolveCalls != 1 || publishCalls != 0 {
		t.Fatalf("receipt=%+v found=%v resolve=%d publish=%d err=%v", receipt, found, resolveCalls, publishCalls, err)
	}
}

func TestChainActionPublisherClientRejectsGeneric404(t *testing.T) {
	action := testChainAction()
	socketPath, stop := startReceiptSignerHTTPServer(t, http.NotFoundHandler())
	defer stop()
	client, err := NewChainActionPublisherClient(DefaultChainActionPublisherClientConfig(socketPath, action.Network))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, found, err := client.Resolve(context.Background(), action); err == nil || found {
		t.Fatalf("generic 404 found=%v err=%v", found, err)
	}
}

func TestChainActionPublisherClientRejectsWrongReadinessNetwork(t *testing.T) {
	action := testChainAction()
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(chainActionHealth{
				Status: "ready", Version: chain.ChainActionVersion,
				Network: "other-network", PublishPath: ChainActionPath, ResolvePath: ChainActionResolvePath, JournalVersion: "1", Capabilities: []string{"durable_intent_before_publish", "typed_action_not_found", "read_only_resolve"},
			})
		},
	))
	defer stop()
	client, err := NewChainActionPublisherClient(
		DefaultChainActionPublisherClientConfig(socketPath, action.Network),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if err := client.CheckReady(context.Background()); err == nil {
		t.Fatal("publisher readiness for another network was accepted")
	}
}

func testChainAction() chain.Action {
	return chain.Action{
		Version:  chain.ChainActionVersion,
		ActionID: "anchor-" + repeatHex("11", 32), Network: "tos-test",
		Kind: chain.ActionKindAnchor, ObjectID: "capability@example@1",
		Digest: "sha256:" + repeatHex("22", 32),
		Payer:  "0:" + repeatHex("33", 32), Payee: "0:" + repeatHex("44", 32),
		AmountNanoTOS: 1, Comment: "atos:v1:" + repeatHex("55", 32),
		ExpiresUnixMillis: time.Now().Add(time.Minute).UnixMilli(),
	}
}

func repeatHex(pair string, count int) string {
	result := ""
	for range count {
		result += pair
	}
	return result
}
