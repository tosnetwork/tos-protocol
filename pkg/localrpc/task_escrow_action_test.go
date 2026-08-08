package localrpc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
)

func TestTaskEscrowActionPublisherClientPublishesExactAction(t *testing.T) {
	action := testTaskEscrowAction(chain.TaskEscrowActionSettle)
	var calls int
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json; charset=utf-8")
			switch {
			case request.Method == http.MethodGet && request.URL.Path == TaskEscrowActionHealthPath:
				_ = json.NewEncoder(writer).Encode(taskEscrowActionHealth{
					Status: "ready", Version: chain.TaskEscrowActionVersion,
					Network: action.Network, Path: TaskEscrowActionPath,
				})
			case request.Method == http.MethodPost && request.URL.Path == TaskEscrowActionPath:
				var got chain.TaskEscrowAction
				if err := json.NewDecoder(request.Body).Decode(&got); err != nil || got != action {
					writer.WriteHeader(http.StatusBadRequest)
					return
				}
				calls++
				_ = json.NewEncoder(writer).Encode(chain.TaskEscrowActionReceipt{
					Version: got.Version, ActionID: got.ActionID, Network: got.Network,
					Kind: got.Kind, EscrowID: got.EscrowID,
					ContractAddress: got.ContractAddress,
					Reference:       "tos:tx:v1:0:" + strings.Repeat("44", 32) + ":1:" + strings.Repeat("55", 32),
				})
			default:
				writer.WriteHeader(http.StatusNotFound)
			}
		},
	))
	defer stop()
	client, err := NewTaskEscrowActionPublisherClient(
		DefaultTaskEscrowActionPublisherClientConfig(socketPath, action.Network),
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
		t.Fatalf("unexpected task escrow action result: receipt=%#v calls=%d", receipt, calls)
	}
}

func TestTaskEscrowActionPublisherRejectsChangedContract(t *testing.T) {
	action := testTaskEscrowAction(chain.TaskEscrowActionAccept)
	socketPath, stop := startReceiptSignerHTTPServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(chain.TaskEscrowActionReceipt{
				Version: action.Version, ActionID: action.ActionID, Network: action.Network,
				Kind: action.Kind, EscrowID: action.EscrowID,
				ContractAddress: "0:" + strings.Repeat("99", 32),
				Reference:       "tos:tx:v1:0:" + strings.Repeat("99", 32) + ":1:" + strings.Repeat("55", 32),
			})
		},
	))
	defer stop()
	client, err := NewTaskEscrowActionPublisherClient(
		DefaultTaskEscrowActionPublisherClientConfig(socketPath, action.Network),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if _, err := client.Publish(context.Background(), action); err == nil {
		t.Fatal("publisher contract substitution was accepted")
	}
}

func TestTaskEscrowActionRequiresOriginalBudget(t *testing.T) {
	action := testTaskEscrowAction(chain.TaskEscrowActionSettle)
	action.BudgetNanoTOS = 0
	if err := validateTaskEscrowAction(action, action.Network); err == nil {
		t.Fatal("operation without its original budget binding was accepted")
	}
}

func testTaskEscrowAction(kind chain.TaskEscrowActionKind) chain.TaskEscrowAction {
	return chain.TaskEscrowAction{
		Version:  chain.TaskEscrowActionVersion,
		ActionID: "task-action-" + strings.Repeat("11", 32),
		Network:  "tos-test", Kind: kind, EscrowID: "esc-test",
		ContractAddress: "0:" + strings.Repeat("44", 32),
		Creator:         "0:" + strings.Repeat("11", 32),
		Agent:           "0:" + strings.Repeat("22", 32),
		Verifier:        "0:" + strings.Repeat("33", 32),
		BudgetNanoTOS:   1_000, DeadlineUnix: uint64(time.Now().Add(time.Hour).Unix()),
		ReviewPeriod:   3600,
		PolicyHash:     "sha256:" + strings.Repeat("55", 32),
		PermissionHash: "sha256:" + strings.Repeat("66", 32),
		QueryID:        7, ResultHash: "sha256:" + strings.Repeat("77", 32),
		EvidenceHash:      "sha256:" + strings.Repeat("88", 32),
		PayoutNanoTOS:     100,
		ExpectedBodyHash:  "tvm-cell-sha256:" + strings.Repeat("99", 32),
		ExpiresUnixMillis: time.Now().Add(time.Minute).UnixMilli(),
	}
}
