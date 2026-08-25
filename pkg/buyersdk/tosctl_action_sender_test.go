package buyersdk

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type effectRunnerFake struct {
	sender *TOSCTLWalletActionSender
	intent WalletActionIntent
	calls  [][]string
}

func (fake *effectRunnerFake) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	fake.calls = append(fake.calls, append([]string(nil), args...))
	message := cell.BeginCell().MustStoreUInt(0x1234, 16).EndCell()
	if len(fake.calls) == 1 {
		authorizationPath := argumentAfter(args, "--authorization-file")
		raw, err := os.ReadFile(authorizationPath)
		if err != nil {
			return nil, err
		}
		var authorization commerce.CustodyEffectAuthorization
		if json.Unmarshal(raw, &authorization) != nil || authorization.StableActionID != fake.intent.StableActionID {
			return nil, context.Canceled
		}
		return json.Marshal(map[string]any{
			"schema": "tosctl.agent-account.economic-effect-prepared.v1", "stable_action_id": fake.intent.StableActionID,
			"action_kind": fake.intent.TransitionKind, "agreement_body_digest": fake.intent.Authorization.AgreementBodyDigest,
			"obligation_id": fake.intent.Authorization.ObligationID, "account": fake.intent.Authorization.SourceAccount,
			"target": fake.intent.Destination, "amount_nanotos": fake.intent.AmountNanoTOS, "body_hash": fake.intent.BodyHash,
			"controller_epoch": uint64(0), "seqno": uint32(1), "network_global_id": fake.intent.Authorization.NetworkGlobalID,
			"valid_until": fake.intent.ValidUntilUnix, "exact_signed_boc": base64BOC(message), "exact_signed_boc_digest": sha256Text(message.ToBOC()),
		})
	}
	return json.Marshal(map[string]any{"schema": "tosctl.agent-account.economic-effect-broadcast.v1",
		"stable_action_id": fake.intent.StableActionID, "action_kind": fake.intent.TransitionKind,
		"account":                 fake.intent.Authorization.SourceAccount,
		"exact_signed_boc_digest": sha256Text(message.ToBOC()), "state": "broadcasting"})
}

func TestTOSCTLEconomicEffectSenderPreservesExactAuthorizedBody(t *testing.T) {
	base := testTOSCTLSender(t)
	sender, err := NewTOSCTLWalletActionSender(TOSCTLWalletActionSenderConfig{BinaryPath: base.binary,
		ConfigPath: base.config, WalletName: base.wallet, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	body := cell.BeginCell().MustStoreUInt(0x4e450003, 32).MustStoreUInt(7, 64).EndCell()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x73}, ed25519.SeedSize))
	authorization, err := commerce.SignCustodyEffectAuthorization(commerce.CustodyEffectAuthorization{SchemaVersion: 1,
		AuthorityID: "authority:test", OwnerID: "owner:test", AgentID: "agent:buyer", SourceAccount: "0:" + strings.Repeat("1", 64),
		NetworkID: "tos:test", NetworkGlobalID: -3, ActionKind: "escrow.accept", StableActionID: "sha256:" + strings.Repeat("2", 64),
		ExactRequestDigest: "sha256:" + strings.Repeat("3", 64), WriterGeneration: 1, WriterFenceDigest: "sha256:" + strings.Repeat("4", 64),
		PolicyRevision: 1, MandateDigest: "sha256:" + strings.Repeat("5", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("6", 64), ObligationID: "payment:one", Destination: "0:" + strings.Repeat("7", 64),
		AmountNanoTOS: 100_000_000, BodyHash: cellHash(body), StateInitHashOrZero: "sha256:" + strings.Repeat("0", 64),
		ExpiresAtUnix: 2_000_000_100}, key)
	if err != nil {
		t.Fatal(err)
	}
	intent := WalletActionIntent{StableActionID: authorization.StableActionID, NetworkID: authorization.NetworkID,
		TransitionKind: authorization.ActionKind, Destination: authorization.Destination, AmountNanoTOS: authorization.AmountNanoTOS,
		BodyBOCBase64: base64BOC(body), BodyHash: authorization.BodyHash, ValidUntilUnix: 2_000_000_050, Authorization: authorization}
	fake := &effectRunnerFake{sender: sender, intent: intent}
	sender.runner = fake
	prepared, err := sender.PrepareWalletAction(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.BroadcastWalletAction(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0][0] != "agent" || fake.calls[0][2] != "economic-effect-prepare" ||
		fake.calls[1][2] != "economic-effect-broadcast" {
		t.Fatalf("calls=%v", fake.calls)
	}
	changed := intent
	changed.BodyHash = "tvm-cell-sha256:" + strings.Repeat("8", 64)
	if _, err := sender.PrepareWalletAction(context.Background(), changed); err == nil {
		t.Fatal("substituted effect body reached tosctl")
	}
}

func argumentAfter(args []string, name string) string {
	for index := range args {
		if args[index] == name && index+1 < len(args) {
			return args[index+1]
		}
	}
	return ""
}
