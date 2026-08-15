package buyersdk

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type senderRunnerFake struct {
	intent   FundingIntent
	wallet   string
	attached uint64
	bodyHash string
	calls    [][]string
	conflict bool
}

func (f *senderRunnerFake) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	if len(f.calls) == 1 {
		destination := f.intent.BuyerWallet
		if f.conflict {
			destination = "0:" + strings.Repeat("ab", 32)
		}
		return json.Marshal(map[string]any{
			"version": "tosctl.wallet-prepared-send.v1", "message_boc_base64": "te6ccgEBAQEAAgAAAA==",
			"wallet": f.wallet, "payer": f.intent.BuyerAddress, "destination": destination,
			"amount_nanotos": f.attached, "body_hash": f.bodyHash, "state_init_hash": "",
		})
	}
	message, _ := cell.FromBOC([]byte{0xb5, 0xee, 0x9c, 0x72, 0x01, 0x01, 0x01, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00})
	return json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-broadcast.v1",
		"message_hash": bodyHash(message), "status": "submitted"})
}

func TestBuildStablecoinFundingBodyUsesExactJettonTransferShape(t *testing.T) {
	intent := senderIntent()
	body, err := BuildStablecoinFundingBody(intent, 50_000_000)
	if err != nil {
		t.Fatal(err)
	}
	s := body.BeginParse()
	op, err := s.LoadUInt(32)
	if err != nil || op != stablecoinTransferOpcode {
		t.Fatal("wrong stablecoin transfer opcode")
	}
	query, _ := s.LoadUInt(64)
	amount, _ := s.LoadBigCoins()
	recipient, _ := s.LoadAddr()
	response, _ := s.LoadAddr()
	custom, _ := s.LoadBoolBit()
	forward, _ := s.LoadCoins()
	payload, _ := s.LoadBoolBit()
	if query != intent.QueryID || amount.String() != intent.AmountAtomic || recipient.StringRaw() != intent.EscrowAddress ||
		response.StringRaw() != intent.BuyerAddress || custom || forward != 50_000_000 || payload ||
		s.BitsLeft() != 0 || s.RefsNum() != 0 {
		t.Fatal("stablecoin funding body does not match the canonical transfer shape")
	}
}

func TestTOSCTLSenderVerifiesPreparedMessageBeforeBroadcast(t *testing.T) {
	sender := testTOSCTLSender(t)
	intent := senderIntent()
	body, _ := BuildStablecoinFundingBody(intent, sender.forward)
	fake := &senderRunnerFake{intent: intent, wallet: sender.wallet, attached: sender.attached,
		bodyHash: "tvm-cell-sha256:" + strings.ToLower(strings.TrimPrefix(bodyHash(body), "tvm-cell-sha256:"))}
	sender.runner = fake
	prepared, err := sender.PrepareStablecoinFunding(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.BroadcastStablecoinFunding(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0][len(fake.calls[0])-1] != "--build-only" ||
		fake.calls[1][0] != "wallet" || fake.calls[1][3] != "broadcast-prepared" ||
		fake.calls[1][len(fake.calls[1])-1] != "--yes" {
		t.Fatal("tosctl sender did not prepare then broadcast the exact message")
	}
}

func TestTOSCTLSenderRejectsConflictingCustodyOutput(t *testing.T) {
	sender := testTOSCTLSender(t)
	intent := senderIntent()
	body, _ := BuildStablecoinFundingBody(intent, sender.forward)
	fake := &senderRunnerFake{intent: intent, wallet: sender.wallet, attached: sender.attached,
		bodyHash: bodyHash(body), conflict: true}
	sender.runner = fake
	if _, err := sender.PrepareStablecoinFunding(context.Background(), intent); err == nil {
		t.Fatal("conflicting tosctl prepared message was broadcast")
	}
	if len(fake.calls) != 1 {
		t.Fatal("conflicting custody output reached broadcast")
	}
}

func testTOSCTLSender(t *testing.T) *TOSCTLFundingSender {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "tosctl")
	config := filepath.Join(dir, "tosctl-config.json")
	if err := os.WriteFile(binary, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sender, err := NewTOSCTLFundingSender(TOSCTLFundingSenderConfig{
		BinaryPath: binary, ConfigPath: config, WalletName: "buyer", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return sender
}

func senderIntent() FundingIntent {
	return FundingIntent{
		NetworkID: "test", EscrowAddress: "0:" + strings.Repeat("11", 32),
		QuoteCommitment: "tvm-cell-sha256:" + strings.Repeat("22", 32),
		Asset: &nativev1.TOSAssetIdentityV1{Master: &nativev1.TOSContractIdentityV1{
			Workchain: 0, AccountId: []byte(strings.Repeat("3", 32)),
			CodeHash: "tvm-cell-sha256:" + strings.Repeat("44", 32),
		}, WalletCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32), Decimals: 6},
		BuyerAddress: "0:" + strings.Repeat("66", 32), BuyerWallet: "0:" + strings.Repeat("77", 32),
		AmountAtomic: "25000000", QueryID: 42,
	}
}

func bodyHash(body *cell.Cell) string {
	return "tvm-cell-sha256:" + fmt.Sprintf("%x", body.Hash())
}
