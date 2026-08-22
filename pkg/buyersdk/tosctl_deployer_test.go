package buyersdk

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type deployRunnerFake struct {
	purchase *PreparedPurchase
	deployer *TOSCTLEscrowDeployer
	conflict bool
	calls    [][]string
}

func (f *deployRunnerFake) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string(nil), args...))
	message := cell.BeginCell().EndCell()
	if len(f.calls) == 1 {
		_, stateHash, _ := decodeStateInit(f.purchase.Escrow.StateInitBOC)
		if f.conflict {
			stateHash = "tvm-cell-sha256:" + strings.Repeat("a", 64)
		}
		return json.Marshal(map[string]any{
			"version": "tosctl.wallet-prepared-send.v1", "message_boc_base64": base64BOC(message),
			"wallet": f.deployer.wallet, "payer": f.deployer.buyer,
			"destination": f.purchase.Escrow.Address, "amount_nanotos": f.deployer.attached,
			"body_hash": cellHash(cell.BeginCell().EndCell()), "state_init_hash": stateHash,
		})
	}
	return json.Marshal(map[string]any{"version": "tosctl.wallet-prepared-broadcast.v1",
		"message_hash": cellHash(message), "status": "submitted"})
}

func testPreparedDeployment(t *testing.T) (*TOSCTLEscrowDeployer, *PreparedPurchase) {
	t.Helper()
	fixture := newBuyerFixture(t, BudgetLimits{Window: time.Hour, MaxPurchases: 2,
		MaxPerPurchaseAtomic: "100", MaxTotalAtomic: "200"})
	purchase, err := fixture.buyer.PreparePurchase(context.Background(), fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	sender := testTOSCTLSender(t)
	deployer, err := NewTOSCTLEscrowDeployer(TOSCTLEscrowDeployerConfig{
		BinaryPath: sender.binary, ConfigPath: sender.config, WalletName: sender.wallet,
		BuyerAddress: fixture.input.EscrowTerms.BuyerAddress, Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return deployer, purchase
}

func TestTOSCTLEscrowDeployerPreparesThenBroadcastsExactMessage(t *testing.T) {
	deployer, purchase := testPreparedDeployment(t)
	fake := &deployRunnerFake{purchase: purchase, deployer: deployer}
	deployer.runner = fake
	prepared, err := deployer.PrepareEscrowDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.EscrowAddress != purchase.Escrow.Address || prepared.QuoteCommitment != purchase.QuoteCommitment ||
		prepared.StateInitBOCBase64 != purchase.Escrow.StateInitBOC {
		t.Fatalf("prepared deployment = %+v", prepared)
	}
	if err := deployer.BroadcastEscrowDeployment(context.Background(), prepared); err != nil {
		t.Fatal(err)
	}
	if len(fake.calls) != 2 || fake.calls[0][len(fake.calls[0])-1] != "--build-only" ||
		fake.calls[1][1] != "broadcast-prepared" || fake.calls[1][len(fake.calls[1])-1] != "--yes" {
		t.Fatalf("calls = %v", fake.calls)
	}
}

func TestTOSCTLEscrowDeployerRejectsCustodyAndArtifactSubstitution(t *testing.T) {
	deployer, purchase := testPreparedDeployment(t)
	fake := &deployRunnerFake{purchase: purchase, deployer: deployer, conflict: true}
	deployer.runner = fake
	if _, err := deployer.PrepareEscrowDeployment(context.Background(), purchase); err == nil {
		t.Fatal("deployer accepted a substituted StateInit hash from custody")
	}
	fake.conflict = false
	fake.calls = nil
	prepared, err := deployer.PrepareEscrowDeployment(context.Background(), purchase)
	if err != nil {
		t.Fatal(err)
	}
	prepared.EscrowAddress = "0:" + strings.Repeat("f", 64)
	if err := deployer.BroadcastEscrowDeployment(context.Background(), prepared); err == nil {
		t.Fatal("deployer broadcast a substituted deployment artifact")
	}
}

func base64BOC(value *cell.Cell) string {
	return base64.StdEncoding.EncodeToString(value.ToBOC())
}
