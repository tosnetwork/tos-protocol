package toschain

import (
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestDecodeTaskEscrowDataAllowsAbsentAgentAndVerifier(t *testing.T) {
	creator := address.MustParseRawAddr("0:" + strings.Repeat("11", 32))
	permission := cell.BeginCell().
		MustStoreSlice(make([]byte, 32), 256).
		MustStoreSlice(make([]byte, 32), 256).
		EndCell()
	attestor := cell.BeginCell().
		MustStoreBoolBit(false).
		MustStoreSlice(make([]byte, 32), 256).
		EndCell()
	hashes := cell.BeginCell().
		MustStoreSlice(make([]byte, 32), 256).
		MustStoreSlice(make([]byte, 32), 256).
		MustStoreSlice([]byte(strings.Repeat("\x22", 32)), 256).
		MustStoreUInt(3600, 32).
		MustStoreUInt(0, 64).
		MustStoreRef(permission).
		MustStoreRef(attestor).
		EndCell()
	root := cell.BeginCell().
		MustStoreAddr(creator).
		MustStoreBoolBit(false).
		MustStoreAddr(address.NewAddressNone()).
		MustStoreBoolBit(false).
		MustStoreAddr(address.NewAddressNone()).
		MustStoreCoins(1_000).
		MustStoreUInt(1_800_000_000, 64).
		MustStoreUInt(uint64(chain.TaskEscrowStatusOpen), 8).
		MustStoreRef(hashes).
		EndCell()
	state, err := decodeTaskEscrowData(
		root, "0:"+strings.Repeat("44", 32), 1_050,
		"tvm-cell-sha256:"+strings.Repeat("aa", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	if state.HasAgent || state.Agent != "" || state.HasVerifier || state.Verifier != "" {
		t.Fatalf("absent parties were not decoded canonically: %#v", state)
	}
	if state.Creator != creator.StringRaw() || state.BudgetNanoTOS != 1_000 ||
		state.BalanceNanoTOS != 1_050 || state.ReviewPeriod != 3600 {
		t.Fatalf("unexpected Task Escrow state: %#v", state)
	}
}

func TestTaskEscrowReferenceRoundTrip(t *testing.T) {
	addressValue := "0:" + strings.Repeat("44", 32)
	reference, err := FormatTaskEscrowReference(addressValue)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTaskEscrowReference(reference)
	if err != nil {
		t.Fatal(err)
	}
	if parsed != addressValue {
		t.Fatalf("reference round trip mismatch: got %q", parsed)
	}
}
