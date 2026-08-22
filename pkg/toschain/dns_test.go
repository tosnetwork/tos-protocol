package toschain

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func dnsStackCell(t *testing.T, kind string, value *cell.Cell) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal([]any{kind, map[string]string{"bytes": base64.StdEncoding.EncodeToString(value.ToBOC())}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func dnsStackNum(t *testing.T, value string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal([]any{"num", value})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestDNSRecordParsersAreExact(t *testing.T) {
	addr := address.MustParseRawAddr("0:" + strings.Repeat("11", 32))
	next := cell.BeginCell().MustStoreUInt(0xba93, 16).MustStoreAddr(addr).EndCell()
	if got, err := parseNextResolver(next); err != nil || got != addr.StringRaw() {
		t.Fatalf("next resolver = %q, %v", got, err)
	}
	smc := cell.BeginCell().MustStoreUInt(0x9fd3, 16).MustStoreAddr(addr).MustStoreUInt(0, 8).EndCell()
	if got, err := parseSMCRecord(smc); err != nil || got != addr.StringRaw() {
		t.Fatalf("SMC record = %q, %v", got, err)
	}

	for _, malformed := range []*cell.Cell{
		cell.BeginCell().MustStoreUInt(0xba92, 16).MustStoreAddr(addr).EndCell(),
		cell.BeginCell().MustStoreUInt(0xba93, 16).MustStoreAddr(addr).MustStoreUInt(1, 1).EndCell(),
	} {
		if _, err := parseNextResolver(malformed); err == nil {
			t.Fatal("accepted malformed next-resolver record")
		}
	}
	for _, malformed := range []*cell.Cell{
		cell.BeginCell().MustStoreUInt(0x9fd2, 16).MustStoreAddr(addr).MustStoreUInt(0, 8).EndCell(),
		cell.BeginCell().MustStoreUInt(0x9fd3, 16).MustStoreAddr(addr).MustStoreUInt(2, 8).EndCell(),
		cell.BeginCell().MustStoreUInt(0x9fd3, 16).MustStoreAddr(addr).MustStoreUInt(1, 8).EndCell(),
	} {
		if _, err := parseSMCRecord(malformed); err == nil {
			t.Fatal("accepted malformed SMC record")
		}
	}
}

func TestDNSStackParsingRejectsAmbiguity(t *testing.T) {
	value := cell.BeginCell().MustStoreUInt(7, 3).EndCell()
	stack := []json.RawMessage{dnsStackCell(t, "slice", value), json.RawMessage(`["null"]`)}
	parsed, nilValue, err := stackCell(stack, 0)
	if err != nil || nilValue || string(parsed.Hash()) != string(value.Hash()) {
		t.Fatalf("cell = %v, nil=%v, err=%v", parsed, nilValue, err)
	}
	if parsed, nilValue, err = stackCell(stack, 1); err != nil || !nilValue || parsed != nil {
		t.Fatalf("null = %v, nil=%v, err=%v", parsed, nilValue, err)
	}
	for _, raw := range []json.RawMessage{
		json.RawMessage(`["null",{}]`),
		json.RawMessage(`["unsupported"]`),
		json.RawMessage(`["cell",{"bytes":"not-base64"}]`),
		json.RawMessage(`["cell",{"bytes":"te6ccgEBAQEAAgAAAA=="},"extra"]`),
	} {
		if _, _, err := stackCell([]json.RawMessage{raw}, 0); err == nil {
			t.Fatalf("accepted ambiguous stack entry %s", raw)
		}
	}
}

func TestDNSHTTPStackIsTopFirst(t *testing.T) {
	value := cell.BeginCell().MustStoreUInt(0xba93, 16).EndCell()
	// FunC dnsresolve returns (consumed_bits, value), while runGetMethod JSON is
	// [value, consumed_bits]. Keep this fixture transport-shaped so an accidental
	// copy of the bottom-first toslib indices fails loudly.
	stack := []json.RawMessage{dnsStackCell(t, "cell", value), dnsStackNum(t, "32")}
	gotCell, nilValue, err := stackCell(stack, 0)
	if err != nil || nilValue || string(gotCell.Hash()) != string(value.Hash()) {
		t.Fatalf("top cell = %v, nil=%v, err=%v", gotCell, nilValue, err)
	}
	gotBits, err := stackInt(stack, 1)
	if err != nil || gotBits.Uint64() != 32 {
		t.Fatalf("bottom consumed bits = %v, %v", gotBits, err)
	}
	// The same rule fixes get_nft_data and get_auction_info indices.
	identity := []json.RawMessage{
		dnsStackCell(t, "cell", value), dnsStackCell(t, "slice", value),
		dnsStackCell(t, "slice", value), dnsStackNum(t, "99"), dnsStackNum(t, "-1"),
	}
	if index, err := stackInt(identity, 3); err != nil || index.Uint64() != 99 {
		t.Fatalf("top-first NFT index = %v, %v", index, err)
	}
	auction := []json.RawMessage{dnsStackNum(t, "123"), dnsStackNum(t, "7"), dnsStackCell(t, "slice", value)}
	if end, err := stackInt(auction, 0); err != nil || end.Uint64() != 123 {
		t.Fatalf("top-first auction end = %v, %v", end, err)
	}
}

func TestDNSCheckpointBindsFullBlockIdentity(t *testing.T) {
	id := blockID{Type: "tos.blockIdExt", Workchain: -1, Shard: "-9223372036854775808", Seqno: 42,
		RootHash: base64.StdEncoding.EncodeToString(make([]byte, 32)), FileHash: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	checkpoint, err := checkpointFromBlock(id, 1_700_000_000)
	if err != nil || !sameDNSBlock(checkpoint, id) {
		t.Fatalf("checkpoint = %#v, %v", checkpoint, err)
	}
	reorg := id
	reorg.FileHash = base64.StdEncoding.EncodeToString(append([]byte{1}, make([]byte, 31)...))
	if sameDNSBlock(checkpoint, reorg) {
		t.Fatal("same-height reorg accepted as the original checkpoint")
	}
	bad := id
	bad.Workchain = 0
	if _, err := checkpointFromBlock(bad, 1); err == nil {
		t.Fatal("non-masterchain DNS checkpoint accepted")
	}
}

func TestDNSQuorumRejectsMinorityValue(t *testing.T) {
	nodes := []*rpcNode{{}, {}, {}}
	values := map[*rpcNode]string{nodes[0]: "honest", nodes[1]: "honest", nodes[2]: "minority"}
	value, agreed, err := quorumRead(t.Context(), nodes, 2, func(_ context.Context, node *rpcNode) (string, error) {
		return values[node], nil
	})
	if err != nil || value != "honest" || len(agreed) != 2 {
		t.Fatalf("quorum = %q across %d nodes, %v", value, len(agreed), err)
	}
}

func TestSecondLevelLabel(t *testing.T) {
	for name, want := range map[string]string{"alice.tos": "alice", "translate.alice.tos": "alice"} {
		if got := secondLevelLabel(name); got != want {
			t.Fatalf("label(%q) = %q", name, got)
		}
	}
}

func TestDNSComponentBoundaryMatchesTONContracts(t *testing.T) {
	// Root consumes "tos" (3 bytes) and leaves the separator for Collection;
	// consuming the separator (4 bytes) is also a valid resolver boundary.
	query := []byte("tos\x00alice\x00")
	for _, consumed := range []int{3, 4, len(query)} {
		if !dnsComponentBoundary(consumed, query) {
			t.Fatalf("valid boundary %d rejected", consumed)
		}
	}
	if dnsComponentBoundary(2, query) {
		t.Fatal("inside-component boundary accepted")
	}
}
