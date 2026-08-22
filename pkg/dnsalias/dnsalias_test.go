package dnsalias

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type chainFake struct{ result *ChainResult }

func (f chainFake) ResolveDNSAtFinalizedCheckpoint(context.Context, string, string) (*ChainResult, error) {
	return f.result, nil
}

type nativeFake struct {
	states map[string]*nativev1.NativeStateV1
}

func (f nativeFake) ResolveNativeAtCheckpoint(_ context.Context, account string, _ *nativev1.DNSCheckpointV1) (*nativev1.NativeStateV1, bool, error) {
	state := f.states[account]
	return state, state != nil, nil
}

func TestTIP1CategoriesAndEncoding(t *testing.T) {
	tests := []struct {
		kind nativev1.DNSAliasKindV1
		hash string
	}{
		{nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT, "d4f0bc5a29de06b510f9aa428f1eedba926012b591fef7a518e776a7c9bd1824"},
		{nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY, "38a5be91af79d7e5ba9809bf383c699b6864ee50446239fe56a45e32b84638fe"},
		{nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_MESSENGER, "050f993ea2322d4b6940f8560a253a11709fdc5ab08fd994bceb096846ea1645"},
	}
	for _, test := range tests {
		_, got, err := Category(test.kind)
		if err != nil || got != test.hash {
			t.Fatalf("category %v = %q, %v", test.kind, got, err)
		}
	}
	encoded, err := EncodeName("translate.alice.tos")
	if err != nil || string(encoded) != "tos\x00alice\x00translate\x00" {
		t.Fatalf("encoding = %q, %v", encoded, err)
	}
	for _, invalid := range []string{"", ".tos", "alice.tos.", "Alice.tos", "alice//x.tos", "alice.example", strings.Repeat("a", 123) + ".tos"} {
		if _, err := CanonicalName(invalid); err == nil {
			t.Fatalf("accepted non-canonical name %q", invalid)
		}
	}
}

func TestTIP1CorpusIsConsumedWithoutSemanticCopies(t *testing.T) {
	raw, err := os.ReadFile("testdata/tip-1-dns-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Schema     string `json:"schema"`
		Categories map[string]struct {
			SHA256 string `json:"sha256"`
		} `json:"categories"`
		NameEncoding []struct {
			Input      string `json:"input"`
			EncodedHex string `json:"encoded_hex"`
			Result     string `json:"result"`
		} `json:"name_encoding"`
		Lifecycle struct {
			Renewal uint64 `json:"renewal_interval_seconds"`
		} `json:"lifecycle"`
		Resolver struct {
			MaximumContacts uint64 `json:"maximum_contacts"`
		} `json:"resolver_policy"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Schema != "tos.tip-1.dns-v1.v1" || corpus.Lifecycle.Renewal != LeaseSeconds ||
		corpus.Resolver.MaximumContacts != MaxResolverHops {
		t.Fatal("TIP-1 policy differs from the Go implementation")
	}
	for kind, categoryName := range categoryNames {
		_, got, err := Category(kind)
		if err != nil || corpus.Categories[categoryName].SHA256 != got {
			t.Fatalf("TIP-1 category %s differs from Go", categoryName)
		}
	}
	for _, vector := range corpus.NameEncoding {
		if vector.Result != "accept" {
			continue
		}
		encoded, err := EncodeName(vector.Input)
		if err != nil || hex.EncodeToString(encoded) != vector.EncodedHex {
			t.Fatalf("TIP-1 encoding %q differs: %x, %v", vector.Input, encoded, err)
		}
	}
}

func TestLifecycleExactBoundary(t *testing.T) {
	last := uint64(1_000)
	deadline := last + LeaseSeconds
	value := &nativev1.DNSLifecycleV1{LastFillUpUnixSeconds: last, RenewalDeadlineUnixSeconds: deadline}
	if err := validateLifecycle(value, deadline); err != nil {
		t.Fatalf("deadline second rejected: %v", err)
	}
	if err := validateLifecycle(value, deadline+1); err == nil {
		t.Fatal("deadline plus one accepted")
	}
	value.AuctionEndUnixSeconds = 2_000
	if err := validateLifecycle(value, 1_500); err == nil {
		t.Fatal("auctioning item accepted")
	}
}

func TestResolveBindsAliasNativeStateAndOwnerToOneCheckpoint(t *testing.T) {
	locator := testLocator(t)
	capID := "cap_" + strings.Repeat("22", 32)
	ownerID := "agent_" + strings.Repeat("11", 32)
	capIdentity, _ := locator.Locate(capID)
	ownerIdentity, _ := locator.Locate(ownerID)
	checkpoint := testCheckpoint(42)
	capState := &nativev1.NativeStateV1{
		Network:   locator.Network,
		Reference: &nativev1.ChainReference{Account: capIdentity.Address, ContractCodeHash: locator.CodeHash, FinalizedCheckpoint: 42},
		State:     &nativev1.NativeStateV1_Capability{Capability: &nativev1.CapabilityStateV1{CapabilityId: capID, OwnerAgentId: ownerID}},
	}
	ownerState := &nativev1.NativeStateV1{
		Network:   locator.Network,
		Reference: &nativev1.ChainReference{Account: ownerIdentity.Address, ContractCodeHash: locator.CodeHash, FinalizedCheckpoint: 42},
		State:     &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: ownerID}},
	}
	_, category, _ := Category(nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY)
	chain := &ChainResult{CanonicalName: "build.tos", CategoryHash: category, Resolved: capIdentity.Address,
		Checkpoint: checkpoint, Lifecycle: &nativev1.DNSLifecycleV1{LastFillUpUnixSeconds: 1_000, RenewalDeadlineUnixSeconds: 1_000 + LeaseSeconds},
		ResolverPath: []string{rawAddress(-1, "31"), rawAddress(0, "32"), rawAddress(0, "33")}}
	resolver, err := NewResolver(chainFake{chain}, nativeFake{map[string]*nativev1.NativeStateV1{
		capIdentity.Address: capState, ownerIdentity.Address: ownerState,
	}}, locator)
	if err != nil {
		t.Fatal(err)
	}
	resolver.now = func() time.Time { return time.Unix(2_000, 0) }
	response, err := resolver.ResolveDNSAlias(context.Background(), &nativev1.ResolveDNSAliasRequest{
		Context: &nativev1.RequestContext{RequestId: "r", CallerId: "c", DeadlineUnixMillis: 3_000_000},
		Name:    "build.tos", Kind: nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY,
	})
	if err != nil || response.NativeObjectId != capID || response.Provenance != nativev1.DNSProvenanceV1_DNS_PROVENANCE_V1_QUORUM_AGREED {
		t.Fatalf("resolve = %#v, %v", response, err)
	}

	ownerState.GetAgent().Tombstoned = true
	if _, err := resolver.ResolveDNSAlias(context.Background(), &nativev1.ResolveDNSAliasRequest{
		Context: &nativev1.RequestContext{RequestId: "r2", CallerId: "c", DeadlineUnixMillis: 3_000_000},
		Name:    "build.tos", Kind: nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_CAPABILITY,
	}); err == nil {
		t.Fatal("Capability with tombstoned owner accepted")
	}
}

func TestResolverPathRejectsNinthHopAndCycle(t *testing.T) {
	_, category, _ := Category(nativev1.DNSAliasKindV1_DNS_ALIAS_KIND_V1_AGENT)
	base := &ChainResult{CanonicalName: "alice.tos", CategoryHash: category, Resolved: rawAddress(0, "44"),
		Checkpoint: testCheckpoint(1), Lifecycle: &nativev1.DNSLifecycleV1{LastFillUpUnixSeconds: 1, RenewalDeadlineUnixSeconds: 1 + LeaseSeconds}}
	for i := 0; i < 9; i++ {
		base.ResolverPath = append(base.ResolverPath, rawAddress(0, hex.EncodeToString([]byte{byte(i + 1)})))
	}
	if err := validateChainResult(base, base.CanonicalName, category, 2); err == nil {
		t.Fatal("nine-hop path accepted")
	}
	base.ResolverPath = base.ResolverPath[:3]
	base.ResolverPath[2] = base.ResolverPath[0]
	if err := validateChainResult(base, base.CanonicalName, category, 2); err == nil {
		t.Fatal("cycle accepted")
	}
}

func testLocator(t *testing.T) *nativecore.Locator {
	t.Helper()
	code := cell.BeginCell().MustStoreUInt(0xdeadbeef, 32).EndCell()
	locator, err := nativecore.NewLocator(&nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("aa", 32), GenesisFileHash: "sha256:" + strings.Repeat("bb", 32)},
		0, base64.StdEncoding.EncodeToString(code.ToBOC()), "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	return locator
}

func testCheckpoint(sequence uint64) *nativev1.DNSCheckpointV1 {
	return &nativev1.DNSCheckpointV1{Workchain: -1, Shard: -1, Sequence: sequence, RootHash: make([]byte, 32), FileHash: append([]byte{1}, make([]byte, 31)...), GenerationUnixSeconds: 1_500}
}

func rawAddress(workchain int32, prefix string) string {
	return fmt.Sprintf("%d:%s%s", workchain, prefix, strings.Repeat("0", 64-len(prefix)))
}
