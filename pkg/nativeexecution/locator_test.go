package nativeexecution

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func TestObjectLocatorIsDeterministicAndObjectScoped(t *testing.T) {
	code := cell.BeginCell().MustStoreUInt(0x1234, 16).EndCell()
	network := nativeprotocol.NetworkDomain{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	codeHash := "tvm-cell-sha256:" + strings.ToLower(hexString(code.Hash()))
	locator, err := NewObjectLocator(network, 0, base64.StdEncoding.EncodeToString(code.ToBOC()), codeHash)
	if err != nil {
		t.Fatal(err)
	}
	agentID, _ := idBytes("agent_"+strings.Repeat("33", 32), "agent")
	first := locator.stateInit(1, agentID)
	second := locator.stateInit(1, agentID)
	if !bytes.Equal(first.Hash(), second.Hash()) {
		t.Fatal("deterministic Agent StateInit changed")
	}
	capabilityID, _ := idBytes("cap_"+strings.Repeat("44", 32), "cap")
	other := locator.stateInit(2, capabilityID)
	if string(other.Hash()) == string(first.Hash()) {
		t.Fatal("Agent and Capability shared a contract address")
	}
	anchor, err := locator.LocateActionAnchor("sha256:" + strings.Repeat("55", 32))
	if err != nil || strings.HasSuffix(anchor.Address, hexString(first.Hash())) || strings.HasSuffix(anchor.Address, hexString(other.Hash())) {
		t.Fatalf("Action anchor was not separately derived: %+v %v", anchor, err)
	}
}

func hexString(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, b := range value {
		out[i*2], out[i*2+1] = alphabet[b>>4], alphabet[b&15]
	}
	return string(out)
}
