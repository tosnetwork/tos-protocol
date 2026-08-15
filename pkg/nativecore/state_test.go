package nativecore

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

func testLocator(t *testing.T) *Locator {
	t.Helper()
	code := cell.BeginCell().MustStoreUInt(0xdeadbeef, 32).EndCell()
	l, err := NewLocator(&nativev1.NetworkDomain{NetworkId: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)},
		0, base64.StdEncoding.EncodeToString(code.ToBOC()), "tvm-cell-sha256:"+hex.EncodeToString(code.Hash()))
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestLocatorAndAgentTypedStateRoundTrip(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	policyCell, _ := PolicyCell(policy)
	nonce := []byte(strings.Repeat("o", 32))
	id, err := DeriveAgentID(l.Network, nonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := l.Locate(id)
	if err != nil || !strings.HasPrefix(identity.Address, "0:") {
		t.Fatalf("locate: %v", err)
	}
	delegations := cell.BeginCell().MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()
	recovery := cell.BeginCell().MustStoreBoolBit(false).EndCell()
	state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
		MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(bytes32(0x33), 256).
		MustStoreRef(policyCell).MustStoreRef(delegations).MustStoreRef(recovery).EndCell()
	config, _ := l.configCell()
	rawID, _, _ := objectID(id)
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
		MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	decoded, found, err := l.DecodeData(data, id)
	if err != nil || !found || decoded.GetAgent().GetAgentId() != id || decoded.GetAgent().GetPolicy().GetControllers()[0].GetKeyId() != policy.Controllers[0].KeyId {
		t.Fatalf("decode Agent: found=%v err=%v state=%v", found, err, decoded)
	}
	first, found, err := l.DecodePortable(data, id)
	if err != nil || !found {
		t.Fatal(err)
	}
	second, _, err := l.DecodePortable(data, id)
	if err != nil || string(first) != string(second) {
		t.Fatal("portable projection is not deterministic")
	}
}

func TestCapabilityTypedStatePreservesVersionName(t *testing.T) {
	l := testLocator(t)
	owner := "agent_" + strings.Repeat("44", 32)
	version := &nativev1.CapabilityVersionV1{Version: "1.2.3", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	id, err := DeriveCapabilityID(l.Network, []byte(strings.Repeat("c", 32)), owner, version)
	if err != nil {
		t.Fatal(err)
	}
	versionKey := sha256.Sum256([]byte(version.Version))
	dict := cell.NewDict(256)
	key := cell.BeginCell().MustStoreSlice(versionKey[:], 256).EndCell()
	manifest, _ := digestBytes(version.ManifestDigest, "sha256:", false)
	value := cell.BeginCell().MustStoreSlice(manifest, 256).MustStoreBoolBit(false).MustStoreRef(stringCell(version.Version)).EndCell()
	if err := dict.Set(key, value); err != nil {
		t.Fatal(err)
	}
	versions := cell.BeginCell().MustStoreUInt(1, 16).MustStoreDict(dict).EndCell()
	ownerRaw, _, _ := objectID(owner)
	state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(2, 8).
		MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(1, 64).MustStoreSlice(bytes32(0x66), 256).
		MustStoreSlice(ownerRaw, 256).MustStoreRef(versions).EndCell()
	config, _ := l.configCell()
	rawID, _, _ := objectID(id)
	data := cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(2, 8).
		MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	decoded, found, err := l.DecodeData(data, id)
	if err != nil || !found || len(decoded.GetCapability().GetVersions()) != 1 || decoded.GetCapability().GetVersions()[0].GetVersion() != version.Version {
		t.Fatalf("decode Capability: found=%v err=%v state=%v", found, err, decoded)
	}
}

func TestPendingRecoveryIsBoundToLivePolicy(t *testing.T) {
	l := testLocator(t)
	policy, _ := testPolicy(t)
	policyCell, _ := PolicyCell(policy)
	id, err := DeriveAgentID(l.Network, bytes32('o'), policy)
	if err != nil {
		t.Fatal(err)
	}
	buildData := func(policyHash []byte) *cell.Cell {
		delegations := cell.BeginCell().MustStoreUInt(0, 16).MustStoreDict(nil).EndCell()
		recovery := cell.BeginCell().MustStoreBoolBit(true).MustStoreSlice(bytes32('i'), 256).
			MustStoreSlice(policyHash, 256).MustStoreUInt(1234, 64).MustStoreRef(policyCell).EndCell()
		state := cell.BeginCell().MustStoreUInt(stateMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
			MustStoreBoolBit(false).MustStoreUInt(1, 64).MustStoreUInt(2, 64).MustStoreSlice(bytes32('a'), 256).
			MustStoreRef(policyCell).MustStoreRef(delegations).MustStoreRef(recovery).EndCell()
		config, _ := l.configCell()
		rawID, _, _ := objectID(id)
		return cell.BeginCell().MustStoreUInt(dataMagic, 32).MustStoreUInt(1, 16).MustStoreUInt(1, 8).
			MustStoreSlice(rawID, 256).MustStoreRef(config).MustStoreBoolBit(true).MustStoreRef(state).EndCell()
	}
	decoded, found, err := l.DecodeData(buildData(policyCell.Hash()), id)
	if err != nil || !found || decoded.GetAgent().GetRecoveryInitiatingPolicyHash() != "tvm-cell-sha256:"+hex.EncodeToString(policyCell.Hash()) {
		t.Fatalf("valid bound recovery: found=%v err=%v state=%v", found, err, decoded)
	}
	if _, _, err := l.DecodeData(buildData(bytes32('x')), id); err == nil {
		t.Fatal("recovery bound to a stale policy hash was accepted")
	}
}

func bytes32(value byte) []byte { return []byte(strings.Repeat(string([]byte{value}), 32)) }
