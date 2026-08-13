package nativeexecution

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

const objectDataMagic = 0x4e524432 // NRD2
const ActionAnchorKind = 3
const LocatorVersion = "tos.native-registry-locator.v1"

// ObjectLocator derives the one canonical StateInit address for each Native
// Agent or Capability. The contract code is configuration, never request data.
type ObjectLocator struct {
	Network       nativeprotocol.NetworkDomain
	Workchain     int32
	CodeBOCBase64 string
	CodeHash      string

	code *cell.Cell
}

func NewObjectLocator(network nativeprotocol.NetworkDomain, workchain int32, codeBOCBase64, expectedCodeHash string) (*ObjectLocator, error) {
	if err := network.Validate(); err != nil {
		return nil, err
	}
	if workchain < -128 || workchain > 127 {
		return nil, errors.New("Native registry workchain is outside addr_std range")
	}
	raw, err := base64.StdEncoding.DecodeString(codeBOCBase64)
	if err != nil {
		return nil, errors.New("invalid Native registry code BOC")
	}
	code, err := cell.FromBOC(raw)
	if err != nil || code == nil || len(code.ToBOC()) == 0 {
		return nil, errors.New("invalid Native registry code cell")
	}
	actual := "tvm-cell-sha256:" + hex.EncodeToString(code.Hash())
	if actual != expectedCodeHash {
		return nil, errors.New("Native registry code hash mismatch")
	}
	return &ObjectLocator{Network: network, Workchain: workchain, CodeBOCBase64: codeBOCBase64, CodeHash: actual, code: code}, nil
}

func (l *ObjectLocator) Locate(action nativeprotocol.RegistryAction) (ContractIdentity, error) {
	if l == nil || l.code == nil || action.Network != l.Network {
		return ContractIdentity{}, errors.New("Native registry locator network mismatch")
	}
	objectID := action.AgentID
	kind := uint64(1)
	prefix := "agent"
	if action.CapabilityID != "" {
		objectID, kind, prefix = action.CapabilityID, 2, "cap"
	}
	rawID, err := idBytes(objectID, prefix)
	if err != nil {
		return ContractIdentity{}, err
	}
	stateInit := l.stateInit(kind, rawID)
	actionID, err := nativeprotocol.ActionDigest(action)
	if err != nil {
		return ContractIdentity{}, err
	}
	anchor, err := l.LocateActionAnchor(actionID)
	if err != nil {
		return ContractIdentity{}, err
	}
	return ContractIdentity{
		Network: l.Network, Address: fmt.Sprintf("%d:%s", l.Workchain, hex.EncodeToString(stateInit.Hash())),
		ActionAnchorAddress: anchor.Address, AllowedCodeHash: l.CodeHash,
	}, nil
}

func (l *ObjectLocator) LocateObject(objectID string) (ContractIdentity, error) {
	prefix, kind := "agent", uint64(1)
	if len(objectID) > 4 && objectID[:4] == "cap_" {
		prefix, kind = "cap", 2
	}
	raw, err := idBytes(objectID, prefix)
	if err != nil {
		return ContractIdentity{}, err
	}
	stateInit := l.stateInit(kind, raw)
	address := fmt.Sprintf("%d:%s", l.Workchain, hex.EncodeToString(stateInit.Hash()))
	return ContractIdentity{Network: l.Network, Address: address, AllowedCodeHash: l.CodeHash}, nil
}

// LocateActionAnchor derives the immutable recovery account for an Action ID.
// It is deliberately distinct from the mutable object-contract address.
func (l *ObjectLocator) LocateActionAnchor(actionID string) (ContractIdentity, error) {
	identity, _, err := l.ActionAnchorStateInit(actionID)
	return identity, err
}

func (l *ObjectLocator) ActionAnchorStateInit(actionID string) (ContractIdentity, string, error) {
	if l == nil || l.code == nil {
		return ContractIdentity{}, "", errors.New("Native registry locator is not configured")
	}
	raw, err := digestBytes(actionID, false)
	if err != nil {
		return ContractIdentity{}, "", errors.New("invalid Native Action ID")
	}
	stateInit := l.stateInit(ActionAnchorKind, raw)
	address := fmt.Sprintf("%d:%s", l.Workchain, hex.EncodeToString(stateInit.Hash()))
	return ContractIdentity{Network: l.Network, Address: address, ActionAnchorAddress: address, AllowedCodeHash: l.CodeHash}, base64.StdEncoding.EncodeToString(stateInit.ToBOC()), nil
}

func (l *ObjectLocator) stateInit(kind uint64, rawID []byte) *cell.Cell {
	config := objectConfigCell(l.Network, l.Workchain, l.CodeHash, l.code)
	data := cell.BeginCell().MustStoreUInt(objectDataMagic, 32).MustStoreUInt(1, 16).
		MustStoreUInt(kind, 8).MustStoreSlice(rawID, 256).MustStoreRef(config).
		MustStoreBoolBit(false).MustStoreBoolBit(false).MustStoreBoolBit(false).EndCell()
	return cell.BeginCell().MustStoreBoolBit(false).MustStoreBoolBit(false).
		MustStoreBoolBit(true).MustStoreRef(l.code).MustStoreBoolBit(true).MustStoreRef(data).
		MustStoreBoolBit(false).EndCell()
}

func objectConfigCell(network nativeprotocol.NetworkDomain, workchain int32, codeHash string, code *cell.Cell) *cell.Cell {
	networkHash := sha256.Sum256([]byte(network.NetworkID))
	return cell.BeginCell().MustStoreSlice(mustDigest(network.GenesisRootHash), 256).
		MustStoreSlice(mustDigest(network.GenesisFileHash), 256).MustStoreSlice(networkHash[:], 256).
		MustStoreRef(cell.BeginCell().MustStoreInt(int64(workchain), 32).
			MustStoreSlice(mustDigest(codeHash), 256).MustStoreRef(stringCell(network.NetworkID)).MustStoreRef(code).EndCell()).EndCell()
}
