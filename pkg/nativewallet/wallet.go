// Package nativewallet provides local, review-before-signing support for
// tos_service_v1 actions. It never submits a transaction or grants a gateway
// access to controller keys.
package nativewallet

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/internal/jsonstrict"
	"github.com/tosnetwork/tos-service-protocol/internal/osguard"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"google.golang.org/protobuf/encoding/protojson"
)

const KeySchema = "tos.service.wallet-key.v1"

type Review struct {
	Protocol               string          `json:"protocol"`
	NetworkID              string          `json:"network_id"`
	GenesisRootHash        string          `json:"genesis_root_hash"`
	GenesisFileHash        string          `json:"genesis_file_hash"`
	TargetObjectID         string          `json:"target_object_id"`
	TargetContractCodeHash string          `json:"target_contract_code_hash"`
	Generation             uint64          `json:"generation"`
	Sequence               uint64          `json:"sequence"`
	PredecessorStateHash   string          `json:"predecessor_tvm_state_hash,omitempty"`
	Action                 string          `json:"action"`
	ActionHash             string          `json:"action_hash"`
	SignedAction           json.RawMessage `json:"signed_action"`
}

type Key struct {
	keyID   string
	private ed25519.PrivateKey
}

func (k *Key) KeyID() string {
	if k == nil {
		return ""
	}
	return k.keyID
}

func (k *Key) Close() {
	if k == nil {
		return
	}
	for i := range k.private {
		k.private[i] = 0
	}
	k.private = nil
}

func LoadKey(path string) (*Key, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("Native wallet key path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, errors.New("Native wallet key must be an owner-private regular file")
	}
	if !osguard.CurrentUserOwns(info) {
		return nil, errors.New("Native wallet key owner mismatch")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var encoded struct {
		Schema         string `json:"schema"`
		PrivateSeedHex string `json:"private_seed_hex"`
	}
	if err := jsonstrict.Decode(raw, &encoded); err != nil || encoded.Schema != KeySchema {
		return nil, errors.New("invalid Native wallet key file")
	}
	seed, err := hex.DecodeString(encoded.PrivateSeedHex)
	if err != nil || len(seed) != ed25519.SeedSize || encoded.PrivateSeedHex != hex.EncodeToString(seed) {
		return nil, errors.New("invalid Native Ed25519 seed")
	}
	private := ed25519.NewKeyFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	public := private.Public().(ed25519.PublicKey)
	return &Key{keyID: "ed25519:" + hex.EncodeToString(public), private: private}, nil
}

func ReviewAction(action *nativev1.NativeActionV1) (Review, nativecore.BuiltAction, error) {
	built, err := nativecore.BuildAction(action)
	if err != nil {
		return Review{}, nativecore.BuiltAction{}, err
	}
	signedAction, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(action)
	if err != nil {
		return Review{}, nativecore.BuiltAction{}, err
	}
	return Review{Protocol: action.Protocol, NetworkID: action.Network.NetworkId,
		GenesisRootHash: action.Network.GenesisRootHash, GenesisFileHash: action.Network.GenesisFileHash,
		TargetObjectID: action.TargetObjectId, TargetContractCodeHash: action.TargetContractCodeHash,
		Generation: action.Generation, Sequence: action.Sequence, PredecessorStateHash: action.PredecessorTvmStateHash,
		Action: actionName(action), ActionHash: built.HashString, SignedAction: signedAction}, built, nil
}

func Sign(built nativecore.BuiltAction, keys []*Key) ([]*nativev1.SignatureV1, error) {
	if built.Cell == nil || len(keys) == 0 || len(keys) > nativecore.MaxSignatures {
		return nil, errors.New("invalid Native wallet signing request")
	}
	ordered := append([]*Key(nil), keys...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].keyID < ordered[j].keyID })
	result := make([]*nativev1.SignatureV1, len(ordered))
	for i, key := range ordered {
		if key == nil || len(key.private) != ed25519.PrivateKeySize || i > 0 && key.keyID == ordered[i-1].keyID {
			return nil, errors.New("invalid or duplicate Native wallet key")
		}
		signature, err := nativecore.SignAction(key.private, key.keyID, built)
		if err != nil {
			return nil, err
		}
		result[i] = signature
	}
	return result, nil
}

func actionName(action *nativev1.NativeActionV1) string {
	switch action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		return "register_agent"
	case *nativev1.NativeActionV1_UpdateAgentPolicy:
		return "update_agent_policy"
	case *nativev1.NativeActionV1_DelegateAgent:
		return "delegate_agent"
	case *nativev1.NativeActionV1_InitiateRecovery:
		return "initiate_recovery"
	case *nativev1.NativeActionV1_CompleteRecovery:
		return "complete_recovery"
	case *nativev1.NativeActionV1_RevokeAgent:
		return "revoke_agent"
	case *nativev1.NativeActionV1_RegisterCapability:
		return "register_capability"
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		return "add_capability_version"
	case *nativev1.NativeActionV1_TransferCapability:
		return "transfer_capability"
	case *nativev1.NativeActionV1_RevokeCapability:
		return "revoke_capability"
	default:
		return "unknown"
	}
}

// ConfirmHash requires the operator to type the complete action hash. A simple
// yes/no prompt is intentionally insufficient for a value-bearing mutation.
func ConfirmHash(input *bufio.Reader, expected string) error {
	if input == nil || expected == "" {
		return errors.New("invalid Native semantic confirmation")
	}
	value, err := input.ReadString('\n')
	if err != nil && value == "" {
		return err
	}
	if strings.TrimSpace(value) != expected {
		return errors.New("Native action hash confirmation mismatch")
	}
	return nil
}
