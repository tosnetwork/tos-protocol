// Package trustedcapability implements the portable wire objects for the
// Trusted Capability and Owner Control V1 profile.  It intentionally uses a
// dedicated integer-key CBOR codec: the older generic protocol codec models
// JSON string-keyed maps and is not wire-compatible with this profile.
package trustedcapability

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/text/unicode/norm"
)

const (
	SchemaVersion      uint16 = 1
	ProfileURI                = "tos.trusted-capability-owner-control.v1"
	ProfileVersion     uint16 = 1
	ProfileCriticality uint8  = 1
	MaxCanonicalBytes         = 1 << 20
	MaxCollectionItems        = 4096
	MaxNestedLevels           = 16
)

type DomainKind uint8

const (
	DomainTOSNetwork DomainKind = 1
	DomainOwnerLocal DomainKind = 2
)

// ProfileObjectV1 is the sole hashable wrapper. Body is exact canonical CBOR.
type ProfileObjectV1 struct {
	SchemaVersion         uint16 `cbor:"1,keyasint" json:"schema_version"`
	ProfileURI            string `cbor:"2,keyasint" json:"profile_uri"`
	ProfileVersion        uint16 `cbor:"3,keyasint" json:"profile_version"`
	ProfileCriticality    uint8  `cbor:"4,keyasint" json:"profile_criticality"`
	ProfileRegistryDigest []byte `cbor:"5,keyasint" json:"profile_registry_digest"`
	DomainKind            uint8  `cbor:"6,keyasint" json:"domain_kind"`
	DomainID              []byte `cbor:"7,keyasint" json:"domain_id"`
	ObjectKind            string `cbor:"8,keyasint" json:"object_kind"`
	Body                  []byte `cbor:"9,keyasint" json:"body"`
}

type RegistryEntry struct {
	ObjectKind  string `cbor:"1,keyasint" json:"object_kind"`
	DomainTag   string `cbor:"2,keyasint" json:"domain_tag"`
	Criticality uint8  `cbor:"3,keyasint" json:"criticality"`
}

var objectKinds = []string{
	"artifact", "content-manifest", "entrypoint-descriptor", "permission-manifest", "dependency-manifest", "publisher-envelope",
	"publisher-revocation-observation", "capability-requirement", "sourcing-decision", "evaluation-manifest", "evaluation-result", "evaluation-evidence",
	"authorization-envelope", "owner-policy", "capability-admission", "admission-mutation",
	"promotion-authority", "promotion-mutation", "use-lease", "installation-transaction",
	"inventory-snapshot", "capability-use-binding", "owner-report", "report-source-coverage",
	"projection-event", "projection-snapshot", "owner-bootstrap", "owner-recovery",
	"device-enrollment", "device-session", "owner-command-lease", "owner-command-effect", "owner-command-attempt",
	"owner-command-resolution", "semantic-confirmation", "owner-exit-plan", "migration", "action-outcome-evidence",
}

var (
	encMode        cbor.EncMode
	decMode        cbor.DecMode
	registry       = make(map[string]RegistryEntry, len(objectKinds))
	registryDigest []byte
)

func init() {
	var err error
	options := cbor.CoreDetEncOptions()
	options.TagsMd = cbor.TagsForbidden
	encMode, err = options.EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:   MaxNestedLevels,
		MaxArrayElements:  MaxCollectionItems,
		MaxMapPairs:       MaxCollectionItems,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		IntDec:            cbor.IntDecConvertNone,
		DefaultMapType:    reflect.TypeOf(map[uint64]any{}),
		UTF8:              cbor.UTF8RejectInvalid,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	for _, kind := range objectKinds {
		registry[kind] = RegistryEntry{ObjectKind: kind, DomainTag: kind + ".v1", Criticality: ProfileCriticality}
	}
	entries := make([]RegistryEntry, 0, len(objectKinds))
	for _, kind := range objectKinds {
		entries = append(entries, registry[kind])
	}
	encoded, err := encMode.Marshal(entries)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(append([]byte(ProfileURI+"/registry\x00"), encoded...))
	registryDigest = append([]byte(nil), sum[:]...)
}

func Registry() map[string]RegistryEntry {
	out := make(map[string]RegistryEntry, len(registry))
	for key, value := range registry {
		out[key] = value
	}
	return out
}

func RegistryDigest() []byte { return append([]byte(nil), registryDigest...) }

// RegistryCanonicalBytes are the exact released bytes committed by the
// registry digest. Their list order is part of V1 and follows objectKinds.
func RegistryCanonicalBytes() []byte {
	entries := make([]RegistryEntry, 0, len(objectKinds))
	for _, kind := range objectKinds {
		entries = append(entries, registry[kind])
	}
	encoded, err := encMode.Marshal(entries)
	if err != nil {
		panic(err)
	}
	return encoded
}

func RegistryObjectKinds() []string { return append([]string(nil), objectKinds...) }

func MarshalBody(value any) ([]byte, error) {
	encoded, err := encMode.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("trusted capability CBOR encode: %w", err)
	}
	if len(encoded) == 0 || len(encoded) > MaxCanonicalBytes {
		return nil, errors.New("canonical object has invalid size")
	}
	if err := validateCanonical(encoded); err != nil {
		return nil, err
	}
	return encoded, nil
}

func UnmarshalBody(data []byte, output any) error {
	if err := validateCanonical(data); err != nil {
		return err
	}
	if err := decMode.Unmarshal(data, output); err != nil {
		return fmt.Errorf("decode trusted capability object: %w", err)
	}
	return nil
}

func validateCanonical(data []byte) error {
	if len(data) == 0 || len(data) > MaxCanonicalBytes {
		return errors.New("canonical object has invalid size")
	}
	var value any
	if err := decMode.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("decode trusted capability CBOR: %w", err)
	}
	if err := validateValue(value, 0); err != nil {
		return err
	}
	reencoded, err := encMode.Marshal(value)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, reencoded) {
		return errors.New("CBOR is not in Core Deterministic form")
	}
	return nil
}

func validateValue(value any, depth int) error {
	if depth > MaxNestedLevels {
		return errors.New("CBOR exceeds nesting limit")
	}
	switch typed := value.(type) {
	case string:
		if !utf8.ValidString(typed) || !norm.NFC.IsNormalString(typed) {
			return errors.New("text is not valid NFC UTF-8")
		}
	case float32, float64:
		return errors.New("floating point values are forbidden")
	case cbor.Tag:
		return errors.New("CBOR tags are forbidden")
	case []any:
		if len(typed) > MaxCollectionItems {
			return errors.New("array exceeds item limit")
		}
		for _, item := range typed {
			if err := validateValue(item, depth+1); err != nil {
				return err
			}
		}
	case map[uint64]any:
		if len(typed) > MaxCollectionItems {
			return errors.New("map exceeds pair limit")
		}
		for _, item := range typed {
			if err := validateValue(item, depth+1); err != nil {
				return err
			}
		}
	case map[any]any:
		return errors.New("map keys must be unsigned integers")
	}
	return nil
}

func NewObject(domainKind DomainKind, domainID []byte, objectKind string, body any) (ProfileObjectV1, error) {
	entry, ok := registry[objectKind]
	if !ok {
		return ProfileObjectV1{}, errors.New("unknown object kind")
	}
	if domainKind != DomainTOSNetwork && domainKind != DomainOwnerLocal {
		return ProfileObjectV1{}, errors.New("unknown domain kind")
	}
	if len(domainID) == 0 || len(domainID) > 64 {
		return ProfileObjectV1{}, errors.New("domain ID has invalid size")
	}
	canonical, err := MarshalBody(body)
	if err != nil {
		return ProfileObjectV1{}, err
	}
	if err := ValidateBodyShape(objectKind, canonical); err != nil {
		return ProfileObjectV1{}, fmt.Errorf("%s body shape: %w", objectKind, err)
	}
	return ProfileObjectV1{SchemaVersion: SchemaVersion, ProfileURI: ProfileURI, ProfileVersion: ProfileVersion,
		ProfileCriticality: entry.Criticality, ProfileRegistryDigest: RegistryDigest(), DomainKind: uint8(domainKind),
		DomainID: append([]byte(nil), domainID...), ObjectKind: objectKind, Body: canonical}, nil
}

func EncodeObject(object ProfileObjectV1) ([]byte, error) {
	if err := ValidateObject(object); err != nil {
		return nil, err
	}
	return MarshalBody(object)
}

func DecodeObject(data []byte) (ProfileObjectV1, error) {
	var object ProfileObjectV1
	if err := UnmarshalBody(data, &object); err != nil {
		return object, err
	}
	if err := ValidateObject(object); err != nil {
		return object, err
	}
	return object, nil
}

func ValidateObject(object ProfileObjectV1) error {
	entry, ok := registry[object.ObjectKind]
	if !ok {
		return errors.New("unknown object kind")
	}
	if object.SchemaVersion != SchemaVersion || object.ProfileURI != ProfileURI || object.ProfileVersion != ProfileVersion || object.ProfileCriticality != entry.Criticality {
		return errors.New("profile registry mismatch")
	}
	if !bytes.Equal(object.ProfileRegistryDigest, registryDigest) {
		return errors.New("profile registry digest mismatch")
	}
	if object.DomainKind != uint8(DomainTOSNetwork) && object.DomainKind != uint8(DomainOwnerLocal) {
		return errors.New("unknown domain kind")
	}
	if len(object.DomainID) == 0 || len(object.DomainID) > 64 {
		return errors.New("domain ID has invalid size")
	}
	if err := validateCanonical(object.Body); err != nil {
		return err
	}
	return ValidateBodyShape(object.ObjectKind, object.Body)
}

func ObjectDigest(object ProfileObjectV1) ([]byte, error) {
	entry, ok := registry[object.ObjectKind]
	if !ok {
		return nil, errors.New("unknown object kind")
	}
	canonical, err := EncodeObject(object)
	if err != nil {
		return nil, err
	}
	if len(canonical) > int(^uint32(0)) {
		return nil, errors.New("canonical object exceeds framing limit")
	}
	hash := sha256.New()
	hash.Write([]byte(ProfileURI + "/" + entry.DomainTag))
	hash.Write([]byte{0})
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
	hash.Write(length[:])
	hash.Write(canonical)
	return hash.Sum(nil), nil
}

func DecodeBody(object ProfileObjectV1, expectedKind string, output any) error {
	if err := ValidateObject(object); err != nil {
		return err
	}
	if object.ObjectKind != expectedKind {
		return errors.New("object kind mismatch")
	}
	return UnmarshalBody(object.Body, output)
}
