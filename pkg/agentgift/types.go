// Package agentgift defines the canonical, private direct-message objects for
// OpenFox Agent Gifts. It contains no discovery, recipient-ticket, escrow, or
// gateway authority.
package agentgift

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
	"github.com/tosnetwork/tosutils-go/address"
)

const (
	SchemaAddressRequest  = "tos.agent-gift.address-request.v1"
	SchemaAddressResponse = "tos.agent-gift.address-response.v1"
	SchemaSignedBOCOffer  = "tos.agent-gift.signed-boc-offer.v1"
	AssetNativeTOS        = "native_tos"

	DomainAddressRequest     = "tos.agent-gift.address-request.v1"
	DomainAddressResponse    = "tos.agent-gift.address-response.v1"
	DomainOwnerAuthorization = "tos.agent-gift.owner-authorization.v1"
	DomainOwnerCancellation  = "tos.agent-gift.owner-cancellation.v1"
	DomainUnsignedTransfer   = "tos.agent-gift.unsigned-transfer.v1"
	DomainExactSignedBOC     = "tos.agent-gift.exact-signed-boc.v1"
	DomainSignedGift         = "tos.agent-gift.signed-gift.v1"

	MaxAgentIDBytes        = 96
	MaxNetworkBytes        = 64
	MaxAddressBytes        = 80
	MaxAmountDigits        = 20
	MaxDisplayMessageBytes = 512
	MaxPaddingBytes        = 4096
	// The frozen Agent Account external body stores a 512-bit signature and
	// the payload inline in one 1023-bit cell. Coins values above 48 bits do
	// not fit once controller_epoch is included.
	MaxAgentAccountActionAtomic uint64 = (1 << 48) - 1
	// Leave deterministic space for the canonical offer fields and padding so
	// the complete object always fits Messenger's 64 KiB application limit.
	MaxSignedBOCBytes     = 56 << 10
	MaxCanonicalGiftBytes = 64 << 10
)

var (
	agentIDPattern = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	hex256Pattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	amountPattern  = regexp.MustCompile(`^[1-9][0-9]*$`)
)

type GiftAddressRequestV1 struct {
	Schema              string `json:"schema"`
	Network             string `json:"network"`
	GlobalID            int32  `json:"global_id"`
	GiftIntentID        string `json:"gift_intent_id"`
	SenderAgentID       string `json:"sender_agent_id"`
	RecipientAgentID    string `json:"recipient_agent_id"`
	SenderAgentAccount  string `json:"sender_agent_account"`
	AssetKind           string `json:"asset_kind"`
	AmountAtomic        string `json:"amount_atomic"`
	RequestedValidUntil uint32 `json:"requested_valid_until"`
}

type GiftAddressResponseV1 struct {
	Schema             string `json:"schema"`
	Network            string `json:"network"`
	GlobalID           int32  `json:"global_id"`
	GiftIntentID       string `json:"gift_intent_id"`
	RequestDigest      string `json:"request_digest"`
	SenderAgentID      string `json:"sender_agent_id"`
	RecipientAgentID   string `json:"recipient_agent_id"`
	AssetKind          string `json:"asset_kind"`
	AmountAtomic       string `json:"amount_atomic"`
	DestinationAddress string `json:"destination_address"`
	ResponseNotAfter   uint32 `json:"response_not_after"`
}

type GiftSignedBOCOfferV1 struct {
	Schema                string `json:"schema"`
	GiftIntentID          string `json:"gift_intent_id"`
	AddressRequestDigest  string `json:"address_request_digest"`
	AddressResponseDigest string `json:"address_response_digest"`
	SignedGiftID          string `json:"signed_gift_id"`
	ExactSignedBOC        []byte `json:"exact_signed_boc"`
	DisplayMessage        string `json:"display_message,omitempty"`
	Padding               []byte `json:"padding,omitempty"`
}

type OwnerAuthorizationV1 struct {
	Network               string `json:"network"`
	GlobalID              int32  `json:"global_id"`
	GiftIntentID          string `json:"gift_intent_id"`
	RecipientAgentID      string `json:"recipient_agent_id"`
	SenderAgentAccount    string `json:"sender_agent_account"`
	OwnerWallet           string `json:"owner_wallet"`
	ControllerKeyID       string `json:"controller_key_id"`
	DeploymentID          string `json:"deployment_id"`
	ControllerEpoch       uint64 `json:"controller_epoch"`
	DestinationAddress    string `json:"destination_address"`
	AmountAtomic          string `json:"amount_atomic"`
	Seqno                 uint32 `json:"seqno"`
	ValidUntil            uint32 `json:"valid_until"`
	FeeReserveAtomic      string `json:"fee_reserve_atomic"`
	AddressRequestDigest  string `json:"address_request_digest"`
	AddressResponseDigest string `json:"address_response_digest"`
}

type UnsignedTransferV1 struct {
	Network            string `json:"network"`
	GlobalID           int32  `json:"global_id"`
	SenderAgentAccount string `json:"sender_agent_account"`
	DeploymentID       string `json:"deployment_id"`
	ControllerEpoch    uint64 `json:"controller_epoch"`
	Seqno              uint32 `json:"seqno"`
	ValidUntil         uint32 `json:"valid_until"`
	DestinationAddress string `json:"destination_address"`
	AmountAtomic       string `json:"amount_atomic"`
	SendMode           uint8  `json:"send_mode"`
	Bounce             bool   `json:"bounce"`
}

type OwnerCancellationAuthorizationV1 struct {
	Network               string `json:"network"`
	GlobalID              int32  `json:"global_id"`
	GiftIntentID          string `json:"gift_intent_id"`
	SignedGiftID          string `json:"signed_gift_id"`
	RecipientAgentID      string `json:"recipient_agent_id"`
	SenderAgentAccount    string `json:"sender_agent_account"`
	DeploymentID          string `json:"deployment_id"`
	ControllerEpoch       uint64 `json:"controller_epoch"`
	DestinationAddress    string `json:"destination_address"`
	AmountAtomic          string `json:"amount_atomic"`
	Seqno                 uint32 `json:"seqno"`
	ValidUntil            uint32 `json:"valid_until"`
	AddressRequestDigest  string `json:"address_request_digest"`
	AddressResponseDigest string `json:"address_response_digest"`
}

func NewGiftIntentID() (string, error) {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(id[:]), nil
}

func Encode(value any) ([]byte, error) {
	if err := Validate(value); err != nil {
		return nil, canonicalError(err)
	}
	encoded, err := codec.Marshal(value)
	if err != nil {
		return nil, canonicalError(err)
	}
	if len(encoded) == 0 || len(encoded) > MaxCanonicalGiftBytes {
		return nil, canonicalError(errors.New("canonical Agent Gift object exceeds transport limit"))
	}
	return encoded, nil
}

func DecodeAddressRequest(data []byte) (GiftAddressRequestV1, error) {
	var value GiftAddressRequestV1
	if len(data) == 0 || len(data) > MaxCanonicalGiftBytes {
		return value, canonicalError(errors.New("canonical Agent Gift request has invalid size"))
	}
	if err := codec.Unmarshal(data, &value); err != nil {
		return value, canonicalError(err)
	}
	if err := value.Validate(); err != nil {
		return value, canonicalError(err)
	}
	return value, nil
}

func DecodeAddressResponse(data []byte) (GiftAddressResponseV1, error) {
	var value GiftAddressResponseV1
	if len(data) == 0 || len(data) > MaxCanonicalGiftBytes {
		return value, canonicalError(errors.New("canonical Agent Gift response has invalid size"))
	}
	if err := codec.Unmarshal(data, &value); err != nil {
		return value, canonicalError(err)
	}
	if err := value.Validate(); err != nil {
		return value, canonicalError(err)
	}
	return value, nil
}

func DecodeSignedBOCOffer(data []byte) (GiftSignedBOCOfferV1, error) {
	var value GiftSignedBOCOfferV1
	if len(data) == 0 || len(data) > MaxCanonicalGiftBytes {
		return value, canonicalError(errors.New("canonical Agent Gift offer has invalid size"))
	}
	if err := codec.Unmarshal(data, &value); err != nil {
		return value, canonicalError(err)
	}
	if err := value.Validate(); err != nil {
		return value, canonicalError(err)
	}
	return value, nil
}

func Validate(value any) error {
	switch typed := value.(type) {
	case GiftAddressRequestV1:
		return typed.Validate()
	case *GiftAddressRequestV1:
		if typed == nil {
			return errors.New("nil Gift address request")
		}
		return typed.Validate()
	case GiftAddressResponseV1:
		return typed.Validate()
	case *GiftAddressResponseV1:
		if typed == nil {
			return errors.New("nil Gift address response")
		}
		return typed.Validate()
	case GiftSignedBOCOfferV1:
		return typed.Validate()
	case *GiftSignedBOCOfferV1:
		if typed == nil {
			return errors.New("nil Gift signed BOC offer")
		}
		return typed.Validate()
	case OwnerAuthorizationV1:
		return typed.Validate()
	case *OwnerAuthorizationV1:
		if typed == nil {
			return errors.New("nil owner authorization")
		}
		return typed.Validate()
	case UnsignedTransferV1:
		return typed.Validate()
	case *UnsignedTransferV1:
		if typed == nil {
			return errors.New("nil unsigned transfer")
		}
		return typed.Validate()
	case OwnerCancellationAuthorizationV1:
		return typed.Validate()
	case *OwnerCancellationAuthorizationV1:
		if typed == nil {
			return errors.New("nil owner cancellation authorization")
		}
		return typed.Validate()
	default:
		return errors.New("unsupported Agent Gift canonical type")
	}
}

func (v OwnerCancellationAuthorizationV1) Validate() error {
	if !validNetwork(v.Network) || v.GlobalID == 0 || !hex256Pattern.MatchString(v.GiftIntentID) || !digestPattern.MatchString(v.SignedGiftID) || !digestPattern.MatchString(v.DeploymentID) || !validAgent(v.RecipientAgentID) || v.ValidUntil == 0 {
		return errors.New("invalid owner cancellation identity")
	}
	if validateAddress(v.SenderAgentAccount) != nil || validateAddress(v.DestinationAddress) != nil {
		return errors.New("invalid owner cancellation address")
	}
	if _, err := ParseActionAmount(v.AmountAtomic); err != nil {
		return err
	}
	if !digestPattern.MatchString(v.AddressRequestDigest) || !digestPattern.MatchString(v.AddressResponseDigest) {
		return errors.New("invalid owner cancellation exchange binding")
	}
	return nil
}

func (v GiftAddressRequestV1) Validate() error {
	if v.Schema != SchemaAddressRequest {
		return errors.New("invalid Gift address request schema")
	}
	if err := validateCommon(v.Network, v.GiftIntentID, v.SenderAgentID, v.RecipientAgentID, v.AssetKind, v.AmountAtomic); err != nil {
		return err
	}
	if v.GlobalID == 0 {
		return errors.New("global_id must be explicit and nonzero")
	}
	if v.SenderAgentID == v.RecipientAgentID {
		return errors.New("Gift participants must differ")
	}
	if err := validateAddress(v.SenderAgentAccount); err != nil {
		return fmt.Errorf("sender Agent Account: %w", err)
	}
	if v.RequestedValidUntil == 0 {
		return errors.New("requested_valid_until is required")
	}
	return nil
}

func (v GiftAddressResponseV1) Validate() error {
	if v.Schema != SchemaAddressResponse {
		return errors.New("invalid Gift address response schema")
	}
	if err := validateCommon(v.Network, v.GiftIntentID, v.SenderAgentID, v.RecipientAgentID, v.AssetKind, v.AmountAtomic); err != nil {
		return err
	}
	if v.GlobalID == 0 || !digestPattern.MatchString(v.RequestDigest) {
		return errors.New("invalid request binding")
	}
	if err := validateAddress(v.DestinationAddress); err != nil {
		return fmt.Errorf("destination: %w", err)
	}
	if v.ResponseNotAfter == 0 {
		return errors.New("response_not_after is required")
	}
	return nil
}

func (v GiftSignedBOCOfferV1) Validate() error {
	if v.Schema != SchemaSignedBOCOffer || !hex256Pattern.MatchString(v.GiftIntentID) {
		return errors.New("invalid signed BOC offer identity")
	}
	if !digestPattern.MatchString(v.AddressRequestDigest) || !digestPattern.MatchString(v.AddressResponseDigest) || !digestPattern.MatchString(v.SignedGiftID) {
		return errors.New("invalid signed BOC offer digest")
	}
	if len(v.ExactSignedBOC) == 0 || len(v.ExactSignedBOC) > MaxSignedBOCBytes {
		return errors.New("exact signed BOC has invalid size")
	}
	if len(v.DisplayMessage) > MaxDisplayMessageBytes || strings.TrimSpace(v.DisplayMessage) != v.DisplayMessage {
		return errors.New("display message is not bounded canonical text")
	}
	if len(v.Padding) > MaxPaddingBytes {
		return errors.New("Gift padding exceeds limit")
	}
	want := SignedGiftID(v.ExactSignedBOC)
	if v.SignedGiftID != want {
		return errors.New("SignedGiftID does not match exact BOC bytes")
	}
	return nil
}

func (v OwnerAuthorizationV1) Validate() error {
	if !validNetwork(v.Network) || v.GlobalID == 0 || !hex256Pattern.MatchString(v.GiftIntentID) || !validAgent(v.RecipientAgentID) {
		return errors.New("invalid owner authorization identity")
	}
	if err := validateAddress(v.SenderAgentAccount); err != nil {
		return err
	}
	if err := validateAddress(v.OwnerWallet); err != nil {
		return err
	}
	if err := validateAddress(v.DestinationAddress); err != nil {
		return err
	}
	if v.ControllerKeyID == "" || len(v.ControllerKeyID) > 128 || !digestPattern.MatchString(v.DeploymentID) || v.ValidUntil == 0 {
		return errors.New("invalid owner authorization controller or validity")
	}
	if _, err := ParseActionAmount(v.AmountAtomic); err != nil {
		return err
	}
	if _, err := ParseAmount(v.FeeReserveAtomic); err != nil {
		return err
	}
	if !digestPattern.MatchString(v.AddressRequestDigest) || !digestPattern.MatchString(v.AddressResponseDigest) {
		return errors.New("invalid owner authorization digest")
	}
	return nil
}

func (v UnsignedTransferV1) Validate() error {
	if !validNetwork(v.Network) || v.GlobalID == 0 || !digestPattern.MatchString(v.DeploymentID) || v.ValidUntil == 0 || v.SendMode != 3 || v.Bounce {
		return errors.New("invalid native transfer profile")
	}
	if err := validateAddress(v.SenderAgentAccount); err != nil {
		return err
	}
	if err := validateAddress(v.DestinationAddress); err != nil {
		return err
	}
	_, err := ParseActionAmount(v.AmountAtomic)
	return err
}

func BindResponse(request GiftAddressRequestV1, response GiftAddressResponseV1) error {
	if err := request.Validate(); err != nil {
		return canonicalError(err)
	}
	if err := response.Validate(); err != nil {
		return canonicalError(err)
	}
	digest, err := RequestDigest(request)
	if err != nil {
		return canonicalError(err)
	}
	if response.RequestDigest != digest || response.Network != request.Network || response.GlobalID != request.GlobalID || response.GiftIntentID != request.GiftIntentID || response.SenderAgentID != request.SenderAgentID || response.RecipientAgentID != request.RecipientAgentID || response.AssetKind != request.AssetKind || response.AmountAtomic != request.AmountAtomic {
		return NewError(ErrIntentConflict, RetryNever, errors.New("Gift address response does not bind the complete request"))
	}
	if response.ResponseNotAfter > request.RequestedValidUntil {
		return NewError(ErrIntentConflict, RetryNever, errors.New("response validity exceeds request validity"))
	}
	return nil
}

func canonicalError(cause error) error {
	if cause == nil {
		return nil
	}
	var typed TypedError
	if errors.As(cause, &typed) {
		return cause
	}
	return NewError(ErrInvalidCanonical, RetryNever, cause)
}

func ParseAmount(value string) (uint64, error) {
	if len(value) == 0 || len(value) > MaxAmountDigits || !amountPattern.MatchString(value) {
		return 0, errors.New("amount_atomic is not canonical positive decimal")
	}
	amount, err := strconv.ParseUint(value, 10, 64)
	if err != nil || amount == 0 {
		return 0, errors.New("amount_atomic exceeds uint64 or is zero")
	}
	return amount, nil
}

func ParseActionAmount(value string) (uint64, error) {
	amount, err := ParseAmount(value)
	if err != nil {
		return 0, err
	}
	if amount > MaxAgentAccountActionAtomic {
		return 0, errors.New("amount_atomic exceeds Agent Account signed-action wire limit")
	}
	return amount, nil
}

func RequestDigest(v GiftAddressRequestV1) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(DomainAddressRequest, v)
}
func ResponseDigest(v GiftAddressResponseV1) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(DomainAddressResponse, v)
}
func OwnerAuthorizationDigest(v OwnerAuthorizationV1) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(DomainOwnerAuthorization, v)
}
func OwnerCancellationAuthorizationDigest(v OwnerCancellationAuthorizationV1) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(DomainOwnerCancellation, v)
}
func UnsignedTransferDigest(v UnsignedTransferV1) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}
	return codec.Digest(DomainUnsignedTransfer, v)
}
func ExactSignedBOCDigest(boc []byte) string { return rawDigest(DomainExactSignedBOC, boc) }
func SignedGiftID(boc []byte) string         { return rawDigest(DomainSignedGift, boc) }

func rawDigest(domain string, value []byte) string {
	h := sha256.New()
	h.Write([]byte("TOS-AGENT-GIFT-RAW"))
	h.Write([]byte{0})
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(domain)))
	h.Write(size[:])
	h.Write([]byte(domain))
	var valueSize [8]byte
	binary.BigEndian.PutUint64(valueSize[:], uint64(len(value)))
	h.Write(valueSize[:])
	h.Write(value)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func validateCommon(network, intent, sender, recipient, asset, amount string) error {
	if !validNetwork(network) || !hex256Pattern.MatchString(intent) || !validAgent(sender) || !validAgent(recipient) || asset != AssetNativeTOS {
		return errors.New("invalid Gift request identity or asset")
	}
	_, err := ParseActionAmount(amount)
	return err
}
func validNetwork(v string) bool {
	return v != "" && len(v) <= MaxNetworkBytes && strings.TrimSpace(v) == v
}
func validAgent(v string) bool { return len(v) <= MaxAgentIDBytes && agentIDPattern.MatchString(v) }
func validateAddress(value string) error {
	if value == "" || len(value) > MaxAddressBytes || strings.TrimSpace(value) != value {
		return errors.New("invalid canonical TOS address")
	}
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 {
		return errors.New("invalid canonical TOS std address")
	}
	if parsed.StringRaw() != value {
		return errors.New("TOS address must use canonical raw form")
	}
	return nil
}
