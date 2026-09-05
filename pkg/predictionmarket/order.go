package predictionmarket

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	maxOrderCells = 6
	maxOrderDepth = 3
)

// PredictionOrderV1 is the only order payload that the V1 market accepts.
// Prices are integer ticks in (0, PriceScale); quantities are integer lots.
type PredictionOrderV1 struct {
	GlobalID             int32
	WorkchainID          int8
	MarketAddress        string
	MarketConfigHash     Hash32
	OwnerAddress         string
	KeyEpoch             uint32
	Nonce                uint64
	Salt                 Hash32
	Action               Action
	Outcome              Outcome
	LiquidityRole        LiquidityRole
	QuantityLots         uint64
	MinFillLots          uint64
	AllowPartial         bool
	LimitPriceTick       uint16
	ValidAfter           uint64
	ValidUntil           uint64
	OptionalCounterparty *string
}

// SignedPredictionOrderV1 contains an exact canonical order and its detached
// Ed25519 signature. Signature is over OrderDigest, not OrderCellHash.
type SignedPredictionOrderV1 struct {
	Order         PredictionOrderV1
	PublicKey     [ed25519.PublicKeySize]byte
	Signature     [ed25519.SignatureSize]byte
	OrderCellHash Hash32
	OrderDigest   Hash32
}

func validateOrder(value PredictionOrderV1) (*address.Address, *address.Address, *address.Address, error) {
	market, err := parseCanonicalAddress(value.MarketAddress)
	if err != nil || int8(market.Workchain()) != value.WorkchainID {
		return nil, nil, nil, errors.New("order market address does not match its workchain domain")
	}
	owner, err := parseCanonicalAddress(value.OwnerAddress)
	if err != nil {
		return nil, nil, nil, errors.New("invalid order owner address")
	}
	if value.WorkchainID != -1 && value.WorkchainID != 0 {
		return nil, nil, nil, errors.New("unsupported order workchain")
	}
	if value.MarketConfigHash.IsZero() || value.Salt.IsZero() {
		return nil, nil, nil, errors.New("order hashes and salt must be non-zero")
	}
	if !value.Action.valid() || (value.Outcome != OutcomeYes && value.Outcome != OutcomeNo) || !value.LiquidityRole.valid() {
		return nil, nil, nil, errors.New("invalid order enum")
	}
	if value.QuantityLots == 0 || value.MinFillLots == 0 || value.MinFillLots > value.QuantityLots {
		return nil, nil, nil, errors.New("invalid order quantity or minimum fill")
	}
	if value.LimitPriceTick == 0 || value.LimitPriceTick >= PriceScale {
		return nil, nil, nil, errors.New("order price must be strictly inside the payout interval")
	}
	if value.ValidUntil == 0 || value.ValidAfter >= value.ValidUntil {
		return nil, nil, nil, errors.New("order validity interval must be non-empty")
	}
	var counterparty *address.Address
	if value.OptionalCounterparty != nil {
		counterparty, err = parseCanonicalAddress(*value.OptionalCounterparty)
		if err != nil {
			return nil, nil, nil, errors.New("invalid order counterparty address")
		}
	}
	return market, owner, counterparty, nil
}

// BuildPredictionOrderCell returns the unique V1 cell tree for an order.
func BuildPredictionOrderCell(value PredictionOrderV1) (*cell.Cell, error) {
	market, owner, counterparty, err := validateOrder(value)
	if err != nil {
		return nil, err
	}
	marketBinding := cell.BeginCell().MustStoreAddr(market).
		MustStoreSlice(value.MarketConfigHash[:], 256).EndCell()
	ownerBuilder := cell.BeginCell().MustStoreAddr(owner).MustStoreBoolBit(counterparty != nil)
	if counterparty != nil {
		ownerBuilder.MustStoreAddr(counterparty)
	}
	ownerBinding := ownerBuilder.EndCell()
	root := cell.BeginCell().MustStoreUInt(orderMagic, 32).
		MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreInt(int64(value.GlobalID), 32).
		MustStoreInt(int64(value.WorkchainID), 8).
		MustStoreUInt(uint64(value.KeyEpoch), 32).
		MustStoreUInt(value.Nonce, 64).
		MustStoreSlice(value.Salt[:], 256).
		MustStoreUInt(value.QuantityLots, 64).
		MustStoreUInt(value.MinFillLots, 64).
		MustStoreUInt(uint64(value.LimitPriceTick), 16).
		MustStoreUInt(value.ValidAfter, 64).
		MustStoreUInt(value.ValidUntil, 64).
		MustStoreUInt(uint64(value.Action), 8).
		MustStoreUInt(uint64(value.Outcome), 8).
		MustStoreUInt(uint64(value.LiquidityRole), 8).
		MustStoreBoolBit(value.AllowPartial).
		MustStoreRef(marketBinding).
		MustStoreRef(ownerBinding).EndCell()
	if err := ensureBoundedOrdinaryDAG(root, maxOrderCells, maxOrderDepth); err != nil {
		return nil, err
	}
	return root, nil
}

// DecodePredictionOrderV1 fully consumes, validates, and canonically
// reconstructs the supplied cell tree.
func DecodePredictionOrderV1(root *cell.Cell) (*PredictionOrderV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, maxOrderCells, maxOrderDepth); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid prediction order cell")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != orderMagic {
		return nil, errors.New("invalid prediction order magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return nil, errors.New("unsupported prediction order schema")
	}
	globalID, err := s.LoadInt(32)
	if err != nil {
		return nil, errors.New("invalid order global id")
	}
	workchain, err := s.LoadInt(8)
	if err != nil {
		return nil, errors.New("invalid order workchain")
	}
	keyEpoch, err := s.LoadUInt(32)
	if err != nil {
		return nil, errors.New("invalid order key epoch")
	}
	nonce, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid order nonce")
	}
	salt, err := loadHash(s, "order salt")
	if err != nil {
		return nil, err
	}
	quantity, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid order quantity")
	}
	minimum, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid order minimum fill")
	}
	price, err := s.LoadUInt(16)
	if err != nil {
		return nil, errors.New("invalid order price")
	}
	validAfter, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid order start time")
	}
	validUntil, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid order expiry")
	}
	action, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid order action")
	}
	outcome, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid order outcome")
	}
	role, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid order liquidity role")
	}
	partial, err := s.LoadBoolBit()
	if err != nil {
		return nil, errors.New("invalid order partial-fill flag")
	}
	marketBinding, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing order market binding")
	}
	ownerBinding, err := s.LoadRefCell()
	if err != nil || finish(s, "prediction order") != nil {
		return nil, errors.New("invalid prediction order shape")
	}
	market, configHash, err := decodeMarketBinding(marketBinding)
	if err != nil {
		return nil, err
	}
	owner, counterparty, err := decodeOwnerBinding(ownerBinding)
	if err != nil {
		return nil, err
	}
	result := PredictionOrderV1{
		GlobalID: int32(globalID), WorkchainID: int8(workchain), MarketAddress: market,
		MarketConfigHash: configHash, OwnerAddress: owner, KeyEpoch: uint32(keyEpoch), Nonce: nonce,
		Salt: salt, Action: Action(action), Outcome: Outcome(outcome), LiquidityRole: LiquidityRole(role),
		QuantityLots: quantity, MinFillLots: minimum, AllowPartial: partial, LimitPriceTick: uint16(price),
		ValidAfter: validAfter, ValidUntil: validUntil, OptionalCounterparty: counterparty,
	}
	rebuilt, err := BuildPredictionOrderCell(result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("prediction order is not canonical")
	}
	return &result, nil
}

// BuildOrderAuthorizationCell constructs the domain-separated authorization
// preimage whose cell hash is the order digest.
func BuildOrderAuthorizationCell(orderCell *cell.Cell) (*cell.Cell, error) {
	order, err := DecodePredictionOrderV1(orderCell)
	if err != nil {
		return nil, err
	}
	market, err := parseCanonicalAddress(order.MarketAddress)
	if err != nil {
		return nil, err
	}
	binding := cell.BeginCell().MustStoreAddr(market).
		MustStoreSlice(order.MarketConfigHash[:], 256).
		MustStoreSlice(orderCell.Hash(), 256).EndCell()
	return cell.BeginCell().MustStoreUInt(orderAuthorizationMagic, 32).
		MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(orderDomainHash[:], 256).
		MustStoreInt(int64(order.GlobalID), 32).
		MustStoreInt(int64(order.WorkchainID), 8).
		MustStoreUInt(uint64(ContractCodeVersion), 16).
		MustStoreRef(binding).EndCell(), nil
}

func PredictionOrderDigest(orderCell *cell.Cell) (Hash32, error) {
	authorization, err := BuildOrderAuthorizationCell(orderCell)
	if err != nil {
		return Hash32{}, err
	}
	return cellHash(authorization), nil
}

// BuildSignedPredictionOrderCell verifies the key profile and signature before
// returning the canonical transport cell.
func BuildSignedPredictionOrderCell(orderCell *cell.Cell, publicKey, signature []byte) (*cell.Cell, error) {
	if err := ValidateTradingPublicKey(publicKey); err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize {
		return nil, errors.New("Ed25519 signature must be 64 bytes")
	}
	digest, err := PredictionOrderDigest(orderCell)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
		return nil, errors.New("invalid prediction order signature")
	}
	signatureCell := cell.BeginCell().MustStoreSlice(signature, 512).EndCell()
	return cell.BeginCell().MustStoreUInt(signedOrderMagic, 32).
		MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(publicKey, 256).
		MustStoreRef(orderCell).
		MustStoreRef(signatureCell).EndCell(), nil
}

func SignPredictionOrder(value PredictionOrderV1, privateKey ed25519.PrivateKey) (*cell.Cell, Hash32, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, Hash32{}, errors.New("Ed25519 private key must be 64 bytes")
	}
	orderCell, err := BuildPredictionOrderCell(value)
	if err != nil {
		return nil, Hash32{}, err
	}
	digest, err := PredictionOrderDigest(orderCell)
	if err != nil {
		return nil, Hash32{}, err
	}
	signature := ed25519.Sign(privateKey, digest[:])
	signed, err := BuildSignedPredictionOrderCell(orderCell, privateKey.Public().(ed25519.PublicKey), signature)
	return signed, digest, err
}

// DecodeAndVerifySignedPredictionOrder rejects malformed encodings before
// verifying the detached signature over the raw 32-byte order digest.
func DecodeAndVerifySignedPredictionOrder(root *cell.Cell) (*SignedPredictionOrderV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, maxOrderCells, maxOrderDepth); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid signed prediction order")
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != signedOrderMagic {
		return nil, errors.New("invalid signed prediction order magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return nil, errors.New("unsupported signed prediction order schema")
	}
	publicKey, err := s.LoadSlice(256)
	if err != nil || ValidateTradingPublicKey(publicKey) != nil {
		return nil, errors.New("invalid signed-order public key")
	}
	orderCell, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing signed-order payload")
	}
	signatureCell, err := s.LoadRefCell()
	if err != nil || finish(s, "signed prediction order") != nil {
		return nil, errors.New("invalid signed-order shape")
	}
	if err := ensureOrdinary(signatureCell); err != nil {
		return nil, err
	}
	sigSlice, err := signatureCell.BeginParse()
	if err != nil {
		return nil, errors.New("invalid signed-order signature cell")
	}
	signature, err := sigSlice.LoadSlice(512)
	if err != nil || finish(sigSlice, "prediction order signature") != nil {
		return nil, errors.New("signature cell must contain exactly 512 bits")
	}
	order, err := DecodePredictionOrderV1(orderCell)
	if err != nil {
		return nil, err
	}
	digest, err := PredictionOrderDigest(orderCell)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), digest[:], signature) {
		return nil, errors.New("invalid prediction order signature")
	}
	rebuilt, err := BuildSignedPredictionOrderCell(orderCell, publicKey, signature)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("signed prediction order is not canonical")
	}
	result := &SignedPredictionOrderV1{Order: *order, OrderCellHash: cellHash(orderCell), OrderDigest: digest}
	copy(result.PublicKey[:], publicKey)
	copy(result.Signature[:], signature)
	return result, nil
}

func decodeMarketBinding(value *cell.Cell) (string, Hash32, error) {
	if err := ensureOrdinary(value); err != nil {
		return "", Hash32{}, err
	}
	s, err := value.BeginParse()
	if err != nil {
		return "", Hash32{}, errors.New("invalid order market binding")
	}
	market, err := loadCanonicalAddress(s, "order market")
	if err != nil {
		return "", Hash32{}, err
	}
	config, err := loadHash(s, "market config hash")
	if err != nil || finish(s, "order market binding") != nil {
		return "", Hash32{}, errors.New("invalid order market binding shape")
	}
	return market, config, nil
}

func decodeOwnerBinding(value *cell.Cell) (string, *string, error) {
	if err := ensureOrdinary(value); err != nil {
		return "", nil, err
	}
	s, err := value.BeginParse()
	if err != nil {
		return "", nil, errors.New("invalid order owner binding")
	}
	owner, err := loadCanonicalAddress(s, "order owner")
	if err != nil {
		return "", nil, err
	}
	present, err := s.LoadBoolBit()
	if err != nil {
		return "", nil, errors.New("invalid counterparty presence tag")
	}
	var counterparty *string
	if present {
		decoded, err := loadCanonicalAddress(s, "order counterparty")
		if err != nil {
			return "", nil, err
		}
		counterparty = &decoded
	}
	if err := finish(s, "order owner binding"); err != nil {
		return "", nil, err
	}
	return owner, counterparty, nil
}

func loadCanonicalAddress(s *cell.Slice, what string) (string, error) {
	decoded, err := s.LoadAddr()
	if err != nil || decoded == nil || decoded.Type() != address.StdAddress || decoded.BitsLen() != 256 {
		return "", fmt.Errorf("invalid %s address", what)
	}
	raw := decoded.StringRaw()
	if _, err := parseCanonicalAddress(raw); err != nil {
		return "", fmt.Errorf("invalid %s address", what)
	}
	return raw, nil
}

func loadHash(s *cell.Slice, what string) (Hash32, error) {
	var result Hash32
	raw, err := s.LoadSlice(256)
	if err != nil {
		return result, fmt.Errorf("invalid %s", what)
	}
	copy(result[:], raw)
	return result, nil
}
