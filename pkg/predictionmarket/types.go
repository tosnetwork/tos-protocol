// Package predictionmarket implements the canonical off-chain objects and
// deterministic arithmetic shared by TOS PredictionMarket V1 clients.
//
// It deliberately does not treat an OpenFox Intent as spend authority. The
// only executable order authorization is the domain-separated TVM-cell digest
// produced by BuildOrderAuthorizationCell.
package predictionmarket

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/tosnetwork/tosutils-go/address"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

const (
	SchemaVersion           uint16 = 1
	ContractCodeVersion     uint16 = 1
	PriceScale              uint16 = 10_000
	MaxEvidenceEntries             = 32
	MaxSourceIDBytes               = 120
	MaxArchiveLocatorBytes         = 96
	MaxParserProfileBytes          = 96
	MaxCanonicalObjectCells        = 256
	MaxCanonicalObjectDepth        = 16
)

const (
	orderMagic              = 0x504f5231 // POR1
	signedOrderMagic        = 0x50534f31 // PSO1
	orderAuthorizationMagic = 0x504f4131 // POA1
	resolutionMagic         = 0x50525331 // PRS1
	normalContextMagic      = 0x504e4331 // PNC1
	reviewBaseMagic         = 0x50524231 // PRB1
	reviewVoteMagic         = 0x50525631 // PRV1
	evidenceManifestMagic   = 0x50454d31 // PEM1
	challengeManifestMagic  = 0x50434531 // PCE1
	evidenceEntryMagic      = 0x50454531 // PEE1
	evidenceMetaMagic       = 0x50454d54 // PEMT
	evidenceListMagic       = 0x50454c31 // PEL1
	textMagic               = 0x50545831 // PTX1
)

var (
	orderDomainHash      = sha256Bytes([]byte("TOS_PREDICTION_ORDER_V1"))
	resultDomainHash     = sha256Bytes([]byte("TOS_PREDICTION_RESULT_V1"))
	normalContextDomain  = sha256Bytes([]byte("TOS_PREDICTION_NORMAL_CONTEXT_V1"))
	reviewBaseDomain     = sha256Bytes([]byte("TOS_PREDICTION_REVIEW_BASE_CONTEXT_V1"))
	reviewVoteDomain     = sha256Bytes([]byte("TOS_PREDICTION_REVIEW_VOTE_CONTEXT_V1"))
	accountBindingDomain = []byte("TOS_PREDICTION_ACCOUNT_BINDING_V1")
	zeroHash             Hash32
)

type Hash32 [32]byte

func ParseHash32(value string) (Hash32, error) {
	var result Hash32
	for _, prefix := range []string{"sha256:", "tvm-cell-sha256:"} {
		if strings.HasPrefix(value, prefix) {
			raw, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
			if err != nil || len(raw) != len(result) {
				return result, errors.New("invalid 32-byte digest")
			}
			copy(result[:], raw)
			return result, nil
		}
	}
	return result, errors.New("digest must use sha256: or tvm-cell-sha256: prefix")
}

func (value Hash32) IsZero() bool           { return value == zeroHash }
func (value Hash32) SHA256String() string   { return "sha256:" + hex.EncodeToString(value[:]) }
func (value Hash32) CellHashString() string { return "tvm-cell-sha256:" + hex.EncodeToString(value[:]) }

func cellHash(value *cell.Cell) Hash32 {
	var result Hash32
	copy(result[:], value.Hash())
	return result
}

func sha256Bytes(value []byte) Hash32 {
	return sha256.Sum256(value)
}

// PredictionAccountBindingDigestV1 binds semantic custody fields to one
// canonical raw standard address without depending on display/base64 flags.
// The preimage is the ASCII domain, one two's-complement int8 workchain byte,
// and the 256-bit account ID.
func PredictionAccountBindingDigestV1(rawAddress string) (Hash32, error) {
	parsed, err := parseCanonicalAddress(rawAddress)
	if err != nil {
		return Hash32{}, err
	}
	preimage := make([]byte, 0, len(accountBindingDomain)+1+32)
	preimage = append(preimage, accountBindingDomain...)
	preimage = append(preimage, byte(int8(parsed.Workchain())))
	preimage = append(preimage, parsed.Data()...)
	return sha256Bytes(preimage), nil
}

type Action uint8

const (
	ActionBuy Action = iota
	ActionSell
)

func (value Action) valid() bool { return value == ActionBuy || value == ActionSell }

type Outcome uint8

const (
	OutcomeYes Outcome = iota
	OutcomeNo
	OutcomeInvalid
)

func (value Outcome) valid() bool { return value <= OutcomeInvalid }

type LiquidityRole uint8

const (
	RoleMaker LiquidityRole = iota
	RoleTaker
)

func (value LiquidityRole) valid() bool { return value == RoleMaker || value == RoleTaker }

type Round uint8

const (
	RoundNormal Round = iota
	RoundAppeal
)

func (value Round) valid() bool { return value == RoundNormal || value == RoundAppeal }

type ReviewReason uint8

const (
	ReviewNormalTimeout ReviewReason = iota
	ReviewChallenge
)

func (value ReviewReason) valid() bool {
	return value == ReviewNormalTimeout || value == ReviewChallenge
}

type SourceKind uint8

const (
	SourceHTTPS SourceKind = iota + 1
	SourceSignedDocument
	SourceTOSFinalized
)

func (value SourceKind) valid() bool {
	return value == SourceHTTPS || value == SourceSignedDocument || value == SourceTOSFinalized
}

func parseCanonicalAddress(value string) (*address.Address, error) {
	parsed, err := address.ParseRawAddr(value)
	if err != nil || parsed == nil || parsed.Type() != address.StdAddress || parsed.BitsLen() != 256 || parsed.StringRaw() != value {
		return nil, errors.New("address must be a canonical raw standard TOS address")
	}
	if parsed.Workchain() != -1 && parsed.Workchain() != 0 {
		return nil, errors.New("unsupported prediction-market workchain")
	}
	return parsed, nil
}

func ensureOrdinary(value *cell.Cell) error {
	if value == nil || value.GetType() != cell.OrdinaryCellType || value.Level() != 0 {
		return errors.New("prediction object contains a non-ordinary cell")
	}
	return nil
}

func ensureBoundedOrdinaryDAG(root *cell.Cell, maximumCells int, maximumDepth uint16) error {
	if root == nil || root.Depth() > maximumDepth {
		return errors.New("prediction object exceeds its cell-depth limit")
	}
	seen := make(map[*cell.Cell]struct{})
	stack := []*cell.Cell{root}
	for len(stack) != 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if _, ok := seen[current]; ok {
			continue
		}
		if err := ensureOrdinary(current); err != nil {
			return err
		}
		seen[current] = struct{}{}
		if len(seen) > maximumCells {
			return errors.New("prediction object exceeds its cell-count limit")
		}
		for index := uint(0); index < current.RefsNum(); index++ {
			next, err := current.PeekRef(int(index))
			if err != nil || next == nil {
				return errors.New("prediction object has an invalid reference")
			}
			stack = append(stack, next)
		}
	}
	return nil
}

func finish(slice *cell.Slice, what string) error {
	if slice.BitsLeft() != 0 || slice.RefsNum() != 0 {
		return fmt.Errorf("%s contains trailing data", what)
	}
	return nil
}

func textCell(value string, maximum int) (*cell.Cell, error) {
	if len(value) == 0 || len(value) > maximum || !canonicalASCII(value) {
		return nil, errors.New("invalid canonical prediction text")
	}
	builder := cell.BeginCell().MustStoreUInt(textMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreUInt(uint64(len(value)), 16)
	if err := builder.StoreSlice([]byte(value), uint(len(value))*8); err != nil {
		return nil, err
	}
	return builder.EndCell(), nil
}

func decodeText(value *cell.Cell, maximum int) (string, error) {
	if err := ensureOrdinary(value); err != nil {
		return "", err
	}
	s, err := value.BeginParse()
	if err != nil {
		return "", err
	}
	magic, err := s.LoadUInt(32)
	if err != nil || magic != textMagic {
		return "", errors.New("invalid prediction text magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return "", errors.New("unsupported prediction text schema")
	}
	length, err := s.LoadUInt(16)
	if err != nil || length == 0 || length > uint64(maximum) {
		return "", errors.New("invalid prediction text length")
	}
	raw, err := s.LoadSlice(uint(length) * 8)
	if err != nil || finish(s, "prediction text") != nil || !canonicalASCII(string(raw)) {
		return "", errors.New("invalid prediction text encoding")
	}
	return string(raw), nil
}

func canonicalASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func equalHash(left []byte, right Hash32) bool { return bytes.Equal(left, right[:]) }

// Curve and small-order validation is performed on public input, so big.Int
// arithmetic here does not create a secret-dependent timing boundary.
func ValidateTradingPublicKey(publicKey []byte) error {
	if len(publicKey) != 32 {
		return errors.New("Ed25519 public key must be 32 bytes")
	}
	for _, denied := range ed25519SmallOrderEncodings {
		if bytes.Equal(publicKey, denied[:]) {
			return errors.New("Ed25519 public key has small order")
		}
	}
	yBytes := append([]byte(nil), publicKey...)
	sign := yBytes[31] >> 7
	yBytes[31] &= 0x7f
	y := littleEndianInteger(yBytes)
	if y.Cmp(ed25519Prime) >= 0 {
		return errors.New("Ed25519 public key is non-canonical")
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, ed25519Prime)
	numerator := new(big.Int).Sub(y2, big.NewInt(1))
	numerator.Mod(numerator, ed25519Prime)
	denominator := new(big.Int).Mul(ed25519D, y2)
	denominator.Add(denominator, big.NewInt(1)).Mod(denominator, ed25519Prime)
	if denominator.Sign() == 0 {
		return errors.New("Ed25519 public key is off curve")
	}
	x2 := new(big.Int).Mul(numerator, new(big.Int).ModInverse(denominator, ed25519Prime))
	x2.Mod(x2, ed25519Prime)
	x := new(big.Int).Exp(x2, ed25519SqrtExponent, ed25519Prime)
	check := new(big.Int).Mul(x, x)
	check.Mod(check, ed25519Prime)
	if check.Cmp(x2) != 0 {
		x.Mul(x, ed25519SqrtM1).Mod(x, ed25519Prime)
		check.Mul(x, x).Mod(check, ed25519Prime)
	}
	if check.Cmp(x2) != 0 || (x.Sign() == 0 && sign == 1) {
		return errors.New("Ed25519 public key is off curve or non-canonical")
	}
	return nil
}

func littleEndianInteger(value []byte) *big.Int {
	reversed := append([]byte(nil), value...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	return new(big.Int).SetBytes(reversed)
}

var (
	ed25519Prime = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	ed25519D     = func() *big.Int {
		numerator := new(big.Int).Neg(big.NewInt(121665))
		inverse := new(big.Int).ModInverse(big.NewInt(121666), ed25519Prime)
		return numerator.Mul(numerator, inverse).Mod(numerator, ed25519Prime)
	}()
	ed25519SqrtExponent        = new(big.Int).Rsh(new(big.Int).Add(new(big.Int).Set(ed25519Prime), big.NewInt(3)), 3)
	ed25519SqrtM1              = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(new(big.Int).Set(ed25519Prime), big.NewInt(1)), 2), ed25519Prime)
	ed25519SmallOrderEncodings = [][32]byte{
		mustDecodeKey("0100000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
		mustDecodeKey("0000000000000000000000000000000000000000000000000000000000000080"),
		mustDecodeKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
		mustDecodeKey("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
		mustDecodeKey("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
		mustDecodeKey("0000000000000000000000000000000000000000000000000000000000000000"),
		mustDecodeKey("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
	}
)

func mustDecodeKey(value string) [32]byte {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		panic("invalid built-in Ed25519 key encoding")
	}
	var result [32]byte
	copy(result[:], decoded)
	return result
}
