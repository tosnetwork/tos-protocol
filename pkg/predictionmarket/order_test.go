package predictionmarket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func testHash(fill byte) Hash32 {
	var result Hash32
	for index := range result {
		result[index] = fill
	}
	return result
}

func testAddress(fill byte) string {
	return "0:" + strings.Repeat(hex.EncodeToString([]byte{fill}), 32)
}

func testOrder() PredictionOrderV1 {
	counterparty := testAddress(0x33)
	return PredictionOrderV1{
		GlobalID: 42, WorkchainID: 0, MarketAddress: testAddress(0x11), MarketConfigHash: testHash(0x44),
		OwnerAddress: testAddress(0x22), KeyEpoch: 7, Nonce: 19, Salt: testHash(0x55), Action: ActionBuy,
		Outcome: OutcomeYes, LiquidityRole: RoleMaker, QuantityLots: 100, MinFillLots: 10, AllowPartial: true,
		LimitPriceTick: 6_250, ValidAfter: 1_700_000_000, ValidUntil: 1_700_003_600,
		OptionalCounterparty: &counterparty,
	}
}

func testPrivateKey() ed25519.PrivateKey {
	seed := bytes.Repeat([]byte{0x6d}, ed25519.SeedSize)
	return ed25519.NewKeyFromSeed(seed)
}

func TestPredictionOrderCanonicalRoundTripAndSignature(t *testing.T) {
	order := testOrder()
	orderCell, err := BuildPredictionOrderCell(order)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePredictionOrderV1(orderCell)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.MarketAddress != order.MarketAddress || decoded.OwnerAddress != order.OwnerAddress ||
		decoded.OptionalCounterparty == nil || *decoded.OptionalCounterparty != *order.OptionalCounterparty {
		t.Fatalf("order binding changed during round trip: %#v", decoded)
	}

	signedCell, signedDigest, err := SignPredictionOrder(order, testPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := DecodeAndVerifySignedPredictionOrder(signedCell)
	if err != nil {
		t.Fatal(err)
	}
	if verified.OrderDigest != signedDigest || verified.OrderCellHash != cellHash(orderCell) {
		t.Fatal("signed order returned the wrong hashes")
	}
	if verified.OrderDigest == verified.OrderCellHash {
		t.Fatal("authorization digest must not collapse to the payload hash")
	}
}

func TestPredictionOrderSignatureCommitsEveryEconomicField(t *testing.T) {
	original := testOrder()
	originalCell, err := BuildPredictionOrderCell(original)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := PredictionOrderDigest(originalCell)
	if err != nil {
		t.Fatal(err)
	}
	privateKey := testPrivateKey()
	signature := ed25519.Sign(privateKey, digest[:])

	tampered := original
	tampered.LimitPriceTick++
	tamperedCell, err := BuildPredictionOrderCell(tampered)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	signatureCell := cell.BeginCell().MustStoreSlice(signature, 512).EndCell()
	forged := cell.BeginCell().MustStoreUInt(signedOrderMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(publicKey, 256).MustStoreRef(tamperedCell).MustStoreRef(signatureCell).EndCell()
	if _, err := DecodeAndVerifySignedPredictionOrder(forged); err == nil {
		t.Fatal("signature unexpectedly authorized a changed price")
	}
}

func TestPredictionOrderRejectsTrailingData(t *testing.T) {
	orderCell, err := BuildPredictionOrderCell(testOrder())
	if err != nil {
		t.Fatal(err)
	}
	withTrailingBit := orderCell.ToBuilder().MustStoreBoolBit(false).EndCell()
	if _, err := DecodePredictionOrderV1(withTrailingBit); err == nil {
		t.Fatal("order with a trailing bit was accepted")
	}

	signedCell, _, err := SignPredictionOrder(testOrder(), testPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	s := signedCell.MustBeginParse()
	s.MustLoadUInt(32)
	s.MustLoadUInt(16)
	publicKey := s.MustLoadSlice(256)
	payload, err := s.LoadRefCell()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := s.LoadRefCell()
	if err != nil {
		t.Fatal(err)
	}
	badSignature := signature.ToBuilder().MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	malformed := cell.BeginCell().MustStoreUInt(signedOrderMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(publicKey, 256).MustStoreRef(payload).MustStoreRef(badSignature).EndCell()
	if _, err := DecodeAndVerifySignedPredictionOrder(malformed); err == nil {
		t.Fatal("signature cell with a trailing reference was accepted")
	}
}

func TestPredictionOrderValidationBoundaries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*PredictionOrderV1)
	}{
		{"zero price", func(value *PredictionOrderV1) { value.LimitPriceTick = 0 }},
		{"payout price", func(value *PredictionOrderV1) { value.LimitPriceTick = PriceScale }},
		{"invalid outcome", func(value *PredictionOrderV1) { value.Outcome = OutcomeInvalid }},
		{"empty interval", func(value *PredictionOrderV1) { value.ValidAfter = value.ValidUntil }},
		{"zero quantity", func(value *PredictionOrderV1) { value.QuantityLots = 0 }},
		{"minimum exceeds quantity", func(value *PredictionOrderV1) { value.MinFillLots = value.QuantityLots + 1 }},
		{"zero config", func(value *PredictionOrderV1) { value.MarketConfigHash = Hash32{} }},
		{"zero salt", func(value *PredictionOrderV1) { value.Salt = Hash32{} }},
		{"market workchain mismatch", func(value *PredictionOrderV1) { value.WorkchainID = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := testOrder()
			test.mutate(&value)
			if _, err := BuildPredictionOrderCell(value); err == nil {
				t.Fatal("invalid order was accepted")
			}
		})
	}
}

func TestTradingKeyAdmissionRejectsWeakAndNonCanonicalKeys(t *testing.T) {
	valid := testPrivateKey().Public().(ed25519.PublicKey)
	if err := ValidateTradingPublicKey(valid); err != nil {
		t.Fatalf("valid public key rejected: %v", err)
	}
	for index, denied := range ed25519SmallOrderEncodings {
		if err := ValidateTradingPublicKey(denied[:]); err == nil {
			t.Fatalf("small-order encoding %d was accepted", index)
		}
	}
	nonCanonical := bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize)
	if err := ValidateTradingPublicKey(nonCanonical); err == nil {
		t.Fatal("non-canonical public key was accepted")
	}
}
