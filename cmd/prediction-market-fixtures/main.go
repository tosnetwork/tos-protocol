// Command prediction-market-fixtures emits deterministic cross-language
// PredictionMarket V1 cell, digest, signature, and rejection vectors.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	pm "github.com/tosnetwork/tos-service-protocol/pkg/predictionmarket"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type cellVector struct {
	Name          string         `json:"name"`
	LogicalFields map[string]any `json:"logical_fields"`
	BOCBase64     string         `json:"boc_base64"`
	CellHash      string         `json:"cell_hash"`
	BOCSHA256     string         `json:"boc_sha256"`
}

type negativeVector struct {
	Name      string `json:"name"`
	Target    string `json:"target"`
	Mutation  string `json:"mutation"`
	BOCBase64 string `json:"boc_base64,omitempty"`
	Expected  string `json:"expected"`
}

type document struct {
	Schema          string           `json:"schema"`
	SchemaVersion   uint16           `json:"schema_version"`
	PriceScale      uint16           `json:"price_scale"`
	OrderDigest     string           `json:"order_digest"`
	PublicKeyHex    string           `json:"public_key_hex"`
	SignatureHex    string           `json:"signature_hex"`
	PositiveVectors []cellVector     `json:"positive_vectors"`
	NegativeVectors []negativeVector `json:"negative_vectors"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: prediction-market-fixtures OUTPUT")
	}
	market := address(0x11)
	owner := address(0x22)
	counterparty := address(0x33)
	order := pm.PredictionOrderV1{GlobalID: 42, WorkchainID: 0, MarketAddress: market, MarketConfigHash: hash(0x44),
		OwnerAddress: owner, KeyEpoch: 7, Nonce: 19, Salt: hash(0x55), Action: pm.ActionBuy, Outcome: pm.OutcomeYes,
		LiquidityRole: pm.RoleMaker, QuantityLots: 100, MinFillLots: 10, AllowPartial: true, LimitPriceTick: 6_250,
		ValidAfter: 1_700_000_000, ValidUntil: 1_700_003_600, OptionalCounterparty: &counterparty}
	orderCell := mustCell(pm.BuildPredictionOrderCell(order))
	authorizationCell := mustCell(pm.BuildOrderAuthorizationCell(orderCell))
	seed := bytesOf(0x6d, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	signedCell, digest, err := pm.SignPredictionOrder(order, privateKey)
	must(err)
	signed := mustSigned(pm.DecodeAndVerifySignedPredictionOrder(signedCell))

	marketID, rulesHash := hash(0x61), hash(0x62)
	normalContext := pm.PredictionNormalContextV1{MarketID: marketID, RulesHash: rulesHash, NormalRoundNonce: hash(0x63),
		NormalRoundOpenedAt: 1_700_010_000, ResolveNotBefore: 1_700_010_100, OracleVoteDeadline: 1_700_011_000}
	normalContextCell := mustCell(pm.BuildPredictionNormalContextCell(normalContext))
	contentDigest := hash(0x70)
	evidenceEntry := pm.EvidenceEntryV1{SourceKind: pm.SourceHTTPS, CanonicalSourceID: "https://results.example/election/final",
		ContentDigest: contentDigest, ArchiveLocator: "tos-cas-sha256:" + hex.EncodeToString(contentDigest[:]),
		PublicationTimeSeconds: 1_700_010_200, EventTimeSeconds: 1_700_010_100, ParserProfileVersion: "election-result/v1"}
	evidence := pm.PredictionEvidenceManifestV1{MarketID: marketID, RulesHash: rulesHash,
		RoundContextHash: cellHash(normalContextCell), Outcome: pm.OutcomeYes, Entries: []pm.EvidenceEntryV1{evidenceEntry}}
	evidenceCell := mustCell(pm.BuildPredictionEvidenceManifestCell(evidence))
	challengeEvidence := pm.PredictionChallengeEvidenceManifestV1{MarketID: marketID, RulesHash: rulesHash,
		ProposedStatementHash: hash(0x72), CounterOutcome: pm.OutcomeNo, Entries: []pm.EvidenceEntryV1{evidenceEntry}}
	challengeEvidenceCell := mustCell(pm.BuildPredictionChallengeEvidenceManifestCell(challengeEvidence))
	reviewBase := pm.PredictionReviewBaseContextV1{MarketID: marketID, RulesHash: rulesHash, Reason: pm.ReviewChallenge,
		ReviewStartedAt: 1_700_011_100, ReviewVoteNotBefore: 1_700_011_400, AppealDeadline: 1_700_012_000,
		Challenge: &pm.PredictionChallengeReviewV1{ProposedStatementHash: hash(0x72), ProposedOutcome: pm.OutcomeYes,
			ProposedEvidenceRoot: cellHash(evidenceCell), ChallengerAddress: address(0x77), CounterOutcome: pm.OutcomeNo,
			CounterEvidenceRoot: cellHash(challengeEvidenceCell)}}
	reviewBaseCell := mustCell(pm.BuildPredictionReviewBaseContextCell(reviewBase))
	reviewVote := pm.PredictionReviewVoteContextV1{ReviewBaseContextHash: cellHash(reviewBaseCell),
		ReviewRoundNonce: hash(0x73), ReviewRoundOpenedAt: 1_700_011_400}
	reviewVoteCell := mustCell(pm.BuildPredictionReviewVoteContextCell(reviewVote))
	statement := pm.PredictionResolutionStatementV1{GlobalID: 42, MarketAddress: market, MarketID: marketID,
		RulesHash: rulesHash, RoundPolicyHash: hash(0x74), RoundContextHash: cellHash(reviewVoteCell), Round: pm.RoundAppeal,
		Outcome: pm.OutcomeNo, EvidenceRoot: cellHash(challengeEvidenceCell), StatementCreatedAt: 1_700_011_500,
		StatementExpiry: 1_700_011_900}
	statementCell := mustCell(pm.BuildPredictionResolutionStatementCell(statement))

	trailingOrder := orderCell.ToBuilder().MustStoreBoolBit(false).EndCell()
	signatureSlice := signedCell.MustBeginParse()
	signatureSlice.MustLoadUInt(32)
	signatureSlice.MustLoadUInt(16)
	signatureSlice.MustLoadSlice(256)
	signatureSlice.MustLoadRef()
	signatureCell, err := signatureSlice.LoadRefCell()
	must(err)
	trailingSignature := signatureCell.ToBuilder().MustStoreRef(cell.BeginCell().EndCell()).EndCell()
	malformedSigned := cell.BeginCell().MustStoreUInt(0x50534f31, 32).MustStoreUInt(uint64(pm.SchemaVersion), 16).
		MustStoreSlice(signed.PublicKey[:], 256).MustStoreRef(orderCell).MustStoreRef(trailingSignature).EndCell()

	doc := document{Schema: "tos.prediction-market-conformance.v1", SchemaVersion: pm.SchemaVersion,
		PriceScale: pm.PriceScale, OrderDigest: digest.CellHashString(), PublicKeyHex: hex.EncodeToString(signed.PublicKey[:]),
		SignatureHex: hex.EncodeToString(signed.Signature[:]), PositiveVectors: []cellVector{
			vector("prediction-order", orderCell, map[string]any{"global_id": 42, "workchain_id": 0, "market_address": market,
				"market_config_hash": order.MarketConfigHash.SHA256String(), "owner_address": owner, "key_epoch": 7, "nonce": 19,
				"salt": order.Salt.SHA256String(), "action": "buy", "outcome": "yes", "liquidity_role": "maker",
				"quantity_lots": 100, "min_fill_lots": 10, "allow_partial": true, "limit_price_tick": 6_250,
				"valid_after": 1_700_000_000, "valid_until": 1_700_003_600, "counterparty": counterparty}),
			vector("order-authorization", authorizationCell, map[string]any{"order_cell_hash": cellHash(orderCell).CellHashString(),
				"contract_code_version": pm.ContractCodeVersion}),
			vector("signed-prediction-order", signedCell, map[string]any{"order_digest": digest.CellHashString()}),
			vector("normal-round-context", normalContextCell, map[string]any{"market_id": marketID.SHA256String(), "rules_hash": rulesHash.SHA256String()}),
			vector("normal-evidence-manifest", evidenceCell, map[string]any{"outcome": "yes", "entry_count": 1}),
			vector("challenge-evidence-manifest", challengeEvidenceCell, map[string]any{"counter_outcome": "no", "entry_count": 1}),
			vector("review-base-context", reviewBaseCell, map[string]any{"reason": "challenge"}),
			vector("review-vote-context", reviewVoteCell, map[string]any{"review_base_context_hash": cellHash(reviewBaseCell).CellHashString()}),
			vector("resolution-statement", statementCell, map[string]any{"round": "appeal", "outcome": "no"}),
		}, NegativeVectors: []negativeVector{
			{Name: "order-trailing-bit", Target: "prediction-order", Mutation: "append one zero bit to the root", BOCBase64: boc(trailingOrder), Expected: "reject"},
			{Name: "signature-trailing-reference", Target: "signed-prediction-order", Mutation: "append an empty ref to the signature cell", BOCBase64: boc(malformedSigned), Expected: "reject"},
			{Name: "order-signature-over-payload-hash", Target: "signed-prediction-order", Mutation: "sign order_cell_hash instead of order_digest", Expected: "reject"},
			{Name: "evidence-mutable-locator", Target: "normal-evidence-manifest", Mutation: "replace content-addressed locator with mutable HTTPS URL", Expected: "reject"},
			{Name: "review-missing-challenge-provenance", Target: "review-base-context", Mutation: "encode CHALLENGE without proposal/challenger/counter evidence", Expected: "reject"},
		}}
	raw, err := json.MarshalIndent(doc, "", "  ")
	must(err)
	must(os.WriteFile(os.Args[1], append(raw, '\n'), 0o644))
}

func vector(name string, value *cell.Cell, fields map[string]any) cellVector {
	serialized := value.ToBOC()
	digest := sha256.Sum256(serialized)
	return cellVector{Name: name, LogicalFields: fields, BOCBase64: base64.StdEncoding.EncodeToString(serialized),
		CellHash: "tvm-cell-sha256:" + hex.EncodeToString(value.Hash()), BOCSHA256: "sha256:" + hex.EncodeToString(digest[:])}
}

func boc(value *cell.Cell) string { return base64.StdEncoding.EncodeToString(value.ToBOC()) }

func cellHash(value *cell.Cell) pm.Hash32 {
	var result pm.Hash32
	copy(result[:], value.Hash())
	return result
}

func hash(value byte) pm.Hash32 {
	var result pm.Hash32
	for index := range result {
		result[index] = value
	}
	return result
}

func address(value byte) string { return "0:" + strings.Repeat(fmt.Sprintf("%02x", value), 32) }

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustCell(value *cell.Cell, err error) *cell.Cell { must(err); return value }
func mustSigned(value *pm.SignedPredictionOrderV1, err error) *pm.SignedPredictionOrderV1 {
	must(err)
	return value
}
