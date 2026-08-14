package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/tosnetwork/tos-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-protocol/pkg/nativecore"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type descriptor struct {
	Digest string `json:"Digest"`
}
type outcome struct {
	Quote, Execution, Input, Result, Source, Toolchain, Sandbox string
	Artifact, Report                                            descriptor
	Completed                                                   uint64
}

func (o *outcome) UnmarshalJSON(data []byte) error {
	var v struct {
		Quote            string `json:"quote_commitment"`
		Execution        string `json:"execution_id"`
		Input            string `json:"input_digest"`
		Result           string `json:"result_digest"`
		Source           string `json:"source_digest"`
		Toolchain        string `json:"toolchain_digest"`
		Sandbox          string `json:"sandbox_digest"`
		Artifact, Report descriptor
		Completed        uint64 `json:"completed_at_unix"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*o = outcome{v.Quote, v.Execution, v.Input, v.Result, v.Source, v.Toolchain, v.Sandbox, v.Artifact, v.Report, v.Completed}
	return nil
}

type identities struct {
	Identities []struct {
		Role string `json:"role"`
		Seed string `json:"private_seed_hex"`
	} `json:"identities"`
}

func main() {
	outPath := flag.String("outcome", "", "outcome JSON")
	quotePath := flag.String("quote-vector", "", "Quote vector")
	idsPath := flag.String("identities", "", "test identities")
	escrow := flag.String("escrow", "", "escrow address")
	query := flag.Uint64("query-id", 0, "non-zero query ID")
	flag.Parse()
	var out outcome
	decode(*outPath, &out)
	var vector referencecodec.QuoteVector
	decode(*quotePath, &vector)
	var ids identities
	decode(*idsPath, &ids)
	var seed []byte
	for _, v := range ids.Identities {
		if v.Role == "execution-signer" {
			seed, _ = hex.DecodeString(v.Seed)
		}
	}
	if len(seed) != 32 {
		fail(fmt.Errorf("execution signer seed unavailable"))
	}
	receipt, commitment, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{QuoteCommitment: out.Quote, ExecutionID: out.Execution, InputDigest: out.Input, ResultDigest: out.Result, ArtifactDigest: out.Artifact.Digest, ReportDigest: out.Report.Digest, SourceDigest: out.Source, ToolchainDigest: out.Toolchain, SandboxDigest: out.Sandbox, ChargedAtomicAmount: vector.Quote.MaximumAtomicAmount, ProviderAgentID: vector.Quote.ProviderAgentID, CompletedAt: out.Completed, ExitCode: 0})
	if err != nil {
		fail(err)
	}
	quoteBOC, err := base64.StdEncoding.DecodeString(vector.Expected.BOCBase64)
	if err != nil {
		fail(err)
	}
	quote, err := cell.FromBOC(quoteBOC)
	if err != nil {
		fail(err)
	}
	amount, _ := new(big.Int).SetString(vector.Quote.MaximumAtomicAmount, 10)
	intent, err := nativecore.BuildEscrowSettlementIntentV1(*escrow, quote, receipt, amount, *query)
	if err != nil {
		fail(err)
	}
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), intent.Hash())
	body, err := nativecore.BuildEscrowReleaseBodyV1(*query, receipt, signature)
	if err != nil {
		fail(err)
	}
	result := map[string]any{"receipt_commitment": commitment, "receipt_boc_base64": base64.StdEncoding.EncodeToString(receipt.ToBOC()), "settlement_intent": "tvm-cell-sha256:" + hex.EncodeToString(intent.Hash()), "signature_hex": hex.EncodeToString(signature), "release_body_boc_base64": base64.StdEncoding.EncodeToString(body.ToBOC()), "query_id": *query}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
}
func decode(path string, target any) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fail(err)
	}
	if err = json.Unmarshal(raw, target); err != nil {
		fail(err)
	}
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
