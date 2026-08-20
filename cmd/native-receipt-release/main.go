// Command native-receipt-release builds a canonical software-work Receipt and
// settlement intent, then optionally verifies an external Ed25519 signature
// and emits the release body. It never reads or handles a private key.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"

	"github.com/tosnetwork/tos-service-protocol/internal/referencecodec"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
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
	var value struct {
		Quote            string `json:"quote_commitment"`
		Execution        string `json:"execution_id"`
		Input            string `json:"input_digest"`
		Result           string `json:"result_digest"`
		Source           string `json:"source_digest"`
		Toolchain        string `json:"toolchain_digest"`
		Sandbox          string `json:"sandbox_digest"`
		Artifact, Report descriptor
		Completed        uint64 `json:"completed_at_unix"`
		ExitCode         *int32 `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if value.ExitCode == nil || *value.ExitCode != 0 {
		return errors.New("execution outcome is not successful")
	}
	*o = outcome{value.Quote, value.Execution, value.Input, value.Result, value.Source,
		value.Toolchain, value.Sandbox, value.Artifact, value.Report, value.Completed}
	return nil
}

type signingPackage struct {
	Schema                   string `json:"schema"`
	ReceiptCommitment        string `json:"receipt_commitment"`
	ReceiptBOCBase64         string `json:"receipt_boc_base64"`
	SettlementIntent         string `json:"settlement_intent"`
	SigningPayloadHex        string `json:"signing_payload_hex"`
	ExecutionSignerPublicKey string `json:"execution_signer_public_key_hex"`
	QueryID                  uint64 `json:"query_id"`
	SignatureHex             string `json:"signature_hex,omitempty"`
	ReleaseBodyBOCBase64     string `json:"release_body_boc_base64,omitempty"`
}

type externalSignature struct {
	Schema       string `json:"schema"`
	Algorithm    string `json:"algorithm"`
	PublicKeyHex string `json:"public_key_hex"`
	MessageHex   string `json:"message_hex"`
	SignatureHex string `json:"signature_hex"`
}

func buildSigningPackage(out outcome, vector referencecodec.QuoteVector, escrow string, query uint64) (signingPackage, *cell.Cell, error) {
	quote, quoteCommitment, err := referencecodec.ComputeAcceptedQuote(vector)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("rebuild Accepted Quote: %w", err)
	}
	if quoteCommitment != vector.Expected.Commitment || out.Quote != quoteCommitment {
		return signingPackage{}, nil, errors.New("execution outcome does not bind the canonical Accepted Quote")
	}
	expectedBOC, err := base64.StdEncoding.DecodeString(vector.Expected.BOCBase64)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("decode expected Quote BOC: %w", err)
	}
	expectedQuote, err := cell.FromBOC(expectedBOC)
	if err != nil || !equalBytes(expectedQuote.Hash(), quote.Hash()) {
		return signingPackage{}, nil, errors.New("expected Quote BOC does not match the canonical encoder")
	}
	receipt, commitment, err := nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: out.Quote, ExecutionID: out.Execution, InputDigest: out.Input,
		ResultDigest: out.Result, ArtifactDigest: out.Artifact.Digest, ReportDigest: out.Report.Digest,
		SourceDigest: out.Source, ToolchainDigest: out.Toolchain, SandboxDigest: out.Sandbox,
		ChargedAtomicAmount: vector.Quote.MaximumAtomicAmount, ProviderAgentID: vector.Quote.ProviderAgentID,
		CompletedAt: out.Completed, ExitCode: 0,
	})
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("build Receipt: %w", err)
	}
	amount, ok := new(big.Int).SetString(vector.Quote.MaximumAtomicAmount, 10)
	if !ok {
		return signingPackage{}, nil, errors.New("invalid Quote amount")
	}
	intent, err := nativecore.BuildEscrowSettlementIntentV1(escrow, quote, receipt, amount, query)
	if err != nil {
		return signingPackage{}, nil, fmt.Errorf("build settlement intent: %w", err)
	}
	publicKey, err := hex.DecodeString(vector.Quote.ExecutionSignerPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return signingPackage{}, nil, errors.New("invalid Quote execution signer public key")
	}
	return signingPackage{
		Schema:            "tos.service.software-work-settlement-signing.v1",
		ReceiptCommitment: commitment, ReceiptBOCBase64: base64.StdEncoding.EncodeToString(receipt.ToBOC()),
		SettlementIntent:         "tvm-cell-sha256:" + hex.EncodeToString(intent.Hash()),
		SigningPayloadHex:        hex.EncodeToString(intent.Hash()),
		ExecutionSignerPublicKey: hex.EncodeToString(publicKey), QueryID: query,
	}, receipt, nil
}

func applyExternalSignature(value *signingPackage, receipt *cell.Cell, path string) error {
	var signed externalSignature
	if err := decode(path, &signed); err != nil {
		return fmt.Errorf("decode external signature: %w", err)
	}
	if signed.Schema != "tosctl-ed25519-signature-v1" || signed.Algorithm != "Ed25519" ||
		signed.PublicKeyHex != value.ExecutionSignerPublicKey || signed.MessageHex != value.SigningPayloadHex {
		return errors.New("external signature metadata does not match the settlement intent")
	}
	publicKey, err := hex.DecodeString(signed.PublicKeyHex)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("invalid external signature public key")
	}
	signature, err := hex.DecodeString(signed.SignatureHex)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("invalid external signature encoding")
	}
	payload, _ := hex.DecodeString(value.SigningPayloadHex)
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("external signature verification failed")
	}
	body, err := nativecore.BuildEscrowReleaseBodyV1(value.QueryID, receipt, signature)
	if err != nil {
		return fmt.Errorf("build release body: %w", err)
	}
	value.Schema = "tos.service.software-work-settlement-release.v1"
	value.SignatureHex = signed.SignatureHex
	value.ReleaseBodyBOCBase64 = base64.StdEncoding.EncodeToString(body.ToBOC())
	return nil
}

func main() {
	outPath := flag.String("outcome", "", "successful outcome JSON")
	quotePath := flag.String("quote-vector", "", "canonical Accepted Quote vector")
	escrow := flag.String("escrow", "", "escrow address")
	query := flag.Uint64("query-id", 0, "non-zero query ID")
	signaturePath := flag.String("signature-file", "", "optional tosctl wallet sign JSON")
	flag.Parse()
	var out outcome
	if err := decode(*outPath, &out); err != nil {
		fail(err)
	}
	var vector referencecodec.QuoteVector
	if err := decode(*quotePath, &vector); err != nil {
		fail(err)
	}
	result, receipt, err := buildSigningPackage(out, vector, *escrow, *query)
	if err != nil {
		fail(err)
	}
	if *signaturePath != "" {
		if err := applyExternalSignature(&result, receipt, *signaturePath); err != nil {
			fail(err)
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fail(err)
	}
	fmt.Println(string(encoded))
}

func decode(path string, target any) error {
	if path == "" {
		return errors.New("required input path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return err
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for i := range left {
		difference |= left[i] ^ right[i]
	}
	return difference == 0
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
