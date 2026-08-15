// Command native-safe-handoff-pack combines portable Quote preimages and the
// buyer-held Receipt signing package into the strict checker input format.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type signingPackage struct {
	ReceiptBOCBase64         string `json:"receipt_boc_base64"`
	ExecutionSignerPublicKey string `json:"execution_signer_public_key_hex"`
	QueryID                  uint64 `json:"query_id"`
	SignatureHex             string `json:"signature_hex"`
}

type document struct {
	Schema                      string          `json:"schema"`
	Network                     json.RawMessage `json:"network"`
	QuoteRequest                json.RawMessage `json:"quote_request"`
	QuotePackage                json.RawMessage `json:"quote_package"`
	ExecutionSignerPublicKeyHex string          `json:"execution_signer_public_key_hex"`
	EscrowAddress               string          `json:"escrow_address"`
	ExpectedEscrowCodeHash      string          `json:"expected_escrow_code_hash"`
	ReceiptBOCBase64            string          `json:"receipt_boc_base64"`
	SettlementQueryID           uint64          `json:"settlement_query_id"`
	SettlementSignatureHex      string          `json:"settlement_signature_hex"`
}

func read(path string, target any) error {
	if path == "" {
		return errors.New("input path is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 3<<20 {
		return errors.New("input is missing or outside size bounds")
	}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON is not allowed")
	}
	return nil
}

func main() {
	networkPath := flag.String("network", "", "protobuf JSON NetworkDomain")
	requestPath := flag.String("quote-request", "", "protobuf JSON RequestQuoteProposalRequest")
	packagePath := flag.String("quote-package", "", "protobuf JSON QuoteProposalPackageV1")
	signingPath := flag.String("signing-package", "", "native-receipt-release signing package JSON")
	escrow := flag.String("escrow", "", "canonical raw escrow address")
	codeHash := flag.String("escrow-code-hash", "", "approved escrow code hash")
	output := flag.String("output", "", "output bundle path")
	flag.Parse()
	if *output == "" || *escrow == "" || *codeHash == "" {
		fatal(errors.New("--output, --escrow, and --escrow-code-hash are required"))
	}
	network, request, quotePackage := new(nativev1.NetworkDomain), new(nativev1.RequestQuoteProposalRequest), new(nativev1.QuoteProposalPackageV1)
	if err := readProto(*networkPath, network); err != nil {
		fatal(err)
	}
	if err := readProto(*requestPath, request); err != nil {
		fatal(err)
	}
	if err := readProto(*packagePath, quotePackage); err != nil {
		fatal(err)
	}
	var signing signingPackage
	if err := read(*signingPath, &signing); err != nil {
		fatal(err)
	}
	if signing.QueryID == 0 || signing.ExecutionSignerPublicKey == "" || signing.SignatureHex == "" {
		fatal(errors.New("signing package lacks a complete release authorization"))
	}
	if _, err := base64.StdEncoding.Strict().DecodeString(signing.ReceiptBOCBase64); err != nil {
		fatal(errors.New("invalid Receipt BOC"))
	}
	if _, err := hex.DecodeString(signing.ExecutionSignerPublicKey); err != nil {
		fatal(errors.New("invalid signer public key"))
	}
	if _, err := hex.DecodeString(signing.SignatureHex); err != nil {
		fatal(errors.New("invalid settlement signature"))
	}
	encodedNetwork, _ := protojson.Marshal(network)
	encodedRequest, _ := protojson.Marshal(request)
	encodedPackage, _ := protojson.Marshal(quotePackage)
	result := document{Schema: "atos.native.safe-handoff.v1", Network: encodedNetwork,
		QuoteRequest: encodedRequest, QuotePackage: encodedPackage,
		ExecutionSignerPublicKeyHex: signing.ExecutionSignerPublicKey, EscrowAddress: *escrow,
		ExpectedEscrowCodeHash: *codeHash, ReceiptBOCBase64: signing.ReceiptBOCBase64,
		SettlementQueryID: signing.QueryID, SettlementSignatureHex: signing.SignatureHex}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*output, append(raw, '\n'), 0o600); err != nil {
		fatal(err)
	}
}

func readProto(path string, target proto.Message) error {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 1<<20 {
		return errors.New("protobuf JSON input is missing or too large")
	}
	return protojson.UnmarshalOptions{DiscardUnknown: false}.Unmarshal(raw, target)
}

func bytesReader(raw []byte) *bytes.Reader { return bytes.NewReader(raw) }
func fatal(err error)                      { fmt.Fprintln(os.Stderr, "native-safe-handoff-pack:", err); os.Exit(1) }
