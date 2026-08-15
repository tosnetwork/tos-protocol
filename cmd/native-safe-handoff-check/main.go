// Command native-safe-handoff-check verifies a buyer-held portable settlement
// bundle against quorum-finalized escrow state. It never contacts a Gateway.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/tosnetwork/tos-protocol/pkg/safehandoff"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	"google.golang.org/protobuf/encoding/protojson"
)

type endpointsFlag []string

func (e *endpointsFlag) String() string { return strings.Join(*e, ",") }
func (e *endpointsFlag) Set(value string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return errors.New("invalid endpoint")
	}
	*e = append(*e, value)
	return nil
}

type bundleDocument struct {
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

func decodeBundle(path string) (safehandoff.Bundle, error) {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 || len(raw) > 3<<20 {
		return safehandoff.Bundle{}, errors.New("read bounded safe-handoff bundle")
	}
	var document bundleDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || decoder.Decode(new(any)) != io.EOF ||
		document.Schema != "atos.native.safe-handoff.v1" {
		return safehandoff.Bundle{}, errors.New("invalid safe-handoff document")
	}
	network := new(nativev1.NetworkDomain)
	request := new(nativev1.RequestQuoteProposalRequest)
	quotePackage := new(nativev1.QuoteProposalPackageV1)
	options := protojson.UnmarshalOptions{DiscardUnknown: false}
	if options.Unmarshal(document.Network, network) != nil || options.Unmarshal(document.QuoteRequest, request) != nil ||
		options.Unmarshal(document.QuotePackage, quotePackage) != nil {
		return safehandoff.Bundle{}, errors.New("invalid protobuf document in safe-handoff bundle")
	}
	publicKey, err := hex.DecodeString(document.ExecutionSignerPublicKeyHex)
	if err != nil {
		return safehandoff.Bundle{}, errors.New("invalid execution signer public key")
	}
	receipt, err := base64.StdEncoding.Strict().DecodeString(document.ReceiptBOCBase64)
	if err != nil {
		return safehandoff.Bundle{}, errors.New("invalid Receipt BOC encoding")
	}
	signature, err := hex.DecodeString(document.SettlementSignatureHex)
	if err != nil {
		return safehandoff.Bundle{}, errors.New("invalid settlement signature")
	}
	return safehandoff.Bundle{Network: network, QuoteRequest: request, QuotePackage: quotePackage,
		ExecutionSignerPublicKey: publicKey, EscrowAddress: document.EscrowAddress,
		ExpectedEscrowCodeHash: document.ExpectedEscrowCodeHash, ReceiptBOC: receipt,
		SettlementQueryID: document.SettlementQueryID, SettlementSignature: signature}, nil
}

func main() {
	var endpoints endpointsFlag
	bundlePath := flag.String("bundle", "", "portable safe-handoff JSON")
	checkpoint := flag.String("checkpoint", "", "absolute durable escrow checkpoint path")
	output := flag.String("output", "", "optional JSON evidence output")
	flag.Var(&endpoints, "endpoint", "validator JSON-RPC URL; repeat three or more times")
	flag.Parse()
	if *bundlePath == "" || *checkpoint == "" || len(endpoints) < 3 {
		fatal(errors.New("bundle, checkpoint, and at least three endpoints are required"))
	}
	bundle, err := decodeBundle(*bundlePath)
	if err != nil {
		fatal(err)
	}
	chain, err := toschain.New(toschain.Config{Network: bundle.Network.NetworkId, Endpoints: endpoints,
		Quorum: len(endpoints)/2 + 1})
	if err != nil {
		fatal(err)
	}
	resolver, err := toschain.NewEscrowResolver(chain, bundle.Network, bundle.ExpectedEscrowCodeHash, *checkpoint)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := safehandoff.Verify(ctx, resolver, bundle)
	if err != nil {
		fatal(err)
	}
	evidence := struct {
		Schema           string              `json:"schema"`
		GeneratedAt      string              `json:"generated_at"`
		GatewayInputs    int                 `json:"gateway_inputs"`
		Endpoints        []string            `json:"endpoints"`
		Quorum           int                 `json:"quorum"`
		EscrowAddress    string              `json:"escrow_address"`
		ExpectedCodeHash string              `json:"expected_escrow_code_hash"`
		Result           *safehandoff.Result `json:"result"`
	}{"atos.native.safe-handoff-evidence.v1", time.Now().UTC().Format(time.RFC3339), 0,
		endpoints, len(endpoints)/2 + 1, bundle.EscrowAddress, bundle.ExpectedEscrowCodeHash, result}
	encoded, err := json.MarshalIndent(evidence, "", "  ")
	if err != nil {
		fatal(err)
	}
	encoded = append(encoded, '\n')
	if *output == "" {
		_, err = os.Stdout.Write(encoded)
	} else {
		err = os.WriteFile(*output, encoded, 0o644)
	}
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "native-safe-handoff-check:", err)
	os.Exit(1)
}
