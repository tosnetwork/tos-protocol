package referencecodec

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

func TestIndependentAcceptedQuoteVector(t *testing.T) {
	data, err := os.ReadFile("testdata/accepted_quote_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector QuoteVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Schema != "tos.service.accepted-quote.v1.vector" {
		t.Fatal("wrong quote vector schema")
	}
	frozenBOC, err := base64.StdEncoding.DecodeString(vector.Expected.BOCBase64)
	if err != nil {
		t.Fatal(err)
	}
	frozenRoot, err := cell.FromBOC(frozenBOC)
	if err != nil {
		t.Fatal(err)
	}
	if got := "tvm-cell-sha256:" + hex.EncodeToString(frozenRoot.Hash()); got != vector.Expected.Commitment {
		t.Fatalf("stored vector bytes decode to %s, want the frozen commitment %s", got, vector.Expected.Commitment)
	}
	root, commitment, err := ComputeAcceptedQuote(vector)
	if err != nil {
		t.Fatal(err)
	}
	if commitment != vector.Expected.Commitment || base64.StdEncoding.EncodeToString(root.ToBOC()) != vector.Expected.BOCBase64 {
		t.Fatalf("independent Accepted Quote mismatch: %s", commitment)
	}
	proposalID := vector.Quote.ProposalID
	vector.Quote.ProposalID = "another-gateway-local-id"
	_, second, err := ComputeAcceptedQuote(vector)
	if err != nil {
		t.Fatal(err)
	}
	if second != commitment {
		t.Fatalf("proposal ID %q affected canonical quote", proposalID)
	}
}
