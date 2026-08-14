package referencecodec

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
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
	if vector.Schema != "atos.accepted-quote.v1.vector" {
		t.Fatal("wrong quote vector schema")
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
