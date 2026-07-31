package registry

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
)

func testCatalog() ard.Catalog {
	return ard.Catalog{
		SpecVersion: ard.SpecVersion,
		Entries: []ard.Entry{
			{
				Identifier:            "urn:air:example.com:ai:vision",
				DisplayName:           "Factory Vision",
				Type:                  "application/vnd.tos.service+json",
				URL:                   "https://example.com/vision",
				Tags:                  []string{"edge", "vision"},
				Capabilities:          []string{"object-detection"},
				RepresentativeQueries: []string{"inspect a product", "detect a defect"},
			},
			{
				Identifier:            "urn:air:example.com:ai:ocr",
				DisplayName:           "Local OCR",
				Type:                  "application/vnd.tos.service+json",
				URL:                   "https://example.com/ocr",
				Tags:                  []string{"edge", "ocr"},
				Capabilities:          []string{"text-recognition"},
				RepresentativeQueries: []string{"read an invoice", "extract image text"},
			},
		},
	}
}

func TestIndexSearchAndPagination(t *testing.T) {
	index, err := NewIndex(DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("https://example.com/.well-known/ai-catalog.json", testCatalog()); err != nil {
		t.Fatal(err)
	}
	response, err := index.Search(SearchRequest{
		Query:    QueryModel{Text: "edge", Filter: map[string]interface{}{"capabilities": "object-detection"}},
		PageSize: 1,
	}, "https://registry.example/search")
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Results) != 1 || response.Results[0].Identifier != "urn:air:example.com:ai:vision" {
		t.Fatalf("unexpected results: %#v", response.Results)
	}
}

func TestIndexIsBoundedAndRejectsIdentifierCollision(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxEntries = 2
	index, _ := NewIndex(limits)
	if err := index.AddCatalog("https://one.example/catalog", testCatalog()); err != nil {
		t.Fatal(err)
	}
	if err := index.AddCatalog("https://two.example/catalog", testCatalog()); err == nil {
		t.Fatal("cross-source identifier replacement accepted")
	}

	overflow := testCatalog()
	overflow.Entries = []ard.Entry{{
		Identifier:  "urn:air:other.example:ai:new",
		DisplayName: "new",
		Type:        "application/json",
		URL:         "https://other.example/new",
	}}
	if err := index.AddCatalog("https://other.example/catalog", overflow); err == nil {
		t.Fatal("capacity overflow accepted")
	}
}

func TestCatalogReplacementWithdrawsMissingEntries(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	source := "https://example.com/catalog"
	if err := index.AddCatalog(source, testCatalog()); err != nil {
		t.Fatal(err)
	}
	replacement := testCatalog()
	replacement.Entries = replacement.Entries[:1]
	if err := index.AddCatalog(source, replacement); err != nil {
		t.Fatal(err)
	}
	list, err := index.List(20, "")
	if err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || list.Items[0].Identifier != replacement.Entries[0].Identifier {
		t.Fatalf("stale entries survived replacement: %#v", list)
	}
}

func TestEmptySearchEncodesResultsArray(t *testing.T) {
	index, _ := NewIndex(DefaultLimits())
	response, err := index.Search(SearchRequest{
		Query: QueryModel{Text: "nothing"},
	}, "https://registry.example/search")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"results":[]`) {
		t.Fatalf("empty results are not an array: %s", encoded)
	}
}

func TestPageTokenRejectsDuplicateFields(t *testing.T) {
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"o":0,"o":1,"g":7}`))
	if _, err := decodePageToken(token, 7); err == nil {
		t.Fatal("ambiguous pageToken accepted")
	}
}
