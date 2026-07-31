package ard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeCatalog(t *testing.T) {
	document := `{
	  "specVersion":"1.0",
	  "host":{"displayName":"TOS"},
	  "entries":[{
	    "identifier":"urn:air:example.com:tos:edge",
	    "displayName":"Edge",
	    "type":"application/vnd.tos.service+json",
	    "url":"https://example.com/.well-known/tos-service.json",
	    "representativeQueries":["find an edge service","run private inference"]
	  }]
	}`
	catalog, err := DecodeCatalog(strings.NewReader(document), DefaultLimits())
	if err != nil {
		t.Fatalf("decode valid catalog: %v", err)
	}
	if got := catalog.Entries[0].Identifier; got != "urn:air:example.com:tos:edge" {
		t.Fatalf("identifier = %q", got)
	}
}

func TestDecodeCatalogRejectsUnsafeShapes(t *testing.T) {
	tests := []string{
		`{"specVersion":"1.0","entries":[{"identifier":"urn:air:example.com:x:y","displayName":"x","type":"x","url":"https://x","data":{}}]}`,
		`{"specVersion":"1.0","entries":[{"identifier":"urn:air:localhost:x:y","displayName":"x","type":"x","url":"https://x"}]}`,
		`{"specVersion":"1.0","entries":[],"unknown":true}`,
		`{"specVersion":"1.0","specVersion":"0.9","entries":[]}`,
		`{"specVersion":"1.0","entries":[{"identifier":"urn:air:example.com:x:y","displayName":"x","displayName":"substituted","type":"x","url":"https://x"}]}`,
	}
	for _, document := range tests {
		if _, err := DecodeCatalog(strings.NewReader(document), DefaultLimits()); err == nil {
			t.Fatalf("unsafe catalog accepted: %s", document)
		}
	}
}

func TestDecodeCatalogIsBounded(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxCatalogBytes = 32
	if _, err := DecodeCatalog(strings.NewReader(strings.Repeat(" ", 33)), limits); err == nil {
		t.Fatal("oversized catalog accepted")
	}
}

func TestEntryPreservesBoundedUnknownExtensions(t *testing.T) {
	document := `{
	  "specVersion":"1.0",
	  "entries":[{
	    "identifier":"urn:air:example.com:x:y",
	    "displayName":"x",
	    "type":"application/json",
	    "url":"https://example.com/x",
	    "x-tos-binding":{"network":"testnet"}
	  }]
	}`
	catalog, err := DecodeCatalog(strings.NewReader(document), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"x-tos-binding"`) {
		t.Fatalf("extension was not preserved: %s", encoded)
	}
}

func TestCatalogRejectsEmptyTrustManifest(t *testing.T) {
	document := `{
	  "specVersion":"1.0",
	  "entries":[{
	    "identifier":"urn:air:example.com:x:y",
	    "displayName":"x",
	    "type":"application/json",
	    "url":"https://example.com/x",
	    "trustManifest":{}
	  }]
	}`
	if _, err := DecodeCatalog(strings.NewReader(document), DefaultLimits()); err == nil {
		t.Fatal("empty trust manifest accepted")
	}
}
