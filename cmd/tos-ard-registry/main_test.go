package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/ard"
	"github.com/tosnetwork/tos-protocol/pkg/registry"
)

func TestReloadCatalogsRetainsLastValidGeneration(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first.json")
	secondPath := filepath.Join(directory, "second.json")
	initial := reloadTestCatalog("example.com", "initial")
	if err := ard.WriteCatalogFile(firstPath, initial, ard.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	index, err := registry.NewIndex(registry.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadCatalogs(index, []string{firstPath}); err != nil {
		t.Fatal(err)
	}

	replacement := reloadTestCatalog("example.com", "replacement")
	if err := ard.WriteCatalogFile(firstPath, replacement, ard.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondPath, []byte(`{"invalid":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reloadCatalogs(index, []string{firstPath, secondPath}); err == nil {
		t.Fatal("reload accepted an invalid catalog set")
	}
	list, err := index.List(20, "")
	if err != nil || list.Total != 1 ||
		list.Items[0].Identifier != initial.Entries[0].Identifier {
		t.Fatalf("failed reload replaced valid state: %#v err=%v", list, err)
	}

	second := reloadTestCatalog("other.example", "second")
	if err := ard.WriteCatalogFile(secondPath, second, ard.DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	if err := reloadCatalogs(index, []string{firstPath, secondPath}); err != nil {
		t.Fatal(err)
	}
	list, err = index.List(20, "")
	if err != nil || list.Total != 2 {
		t.Fatalf("valid reload did not commit atomically: %#v err=%v", list, err)
	}
}

func reloadTestCatalog(publisher, name string) ard.Catalog {
	return ard.Catalog{
		SpecVersion: ard.SpecVersion,
		Entries: []ard.Entry{{
			Identifier:  "urn:air:" + publisher + ":tos:" + name,
			DisplayName: name,
			Type:        "application/vnd.tos.service+json",
			URL:         "https://" + publisher + "/" + name,
		}},
	}
}
