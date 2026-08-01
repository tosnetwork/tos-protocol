package ard

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteCatalogFileAtomicallyCreatesAndReplacesPrivateFile(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	catalog, err := BuildWorkerCatalog(
		testWorkerCatalogConfig(), testWorkerCatalogResponse(now), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ai-catalog.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteCatalogFile(path, catalog, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("catalog mode=%v", info.Mode())
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, decodeErr := DecodeCatalog(file, DefaultLimits())
	closeErr := file.Close()
	if decodeErr != nil || closeErr != nil || len(decoded.Entries) != 1 ||
		decoded.Entries[0].Identifier != catalog.Entries[0].Identifier {
		t.Fatalf("decoded=%#v decodeErr=%v closeErr=%v", decoded, decodeErr, closeErr)
	}
}

func TestWriteCatalogFileRejectsSymlinkAndInvalidCatalog(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "catalog.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	valid := Catalog{SpecVersion: SpecVersion}
	if err := WriteCatalogFile(link, valid, DefaultLimits()); err == nil {
		t.Fatal("catalog writer replaced a symlink")
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("symlink target changed: %q err=%v", content, err)
	}
	invalidPath := filepath.Join(directory, "invalid.json")
	if err := WriteCatalogFile(
		invalidPath, Catalog{SpecVersion: "invalid"}, DefaultLimits(),
	); err == nil {
		t.Fatal("catalog writer accepted an invalid catalog")
	}
	if _, err := os.Lstat(invalidPath); !os.IsNotExist(err) {
		t.Fatalf("invalid catalog left output behind: %v", err)
	}
}

func TestReadCatalogFileRejectsSymlink(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	catalog, err := BuildWorkerCatalog(
		testWorkerCatalogConfig(), testWorkerCatalogResponse(now), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.json")
	if err := WriteCatalogFile(target, catalog, DefaultLimits()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "catalog.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCatalogFile(link, DefaultLimits()); err == nil {
		t.Fatal("catalog reader followed a symlink")
	}
	if err := os.Chmod(target, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCatalogFile(target, DefaultLimits()); err == nil {
		t.Fatal("catalog reader accepted a group/other-writable file")
	}
	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadCatalogFile(target, DefaultLimits())
	if err != nil || len(decoded.Entries) != 1 ||
		decoded.Entries[0].Identifier != catalog.Entries[0].Identifier {
		t.Fatalf("decoded catalog=%#v err=%v", decoded, err)
	}
}
