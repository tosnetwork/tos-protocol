package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunEmitsBoundPublicMaterialWithoutPrivateSeeds(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	seedPaths := make([]string, 4)
	privateValues := make([]string, 4)
	for index := range seedPaths {
		seed := bytes.Repeat([]byte{byte(index + 1)}, ed25519.SeedSize)
		privateValues[index] = base64.RawURLEncoding.EncodeToString(seed)
		seedPaths[index] = filepath.Join(directory, "key-"+string(rune('a'+index))+".seed")
		if err := os.WriteFile(seedPaths[index], []byte(privateValues[index]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stdout
	os.Stdout = write
	arguments := []string{
		"-service-id", "ai.edge.test", "-network", "tos-local",
		"-agent-account", "0:" + strings.Repeat("a", 64),
		"-display-name", "Test AI Edge", "-public-url", "https://edge.test",
		"-ard-identifier", "urn:air:edge.test:tos:ai",
		"-manifest-id", "manifest-test-0001", "-revision", "revision-test-0001",
		"-profile-digest", "sha256:" + strings.Repeat("b", 64),
		"-authenticate-key-id", "authenticate-test-0001",
		"-quote-key-id", "quote-test-0001", "-receipt-key-id", "receipt-test-0001",
		"-controller-seed", seedPaths[0], "-authenticate-seed", seedPaths[1],
		"-quote-seed", seedPaths[2], "-receipt-seed", seedPaths[3],
		"-lifetime", time.Hour.String(),
	}
	err = run(arguments)
	_ = write.Close()
	os.Stdout = original
	if err != nil {
		t.Fatal(err)
	}
	document, readErr := io.ReadAll(read)
	_ = read.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, privateValue := range privateValues {
		if bytes.Contains(document, []byte(privateValue)) {
			t.Fatal("public service material exposed a private seed")
		}
	}
	var material output
	if err := json.Unmarshal(document, &material); err != nil {
		t.Fatal(err)
	}
	if material.Descriptor.Revision != "revision-test-0001" ||
		material.AuthenticateKeyID != "authenticate-test-0001" ||
		material.QuoteKeyID != "quote-test-0001" ||
		material.ReceiptKeyID != "receipt-test-0001" ||
		material.ManifestDigest == "" || material.ManifestCanonicalSHA == "" {
		t.Fatalf("unexpected public material: %+v", material)
	}
	invalidOrigin := append([]string(nil), arguments...)
	for index := range invalidOrigin {
		if invalidOrigin[index] == "https://edge.test" {
			invalidOrigin[index] = "https://edge.test/public/path"
		}
	}
	if err := run(invalidOrigin); err == nil {
		t.Fatal("public URL with a path was accepted")
	}
}

func TestRunRejectsIncompleteMaterial(t *testing.T) {
	if err := run([]string{}); err == nil {
		t.Fatal("incomplete service material flags were accepted")
	}
}
