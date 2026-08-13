package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenVerifiedObserverCommandRejectsWritableAndSymlinkPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "observer")
	contents := []byte("#!/bin/sh\nprintf '{}'")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	if file, err := openVerifiedObserverCommand(path, digest); err == nil {
		file.Close()
		t.Fatal("service-owned observer command was accepted")
	}
	symlink := filepath.Join(dir, "observer-link")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if linked, err := openVerifiedObserverCommand(symlink, digest); err == nil {
		linked.Close()
		t.Fatal("observer command symlink was accepted")
	}
}

func TestOpenVerifiedObserverCommandPinsTrustedSystemBinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the verifier must run unprivileged")
	}
	path := "/usr/bin/true"
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(contents))
	file, err := openVerifiedObserverCommand(path, digest)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	var response map[string]any
	err = (commandObserver{path: path, digest: digest}).call(context.Background(), map[string]string{"probe": "read-only"}, &response)
	if err == nil || !strings.Contains(err.Error(), "decode observer response") {
		t.Fatalf("pinned descriptor was not executed as expected: %v", err)
	}
	if file, err := openVerifiedObserverCommand(path, "sha256:"+strings.Repeat("0", 64)); err == nil {
		file.Close()
		t.Fatal("observer command with wrong digest pin was accepted")
	}
}

func TestReadBoundedFileRejectsOversizeWithoutReadingItAll(t *testing.T) {
	path := filepath.Join(t.TempDir(), "package.cbor")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 33)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBoundedFile(path, 32); err == nil {
		t.Fatal("oversized proof package was accepted")
	}
}

func TestReadSecretFileRejectsLoosePermissionsAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readSecretFile(path, 64); err != nil || string(value) != "secret" {
		t.Fatalf("secure token file rejected: value=%q err=%v", value, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(path, 64); err == nil {
		t.Fatal("group-readable token file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "token-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecretFile(link, 64); err == nil {
		t.Fatal("token symlink was accepted")
	}
}

func TestValidSHA256Pin(t *testing.T) {
	if !validSHA256Pin("sha256:" + strings.Repeat("a", 64)) {
		t.Fatal("valid pin rejected")
	}
	for _, invalid := range []string{"", strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("g", 64)} {
		if validSHA256Pin(invalid) {
			t.Fatalf("invalid pin accepted: %q", invalid)
		}
	}
}

func TestDecodeObserverResponseRejectsUnknownAndTrailingData(t *testing.T) {
	for name, input := range map[string]string{
		"second value":  `{"found":true} {"found":false}`,
		"trailing junk": `{"found":true} junk`,
		"unknown field": `{"found":true,"attacker":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			var response struct {
				Found bool `json:"found"`
			}
			if err := decodeObserverResponse(bytes.NewBufferString(input), &response); err == nil {
				t.Fatal("non-canonical observer response was accepted")
			}
		})
	}
}
