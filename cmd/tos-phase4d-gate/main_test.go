package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadSecretRejectsWeakPermissionsAndMultipleLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readSecret(path); err != nil || got != "secret" {
		t.Fatalf("got=%q err=%v", got, err)
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret(path); err == nil {
		t.Fatal("group-readable token accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("one\ntwo"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret(path); err == nil {
		t.Fatal("multi-line token accepted")
	}
}

func TestReviewedEscrowCodeHashIsRequired(t *testing.T) {
	if err := verifyReviewedEscrowCodeHash("tvm-cell-sha256:bb", []string{"tvm-cell-sha256:aa"}); err == nil {
		t.Fatal("unreviewed hash passed")
	}
	if err := verifyReviewedEscrowCodeHash("tvm-cell-sha256:aa", []string{"tvm-cell-sha256:aa"}); err != nil {
		t.Fatal(err)
	}
}
