package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestContextIsFreshAndBounded(t *testing.T) {
	first, err := requestContext("operator", "retry")
	if err != nil {
		t.Fatal(err)
	}
	second, err := requestContext("operator", "retry")
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestId == second.RequestId || first.CallerId != "operator" || first.IdempotencyKey != "retry" ||
		first.DeadlineUnixMillis <= time.Now().UnixMilli() {
		t.Fatal("discovery request context is not fresh and bounded")
	}
}

func TestManifestInputRequiresAbsoluteBoundedRegularFile(t *testing.T) {
	if _, err := readBoundedRegular("relative.cbor", 10); err == nil {
		t.Fatal("relative manifest path was accepted")
	}
	path := filepath.Join(t.TempDir(), "manifest.cbor")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readBoundedRegular(path, 3); err != nil || len(raw) != 3 {
		t.Fatal("bounded regular manifest was rejected")
	}
	if _, err := readBoundedRegular(path, 2); err == nil {
		t.Fatal("oversized manifest was accepted")
	}
}
