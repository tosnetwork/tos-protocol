package files

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeJSONIsStrictAndBounded(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "config.json")
	write := func(value string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	type config struct {
		Name string `json:"name"`
	}
	write(`{"name":"edge"}`)
	var decoded config
	if err := DecodeJSON(path, 64, &decoded); err != nil || decoded.Name != "edge" {
		t.Fatalf("valid strict JSON rejected: %#v err=%v", decoded, err)
	}
	write(`{"name":"edge","name":"attacker"}`)
	if err := DecodeJSON(path, 64, &decoded); err == nil ||
		!strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate key accepted: %v", err)
	}
	write(`{"name":"` + strings.Repeat("x", 64) + `"}`)
	if err := DecodeJSON(path, 16, &decoded); err == nil ||
		err.Error() != "file exceeds byte limit" {
		t.Fatalf("oversized JSON accepted: %v", err)
	}
}

func TestDecodeJSONRejectsInvalidRequestAndMissingFile(t *testing.T) {
	var output map[string]any
	for _, test := range []struct {
		path    string
		maximum int64
		output  any
	}{
		{"", 1, &output},
		{"missing.json", 0, &output},
		{"missing.json", 1, nil},
	} {
		if err := DecodeJSON(test.path, test.maximum, test.output); err == nil {
			t.Fatalf("invalid decode request accepted: %#v", test)
		}
	}
	if err := DecodeJSON(
		filepath.Join(t.TempDir(), "missing.json"), 1, &output,
	); err == nil {
		t.Fatal("missing JSON file accepted")
	}
}
