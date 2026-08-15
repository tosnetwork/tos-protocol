package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBundle(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestDecodeBundleRejectsUnknownAndTrailingJSON(t *testing.T) {
	base := `{"schema":"atos.native.safe-handoff.v1","network":{},"quote_request":{},"quote_package":{},"execution_signer_public_key_hex":"","escrow_address":"","expected_escrow_code_hash":"","receipt_boc_base64":"","settlement_query_id":1,"settlement_signature_hex":""}`
	for name, value := range map[string]string{
		"unknown":  strings.Replace(base, `"schema"`, `"unknown":true,"schema"`, 1),
		"trailing": base + " {}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeBundle(writeBundle(t, value)); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestDecodeBundleRejectsInvalidNestedProtoAndEncodings(t *testing.T) {
	value := `{"schema":"atos.native.safe-handoff.v1","network":{"network_id":"test"},"quote_request":{},"quote_package":{},"execution_signer_public_key_hex":"not-hex","escrow_address":"0:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","expected_escrow_code_hash":"tvm-cell-sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","receipt_boc_base64":"%%%","settlement_query_id":1,"settlement_signature_hex":"%%%"}`
	if _, err := decodeBundle(writeBundle(t, value)); err == nil {
		t.Fatal("invalid bundle accepted")
	}
}
