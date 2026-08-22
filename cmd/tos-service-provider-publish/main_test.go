package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestReadSignedActionIsStrictAndRequiresAuthoritySignature(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "signed.json")
	value := &nativev1.SignedNativeActionV1{Action: &nativev1.NativeActionV1{Protocol: "test"},
		AuthoritySignatures: []*nativev1.SignatureV1{{KeyId: "key", Ed25519Signature: make([]byte, 64)}}}
	raw, err := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readSignedAction(path)
	if err != nil || parsed.GetAction().GetProtocol() != "test" || len(parsed.GetAuthoritySignatures()) != 1 {
		t.Fatalf("read signed action: %+v %v", parsed, err)
	}
	if err := os.WriteFile(path, append(raw[:len(raw)-1], []byte(`,"unknown":true}`)...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSignedAction(path); err == nil {
		t.Fatal("unknown signed action field was accepted")
	}
}

func TestPublicationNonceAndPrivateTokenFailClosed(t *testing.T) {
	if _, err := nonce(strings.Repeat("0", 64)); err == nil {
		t.Fatal("zero publication nonce was accepted")
	}
	if _, err := nonce(strings.Repeat("A", 64)); err == nil {
		t.Fatal("noncanonical publication nonce was accepted")
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "token")
	if err := os.WriteFile(path, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readToken(path); err == nil {
		t.Fatal("public Gateway bearer token file was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if token, err := readToken(path); err != nil || token != "secret" {
		t.Fatalf("private token: %q %v", token, err)
	}
}
