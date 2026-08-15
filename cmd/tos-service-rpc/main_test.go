package main

import "testing"

func TestPlainHTTPRestrictedToLoopback(t *testing.T) {
	if _, secure, err := buildServerTLS("127.0.0.1:8090", "", "", ""); err != nil || secure {
		t.Fatalf("loopback = %v, %v", secure, err)
	}
	if _, _, err := buildServerTLS("0.0.0.0:8090", "", "", ""); err == nil {
		t.Fatal("non-loopback plaintext was accepted")
	}
}

func TestTLSCertificateAndKeyMustBePaired(t *testing.T) {
	if _, _, err := buildServerTLS("127.0.0.1:8090", "/tmp/cert", "", ""); err == nil {
		t.Fatal("unpaired TLS certificate was accepted")
	}
}
