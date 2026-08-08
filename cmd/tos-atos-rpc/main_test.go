package main

import "testing"

func TestPlainHTTPRestrictedToLoopback(t *testing.T) {
	for _, address := range []string{"127.0.0.1:8090", "[::1]:8090", "localhost:8090"} {
		if _, useTLS, err := buildServerTLS(address, "", "", ""); err != nil || useTLS {
			t.Fatalf("loopback %q rejected: useTLS=%v err=%v", address, useTLS, err)
		}
	}
	for _, address := range []string{"0.0.0.0:8090", ":8090", "192.0.2.10:8090"} {
		if _, _, err := buildServerTLS(address, "", "", ""); err == nil {
			t.Fatalf("non-loopback plain HTTP %q was accepted", address)
		}
	}
}

func TestTLSCertificateAndKeyMustBePaired(t *testing.T) {
	if _, _, err := buildServerTLS("0.0.0.0:8090", "cert.pem", "", ""); err == nil {
		t.Fatal("certificate without key was accepted")
	}
	if _, _, err := buildServerTLS("0.0.0.0:8090", "", "key.pem", ""); err == nil {
		t.Fatal("key without certificate was accepted")
	}
}
