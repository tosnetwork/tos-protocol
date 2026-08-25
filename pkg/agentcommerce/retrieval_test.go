package agentcommerce

import (
	"context"
	"net"
	"strings"
	"testing"
)

type fixedResolver []net.IPAddr

func (resolver fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), resolver...), nil
}

func TestRetrievalPolicyRejectsRemoteChosenOriginsAndPrivateDNS(t *testing.T) {
	policy := ContentRetrievalPolicy{SchemaVersion: 1, AllowedOrigins: []string{"https://objects.example"}, MaxRedirects: 1,
		MaxConnections: 2, MaxResponseHeaderBytes: 4096, MaxCompressedBytes: 1024, MaxDecodedBytes: 1024, TimeoutMillis: 1000}
	retriever := SecureContentRetriever{Policy: policy, Resolver: fixedResolver{{IP: net.ParseIP("127.0.0.1")}}}
	request := ContentFetchRequest{CandidateURL: "https://objects.example/file", ContentDigest: "sha256:" + strings.Repeat("1", 64), ContentSize: 1}
	if _, err := retriever.Fetch(context.Background(), request); err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("private DNS was not rejected: %v", err)
	}
	request.CandidateURL = "https://attacker.example/file"
	if _, err := retriever.Fetch(context.Background(), request); err == nil || !strings.Contains(err.Error(), "owner-allowed") {
		t.Fatalf("remote-selected origin was not rejected: %v", err)
	}
}

func TestRetrievalPolicyRejectsCredentialOriginSubstitution(t *testing.T) {
	policy := ContentRetrievalPolicy{SchemaVersion: 1, AllowedOrigins: []string{"https://objects.example"}, MaxRedirects: 0,
		MaxConnections: 1, MaxResponseHeaderBytes: 1024, MaxCompressedBytes: 16, MaxDecodedBytes: 16, TimeoutMillis: 1000}
	retriever := SecureContentRetriever{Policy: policy, Resolver: fixedResolver{{IP: net.ParseIP("1.1.1.1")}},
		Credential: &OriginCredential{Origin: "https://other.example", Name: "Authorization", Value: "secret"}}
	request := ContentFetchRequest{CandidateURL: "https://objects.example/file", ContentDigest: "sha256:" + strings.Repeat("1", 64), ContentSize: 1}
	if _, err := retriever.Fetch(context.Background(), request); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("credential origin substitution was not rejected: %v", err)
	}
}
