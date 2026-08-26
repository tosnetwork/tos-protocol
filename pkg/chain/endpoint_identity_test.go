package chain

import "testing"

func TestEndpointAuthorityDigestCanonicalizesAuthorityAndBindsPath(t *testing.T) {
	first, err := EndpointAuthorityDigest("https://RPC.Example./v1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := EndpointAuthorityDigest("https://rpc.example:443/v1")
	if err != nil || first != second {
		t.Fatalf("canonical endpoint authority mismatch: %q %q err=%v", first, second, err)
	}
	otherPath, err := EndpointAuthorityDigest("https://rpc.example/v2")
	if err != nil || otherPath == first {
		t.Fatal("different JSON-RPC path reused one endpoint authority digest")
	}
	if _, err := EndpointAuthorityDigest("https://user@rpc.example/v1"); err == nil {
		t.Fatal("credential-bearing endpoint received an authority digest")
	}
}
