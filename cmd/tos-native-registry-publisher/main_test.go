package main

import "testing"

func TestSameGenesisHashRequiresExactEquivalentEncoding(t *testing.T) {
	encoded := "u27g1KdV3VSGOAVsu3X9z8cNwT/9tv9vm/wSQFMofWw="
	digest := "sha256:bb6ee0d4a755dd548638056cbb75fdcfc70dc13ffdb6ff6f9bfc124053287d6c"
	if !sameGenesisHash(encoded, digest) {
		t.Fatal("equivalent chain and Native genesis encodings were rejected")
	}
	for _, changed := range []string{
		"u27g1KdV3VSGOAVsu3X9z8cNwT/9tv9vm/wSQFMofWA=",
		"sha256:ab6ee0d4a755dd548638056cbb75fdcfc70dc13ffdb6ff6f9bfc124053287d6c",
		"bb6ee0d4a755dd548638056cbb75fdcfc70dc13ffdb6ff6f9bfc124053287d6c",
	} {
		if sameGenesisHash(changed, digest) || sameGenesisHash(encoded, changed) {
			t.Fatalf("mismatched genesis encoding accepted: %q", changed)
		}
	}
}
