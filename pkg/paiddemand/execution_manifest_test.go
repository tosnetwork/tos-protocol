package paiddemand

import (
	"bytes"
	"strings"
	"testing"
)

func TestGenericExecutionManifestCanonicalAndAgreementBound(t *testing.T) {
	manifest := ExecutionManifestV1{SchemaVersion: 1, AgreementBodyDigest: "sha256:" + strings.Repeat("1", 64),
		WorkObligationIDs: []string{"research", "review"}, ExecutionProfileURI: ExecutionManifestProfileV1,
		PlanContentType: "text/plain", Plan: []byte("perform the exact accepted obligations"),
		AcceptedInputSetDigestOrZero:  "sha256:" + strings.Repeat("0", 64),
		DeliverablePolicyDigestOrZero: "sha256:" + strings.Repeat("2", 64)}
	canonical, digest, err := CanonicalExecutionManifest(manifest)
	if err != nil || len(canonical) == 0 || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("canonical manifest: digest=%s err=%v", digest, err)
	}
	decoded, err := DecodeCanonicalExecutionManifest(canonical)
	if err != nil || decoded.AgreementBodyDigest != manifest.AgreementBodyDigest || !bytes.Equal(decoded.Plan, manifest.Plan) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}
	tampered := append(append([]byte(nil), canonical...), 0)
	if _, err := DecodeCanonicalExecutionManifest(tampered); err == nil {
		t.Fatal("tampered manifest was accepted")
	}
	unsorted := manifest
	unsorted.WorkObligationIDs = []string{"review", "research"}
	if _, _, err := CanonicalExecutionManifest(unsorted); err == nil {
		t.Fatal("unsorted obligation identity was accepted")
	}
}
