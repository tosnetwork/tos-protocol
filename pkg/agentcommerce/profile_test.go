package agentcommerce

import (
	"strings"
	"testing"
)

func TestProfileAndAtomicBounds(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	ref := ProfileRefV1{ProfileURI: "tos.test.profile.v1", ProfileVersion: 1, ProfileDigest: digest}
	if err := ValidateProfileRefV1(ref); err != nil {
		t.Fatal(err)
	}
	asset := AssetIdentityV1{AssetNamespace: "tos", AssetIdentifier: "asset:test", Unit: "atomic"}
	if err := ValidateAtomicAmountRangeV1(AtomicAmountRangeV1{
		Minimum: AtomicAmountV1{Asset: asset, AmountAtomic: "0"},
		Maximum: AtomicAmountV1{Asset: asset, AmountAtomic: "100"},
	}); err != nil {
		t.Fatal(err)
	}
	bad := ref
	bad.ProfileVersion = 0
	if ValidateProfileRefV1(bad) == nil {
		t.Fatal("accepted zero profile version")
	}
}
