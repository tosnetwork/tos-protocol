package trustedcapability

import "testing"

func TestObjectKindRejectsUnrelatedCanonicalBody(t *testing.T) {
	if _, err := NewObject(DomainOwnerLocal, []byte("owner"), "artifact", struct {
		SchemaVersion uint16 `cbor:"1,keyasint"`
	}{1}); err == nil {
		t.Fatal("artifact accepted an unrelated body shape")
	}
}

func TestBodyShapeRejectsMissingNestedField(t *testing.T) {
	body, err := NewConformanceBodyValue("authorization-envelope", 7)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := MarshalBody(body)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[uint64]any
	if err := UnmarshalBody(canonical, &raw); err != nil {
		t.Fatal(err)
	}
	nested, ok := raw[1].(map[uint64]any)
	if !ok {
		t.Fatalf("authorization body decoded as %T", raw[1])
	}
	delete(nested, 16)
	mutated, err := MarshalBody(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBodyShape("authorization-envelope", mutated); err == nil {
		t.Fatal("accepted authorization envelope with missing nested issuer subject")
	}
}
