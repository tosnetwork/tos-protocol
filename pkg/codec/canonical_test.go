package codec

import (
	"bytes"
	"testing"
)

type vector struct {
	Version string            `json:"version"`
	Count   uint64            `json:"count"`
	Labels  map[string]string `json:"labels"`
}

type duplicateJSON struct{}

func (duplicateJSON) MarshalJSON() ([]byte, error) {
	return []byte(`{"value":1,"value":2}`), nil
}

func TestMarshalIsStableAcrossMapOrder(t *testing.T) {
	first := vector{Version: "0.1", Count: 42, Labels: map[string]string{"z": "last", "a": "first"}}
	second := vector{Version: "0.1", Count: 42, Labels: map[string]string{"a": "first", "z": "last"}}
	left, err := Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("canonical encodings differ:\n%x\n%x", left, right)
	}
	var decoded vector
	if err := Unmarshal(left, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Count != 42 || decoded.Labels["a"] != "first" {
		t.Fatalf("unexpected decoded value: %#v", decoded)
	}
}

func TestMarshalRejectsFloatingPoint(t *testing.T) {
	if _, err := Marshal(map[string]interface{}{"price": 1.5}); err == nil {
		t.Fatal("floating-point value accepted")
	}
}

func TestMarshalRejectsDuplicateJSONKeys(t *testing.T) {
	if _, err := Marshal(duplicateJSON{}); err == nil {
		t.Fatal("duplicate JSON key accepted")
	}
}

func TestUnmarshalRejectsNonCanonicalAndTaggedCBOR(t *testing.T) {
	var decoded map[string]interface{}
	// 0x18 0x01 encodes 1 using a non-shortest integer representation.
	if err := Unmarshal([]byte{0xa1, 0x61, 'x', 0x18, 0x01}, &decoded); err == nil {
		t.Fatal("non-canonical integer accepted")
	}
	// Tag 0 is forbidden even though it is valid CBOR.
	var value interface{}
	if err := Unmarshal([]byte{0xc0, 0x61, 'x'}, &value); err == nil {
		t.Fatal("CBOR tag accepted")
	}
}

func TestDigestUsesDomainSeparation(t *testing.T) {
	value := vector{Version: "0.1", Count: 1, Labels: map[string]string{}}
	left, err := Digest("tos.quote.v1", value)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Digest("tos.receipt.v1", value)
	if err != nil {
		t.Fatal(err)
	}
	if left == right {
		t.Fatal("different domains produced the same digest")
	}
}
