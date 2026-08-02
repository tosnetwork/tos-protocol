package jsonstrict

import (
	"strings"
	"testing"
)

func TestDecodeRejectsDuplicateAndUnknownFields(t *testing.T) {
	type document struct {
		Value int `json:"value"`
	}
	for _, input := range []string{
		`{"value":1,"value":2}`,
		`{"value":1,"unknown":2}`,
		`{"value":1}{"value":2}`,
	} {
		var output document
		if err := Decode([]byte(input), &output); err == nil {
			t.Fatalf("ambiguous input accepted: %s", input)
		}
	}
}

func TestDecodeRejectsExcessiveNesting(t *testing.T) {
	input := strings.Repeat("[", MaxNesting+2) + "0" + strings.Repeat("]", MaxNesting+2)
	var output interface{}
	if err := Decode([]byte(input), &output); err == nil {
		t.Fatal("excessive nesting accepted")
	}
}

func TestDecodeAcceptsBoundedDocument(t *testing.T) {
	var output struct {
		Value int `json:"value"`
	}
	if err := Decode([]byte(`{"value":1}`), &output); err != nil {
		t.Fatal(err)
	}
	if output.Value != 1 {
		t.Fatalf("value = %d", output.Value)
	}
}

func FuzzDecode(f *testing.F) {
	for _, seed := range []string{
		`{"value":1}`,
		`{"value":1,"value":2}`,
		`[[[[0]]]]`,
		`{"nested":{"array":[true,false,null]}}`,
		`null`,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		var output interface{}
		_ = Decode(data, &output)
	})
}
