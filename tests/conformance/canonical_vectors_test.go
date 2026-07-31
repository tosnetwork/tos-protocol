package conformance_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

type canonicalVectorFile struct {
	Version         string                    `json:"version"`
	Vectors         []canonicalPositiveVector `json:"vectors"`
	NegativeVectors []canonicalNegativeVector `json:"negativeVectors"`
}

type canonicalPositiveVector struct {
	Name             string          `json:"name"`
	Domain           string          `json:"domain"`
	Value            json.RawMessage `json:"value"`
	CanonicalCBORHex string          `json:"canonicalCborHex"`
	Digest           string          `json:"digest"`
}

type canonicalNegativeVector struct {
	Name    string `json:"name"`
	CBORHex string `json:"cborHex"`
}

func TestCanonicalVectors(t *testing.T) {
	path := filepath.Join(baseSpecDirectory(t), "test-vectors", "canonical-v0.1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors canonicalVectorFile
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Version != "0.1" || len(vectors.Vectors) == 0 || len(vectors.NegativeVectors) == 0 {
		t.Fatal("incomplete canonical vector file")
	}
	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Value))
			decoder.UseNumber()
			var value interface{}
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			encoded, err := codec.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			actualHex := hex.EncodeToString(encoded)
			digest, err := codec.Digest(vector.Domain, value)
			if err != nil {
				t.Fatal(err)
			}
			if actualHex != vector.CanonicalCBORHex || digest != vector.Digest {
				t.Fatalf("vector mismatch\ncanonicalCborHex: %s\ndigest: %s", actualHex, digest)
			}
		})
	}
	for _, vector := range vectors.NegativeVectors {
		t.Run(vector.Name, func(t *testing.T) {
			data, err := hex.DecodeString(vector.CBORHex)
			if err != nil {
				t.Fatal(err)
			}
			var output interface{}
			if err := codec.Unmarshal(data, &output); err == nil {
				t.Fatal("invalid canonical value accepted")
			}
		})
	}
}
