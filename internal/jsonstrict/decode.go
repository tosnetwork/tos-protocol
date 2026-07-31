// Package jsonstrict rejects ambiguous JSON before typed decoding.
package jsonstrict

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	MaxNesting = 64
	MaxItems   = 1_000_000
)

// Decode rejects duplicate object keys, excessive structure, unknown typed
// fields, and trailing values. Callers must apply a byte limit before Decode.
func Decode(data []byte, output interface{}) error {
	if len(data) == 0 {
		return errors.New("empty JSON document")
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	scanner.UseNumber()
	items := 0
	if err := scanValue(scanner, 0, &items); err != nil {
		return err
	}
	if _, err := scanner.Token(); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func scanValue(decoder *json.Decoder, depth int, items *int) error {
	if depth > MaxNesting {
		return errors.New("JSON document exceeds nesting limit")
	}
	*items = *items + 1
	if *items > MaxItems {
		return errors.New("JSON document exceeds item limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			if err := scanValue(decoder, depth+1, items); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
		return nil
	case '[':
		for decoder.More() {
			if err := scanValue(decoder, depth+1, items); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
		return nil
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
