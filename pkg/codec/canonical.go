// Package codec implements the canonical signed representation for TOS
// service protocol values. Public documents use JSON. Signatures and digests
// use RFC 8949 Core Deterministic CBOR over the equivalent JSON data model.
package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/fxamacker/cbor/v2"
)

const (
	MaxCanonicalBytes  = 1 << 20
	MaxJSONBytes       = 2 << 20
	MaxNestedLevels    = 16
	MaxCollectionItems = 4096
	MaxTotalItems      = 16_384
	MaxStringBytes     = 256 << 10
)

var (
	encodingMode cbor.EncMode
	decodingMode cbor.DecMode
)

func init() {
	encoderOptions := cbor.CoreDetEncOptions()
	encoderOptions.TagsMd = cbor.TagsForbidden
	var err error
	encodingMode, err = encoderOptions.EncMode()
	if err != nil {
		panic(err)
	}
	decodingMode, err = cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  MaxNestedLevels,
		MaxArrayElements: MaxCollectionItems,
		MaxMapPairs:      MaxCollectionItems,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertNone,
		DefaultMapType:   reflect.TypeOf(map[string]interface{}{}),
		UTF8:             cbor.UTF8RejectInvalid,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal converts value through its JSON representation and emits
// deterministic CBOR. Floating-point values are deliberately outside v0.1.
func Marshal(value interface{}) ([]byte, error) {
	jsonValue, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal protocol JSON model: %w", err)
	}
	if len(jsonValue) > MaxJSONBytes {
		return nil, errors.New("protocol value exceeds JSON byte limit")
	}
	normalized, err := decodeJSONModel(jsonValue)
	if err != nil {
		return nil, err
	}
	encoded, err := encodingMode.Marshal(normalized)
	if err != nil {
		return nil, fmt.Errorf("encode deterministic CBOR: %w", err)
	}
	if len(encoded) > MaxCanonicalBytes {
		return nil, errors.New("canonical value exceeds byte limit")
	}
	return encoded, nil
}

// Unmarshal accepts only the exact deterministic representation. A
// semantically equivalent but non-canonical CBOR value is rejected.
func Unmarshal(data []byte, output interface{}) error {
	if len(data) == 0 || len(data) > MaxCanonicalBytes {
		return errors.New("canonical value has invalid size")
	}
	var normalized interface{}
	if err := decodingMode.Unmarshal(data, &normalized); err != nil {
		return fmt.Errorf("decode deterministic CBOR: %w", err)
	}
	counter := 0
	if err := validateDecoded(normalized, 0, &counter); err != nil {
		return err
	}
	reencoded, err := encodingMode.Marshal(normalized)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, reencoded) {
		return errors.New("CBOR value is not in canonical form")
	}
	jsonValue, err := json.Marshal(normalized)
	if err != nil {
		return fmt.Errorf("transcode canonical value to JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonValue))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode protocol value: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return errors.New("protocol value contains trailing data")
	}
	return nil
}

// Digest binds a canonical value to a protocol domain. The domain is included
// with an explicit length to prevent concatenation ambiguity.
func Digest(domain string, value interface{}) (string, error) {
	if err := validateDomain(domain); err != nil {
		return "", err
	}
	encoded, err := Marshal(value)
	if err != nil {
		return "", err
	}
	hasher := sha256.New()
	hasher.Write([]byte("TOS-PROTOCOL-CBOR"))
	hasher.Write([]byte{0})
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(domain)))
	hasher.Write(length[:])
	hasher.Write([]byte(domain))
	hasher.Write(encoded)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// DigestCanonical hashes already encoded canonical CBOR under domain after
// independently checking its canonical representation.
func DigestCanonical(domain string, encoded []byte) (string, error) {
	if err := validateDomain(domain); err != nil {
		return "", err
	}
	var value interface{}
	if err := Unmarshal(encoded, &value); err != nil {
		return "", err
	}
	hasher := sha256.New()
	hasher.Write([]byte("TOS-PROTOCOL-CBOR"))
	hasher.Write([]byte{0})
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(domain)))
	hasher.Write(length[:])
	hasher.Write([]byte(domain))
	hasher.Write(encoded)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

func decodeJSONModel(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	counter := 0
	value, err := parseJSONValue(decoder, 0, &counter)
	if err != nil {
		return nil, fmt.Errorf("decode protocol JSON model: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("protocol JSON model contains trailing data")
	}
	counter = 0
	return normalizeJSON(value, 0, &counter)
}

func parseJSONValue(decoder *json.Decoder, depth int, counter *int) (interface{}, error) {
	if depth > MaxNestedLevels {
		return nil, errors.New("protocol JSON model exceeds nesting limit")
	}
	*counter = *counter + 1
	if *counter > MaxTotalItems {
		return nil, errors.New("protocol JSON model exceeds total item limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return token, nil
	}
	switch delimiter {
	case '{':
		output := make(map[string]interface{})
		for decoder.More() {
			if len(output) >= MaxCollectionItems {
				return nil, errors.New("protocol JSON object exceeds pair limit")
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("JSON object key is not a string")
			}
			if _, duplicate := output[key]; duplicate {
				return nil, fmt.Errorf("duplicate JSON object key %q", key)
			}
			value, err := parseJSONValue(decoder, depth+1, counter)
			if err != nil {
				return nil, err
			}
			output[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, errors.New("unterminated JSON object")
		}
		return output, nil
	case '[':
		output := make([]interface{}, 0)
		for decoder.More() {
			if len(output) >= MaxCollectionItems {
				return nil, errors.New("protocol JSON array exceeds item limit")
			}
			value, err := parseJSONValue(decoder, depth+1, counter)
			if err != nil {
				return nil, err
			}
			output = append(output, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, errors.New("unterminated JSON array")
		}
		return output, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}

func normalizeJSON(value interface{}, depth int, counter *int) (interface{}, error) {
	if depth > MaxNestedLevels {
		return nil, errors.New("protocol value exceeds nesting limit")
	}
	*counter = *counter + 1
	if *counter > MaxTotalItems {
		return nil, errors.New("protocol value exceeds total item limit")
	}
	switch typed := value.(type) {
	case nil, bool:
		return typed, nil
	case string:
		if !utf8.ValidString(typed) || len(typed) > MaxStringBytes {
			return nil, errors.New("protocol string is invalid or too large")
		}
		return typed, nil
	case json.Number:
		text := typed.String()
		if strings.ContainsAny(text, ".eE") {
			return nil, errors.New("floating-point values are not allowed in protocol v0.1")
		}
		if strings.HasPrefix(text, "-") {
			number, err := strconv.ParseInt(text, 10, 64)
			if err != nil {
				return nil, errors.New("signed integer is outside int64")
			}
			return number, nil
		}
		number, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			return nil, errors.New("unsigned integer is outside uint64")
		}
		return number, nil
	case []interface{}:
		if len(typed) > MaxCollectionItems {
			return nil, errors.New("protocol array exceeds item limit")
		}
		output := make([]interface{}, len(typed))
		for index := range typed {
			normalized, err := normalizeJSON(typed[index], depth+1, counter)
			if err != nil {
				return nil, err
			}
			output[index] = normalized
		}
		return output, nil
	case map[string]interface{}:
		if len(typed) > MaxCollectionItems {
			return nil, errors.New("protocol map exceeds pair limit")
		}
		output := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			if !utf8.ValidString(key) || len(key) > MaxStringBytes {
				return nil, errors.New("protocol map key is invalid or too large")
			}
			normalized, err := normalizeJSON(item, depth+1, counter)
			if err != nil {
				return nil, err
			}
			output[key] = normalized
		}
		return output, nil
	default:
		return nil, fmt.Errorf("unsupported JSON model type %T", value)
	}
}

func validateDecoded(value interface{}, depth int, counter *int) error {
	if depth > MaxNestedLevels {
		return errors.New("canonical value exceeds nesting limit")
	}
	*counter = *counter + 1
	if *counter > MaxTotalItems {
		return errors.New("canonical value exceeds total item limit")
	}
	switch typed := value.(type) {
	case nil, bool, int64, uint64:
		return nil
	case string:
		if !utf8.ValidString(typed) || len(typed) > MaxStringBytes {
			return errors.New("canonical string is invalid or too large")
		}
		return nil
	case []interface{}:
		if len(typed) > MaxCollectionItems {
			return errors.New("canonical array exceeds item limit")
		}
		for _, item := range typed {
			if err := validateDecoded(item, depth+1, counter); err != nil {
				return err
			}
		}
		return nil
	case map[string]interface{}:
		if len(typed) > MaxCollectionItems {
			return errors.New("canonical map exceeds pair limit")
		}
		for key, item := range typed {
			if !utf8.ValidString(key) || len(key) > MaxStringBytes {
				return errors.New("canonical map key is invalid or too large")
			}
			if err := validateDecoded(item, depth+1, counter); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("canonical value contains forbidden type %T", value)
	}
}

func validateDomain(domain string) error {
	if len(domain) < 3 || len(domain) > 128 || !strings.HasPrefix(domain, "tos.") {
		return errors.New("canonical digest domain must be a bounded tos.* label")
	}
	for _, character := range domain {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '-' {
			return errors.New("canonical digest domain contains an invalid character")
		}
	}
	return nil
}
