package atosrpc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"google.golang.org/protobuf/proto"
)

func validateReadContext(value *atostosv1.RequestContext, now time.Time) error {
	if value == nil {
		return invalid("INVALID_ARGUMENT", "request context is required")
	}
	if !identifierPattern.MatchString(value.RequestId) || !identifierPattern.MatchString(value.CallerId) {
		return invalid("INVALID_ARGUMENT", "request_id and caller_id are required")
	}
	if value.DeadlineUnixMillis > 0 && !now.Before(time.UnixMilli(value.DeadlineUnixMillis)) {
		return rpcError(connect.CodeDeadlineExceeded, "DEADLINE_EXCEEDED", "request deadline has elapsed")
	}
	return nil
}

func validateMutationContext(value *atostosv1.RequestContext, now time.Time) error {
	if err := validateReadContext(value, now); err != nil {
		return err
	}
	if !identifierPattern.MatchString(value.IdempotencyKey) {
		return invalid("INVALID_ARGUMENT", "idempotency_key is required")
	}
	return nil
}

func protoDigest(domain string, value proto.Message) (string, error) {
	if value == nil || strings.TrimSpace(domain) == "" {
		return "", errors.New("invalid digest request")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(encoded)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func bytesDigest(domain string, value []byte) string {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write([]byte{0})
	h.Write(value)
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func digestMessage(value []byte) *atostosv1.Digest {
	sum := sha256.Sum256(value)
	return &atostosv1.Digest{Algorithm: "sha256", Value: sum[:]}
}

func validateDigest(value *atostosv1.Digest) error {
	if value == nil || value.Algorithm != "sha256" || len(value.Value) != sha256.Size {
		return invalid("INVALID_ARGUMENT", "a sha256 digest is required")
	}
	return nil
}

func digestEqual(value *atostosv1.Digest, bytesValue []byte) bool {
	if validateDigest(value) != nil {
		return false
	}
	sum := sha256.Sum256(bytesValue)
	return bytes.Equal(value.Value, sum[:])
}

func validateModeProfile(mode atostosv1.TrustMode, profile atostosv1.ProofProfile) error {
	switch mode {
	case atostosv1.TrustMode_TRUST_MODE_MANAGED:
		if profile != atostosv1.ProofProfile_PROOF_PROFILE_NONE && profile != atostosv1.ProofProfile_PROOF_PROFILE_UNSPECIFIED {
			return invalid("PROOF_PROFILE_UNAVAILABLE", "Managed mode requires no TOS proof profile")
		}
	case atostosv1.TrustMode_TRUST_MODE_VERIFIED:
		if profile != atostosv1.ProofProfile_PROOF_PROFILE_TOS_VERIFIED_V1 {
			return invalid("PROOF_PROFILE_UNAVAILABLE", "Verified mode requires tos_verified_v1")
		}
	case atostosv1.TrustMode_TRUST_MODE_NATIVE:
		if profile != atostosv1.ProofProfile_PROOF_PROFILE_TOS_NATIVE_V1 {
			return invalid("PROOF_PROFILE_UNAVAILABLE", "Native mode requires tos_native_v1")
		}
	default:
		return invalid("TRUST_MODE_UNAVAILABLE", "a concrete trust mode is required")
	}
	return nil
}

func parseAtomic(value string) (*big.Int, error) {
	if value == "" || strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
		return nil, errors.New("invalid atomic amount")
	}
	parsed, ok := new(big.Int).SetString(value, 10)
	if !ok || parsed.Sign() < 0 {
		return nil, errors.New("invalid atomic amount")
	}
	return parsed, nil
}

func capabilityKey(id, version string) string { return id + "\x00" + version }
func signerKey(provider, capability, version, signer string) string {
	return strings.Join([]string{provider, capability, version, signer}, "\x00")
}
func idempotencyKey(method string, context *atostosv1.RequestContext) string {
	return strings.Join([]string{context.CallerId, method, context.IdempotencyKey}, "\x00")
}

func shortID(prefix, digest string) string {
	value := strings.TrimPrefix(digest, "sha256:")
	if len(value) > 32 {
		value = value[:32]
	}
	return prefix + value
}

func cloneMessage[T proto.Message](value T) T {
	if any(value) == nil {
		return value
	}
	return proto.Clone(value).(T)
}

func requiredIdentifier(name, value string) error {
	if !identifierPattern.MatchString(value) {
		return invalid("INVALID_ARGUMENT", fmt.Sprintf("%s is required", name))
	}
	return nil
}
