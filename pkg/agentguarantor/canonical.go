package agentguarantor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func equalCanonical(left, right any) bool {
	leftBytes, leftErr := codec.Marshal(left)
	rightBytes, rightErr := codec.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const NativeAuthorizationContentType = "application/vnd.tos.service.agent-guarantor-native-authorization.v1+cbor"

type AuthorityKeyResolver interface {
	ResolveGuarantorAuthority(scope AuthorityResolutionScopeV1, publicKey string, at time.Time, historicalProof []byte) error
}

// AuthorityResolutionScopeV1 prevents a key authorized for one low-risk role
// from being replayed for a different profile, object, or signature domain.
type AuthorityResolutionScopeV1 struct {
	AuthoritySubject string
	ProfileURI       string
	ProfileVersion   uint64
	ProfileDigest    string
	AuthorizedKind   string
	AuthorizedDigest string
	SignatureDomain  string
}

func Digest(domain string, value interface{}) (string, error) { return codec.Digest(domain, value) }

func Canonical(value interface{}) ([]byte, error) { return codec.Marshal(value) }

func enforceCanonicalSize(value interface{}, maximum uint64, label string) error {
	if maximum == 0 || maximum > MaxCanonicalObjectBytes {
		return fmt.Errorf("%s has an invalid negotiated byte ceiling", label)
	}
	encoded, err := codec.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode %s: %w", label, err)
	}
	if uint64(len(encoded)) > maximum {
		return fmt.Errorf("%s exceeds its negotiated byte ceiling", label)
	}
	return nil
}

func authorizationMessage(signatureDomain string, statement AuthorizationStatementV1) ([]byte, error) {
	if err := validateAuthorizationStatement(statement); err != nil {
		return nil, err
	}
	canonical, err := codec.Marshal(statement)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte(signatureDomain))
	h.Write([]byte{0})
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(canonical)))
	h.Write(size[:])
	h.Write(canonical)
	return h.Sum(nil), nil
}

func SignObjectAuthorization(statement AuthorizationStatementV1, signatureDomain string, key ed25519.PrivateKey,
	historicalProof []byte) (ProfileQualifiedObjectAuthorizationV1, error) {
	if len(key) != ed25519.PrivateKeySize || len(historicalProof) == 0 || len(historicalProof) > 64<<10 {
		return ProfileQualifiedObjectAuthorizationV1{}, errors.New("Guarantor authorization key or authority proof is invalid")
	}
	message, err := authorizationMessage(signatureDomain, statement)
	if err != nil {
		return ProfileQualifiedObjectAuthorizationV1{}, err
	}
	public := key.Public().(ed25519.PublicKey)
	return ProfileQualifiedObjectAuthorizationV1{AuthoritySubject: statement.AuthoritySubject,
		ProfileURI: statement.ProfileURI, ProfileVersion: statement.ProfileVersion,
		ProfileDigest: statement.ProfileDigest, AuthorizedObjectKind: statement.AuthorizedObjectKind,
		AuthorizedBodyDigest: statement.AuthorizedBodyDigest, ValidationTimeUnix: statement.ValidationTimeUnix,
		EvidenceContentType: NativeAuthorizationContentType,
		Evidence: NativeEd25519AgentAuthorizationEvidenceV1{PublicKey: "ed25519:" + hex.EncodeToString(public),
			Signature:                "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message)),
			HistoricalAuthorityProof: append([]byte(nil), historicalProof...)}}, nil
}

func VerifyObjectAuthorization(authorization ProfileQualifiedObjectAuthorizationV1, expectedObjectKind, expectedBodyDigest,
	signatureDomain string, resolver AuthorityKeyResolver, now time.Time) error {
	statement := authorization.AuthorizationStatement()
	if authorization.EvidenceContentType != NativeAuthorizationContentType ||
		statement.AuthorizedObjectKind != expectedObjectKind || statement.AuthorizedBodyDigest != expectedBodyDigest || resolver == nil ||
		len(authorization.Evidence.HistoricalAuthorityProof) == 0 || len(authorization.Evidence.HistoricalAuthorityProof) > 64<<10 {
		return errors.New("Guarantor object authorization does not match the expected body")
	}
	if statement.ValidationTimeUnix > uint64(now.UTC().Add(5*time.Minute).Unix()) {
		return errors.New("Guarantor authorization validation time is in the future")
	}
	publicText := authorization.Evidence.PublicKey
	if len(publicText) != len("ed25519:")+ed25519.PublicKeySize*2 || publicText[:len("ed25519:")] != "ed25519:" {
		return errors.New("Guarantor authorization public key is invalid")
	}
	public, err := hex.DecodeString(publicText[len("ed25519:"):])
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("Guarantor authorization public key is invalid")
	}
	signatureText := authorization.Evidence.Signature
	if len(signatureText) <= len("ed25519:") || signatureText[:len("ed25519:")] != "ed25519:" {
		return errors.New("Guarantor authorization signature is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(signatureText[len("ed25519:"):])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("Guarantor authorization signature is invalid")
	}
	message, err := authorizationMessage(signatureDomain, statement)
	if err != nil || !ed25519.Verify(public, message, signature) {
		return errors.New("Guarantor authorization signature does not verify")
	}
	return resolver.ResolveGuarantorAuthority(AuthorityResolutionScopeV1{
		AuthoritySubject: statement.AuthoritySubject, ProfileURI: statement.ProfileURI,
		ProfileVersion: statement.ProfileVersion, ProfileDigest: statement.ProfileDigest,
		AuthorizedKind: statement.AuthorizedObjectKind, AuthorizedDigest: statement.AuthorizedBodyDigest,
		SignatureDomain: signatureDomain,
	}, publicText,
		time.Unix(int64(statement.ValidationTimeUnix), 0).UTC(), authorization.Evidence.HistoricalAuthorityProof)
}

func ValidateAuthorizationSet(authorizations []ProfileQualifiedObjectAuthorizationV1, objectKind, bodyDigest,
	signatureDomain string, requiredSubjects []string, resolver AuthorityKeyResolver, now time.Time) error {
	if len(authorizations) == 0 || len(authorizations) > MaxAuthorizations || !sortedUnique(requiredSubjects, MaxAuthorizations, validID) {
		return errors.New("Guarantor authorization set is invalid")
	}
	seen := make(map[string]struct{}, len(authorizations))
	previous := []byte(nil)
	for _, authorization := range authorizations {
		canonical, err := codec.Marshal(authorization)
		if err != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("Guarantor authorizations are unsorted or duplicated")
		}
		previous = canonical
		if err := VerifyObjectAuthorization(authorization, objectKind, bodyDigest, signatureDomain, resolver, now); err != nil {
			return err
		}
		if _, duplicate := seen[authorization.AuthoritySubject]; duplicate {
			return errors.New("Guarantor authorization subject is duplicated")
		}
		seen[authorization.AuthoritySubject] = struct{}{}
	}
	for _, subject := range requiredSubjects {
		if _, found := seen[subject]; !found {
			return fmt.Errorf("required Guarantor authority %q is missing", subject)
		}
	}
	return nil
}

// QuorumThresholdV1 parses the closed V1 quorum grammar.  A quorum is part of
// the signed commercial terms, so implementations MUST NOT delegate its
// interpretation to UI text or an adapter-specific expression language.
//
// The only released forms are "all", "any", and "at-least:<n>" where n is a
// canonical base-10 positive integer no greater than the eligible subject set.
func QuorumThresholdV1(rule string, eligibleSubjects []string) (int, error) {
	if !sortedUnique(eligibleSubjects, MaxAuthorizations, validID) {
		return 0, errors.New("Guarantor quorum subject set is invalid")
	}
	switch rule {
	case "all":
		return len(eligibleSubjects), nil
	case "any":
		return 1, nil
	}
	const prefix = "at-least:"
	if !strings.HasPrefix(rule, prefix) {
		return 0, errors.New("Guarantor quorum rule is not released")
	}
	raw := strings.TrimPrefix(rule, prefix)
	if raw == "" || len(raw) > 2 || raw[0] == '0' {
		return 0, errors.New("Guarantor quorum threshold is not canonical")
	}
	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil || value == 0 || value > uint64(len(eligibleSubjects)) {
		return 0, errors.New("Guarantor quorum threshold is unsatisfiable")
	}
	return int(value), nil
}

func QuorumThresholdMustFailV1(rule string, eligibleSubjects []string) bool {
	_, err := QuorumThresholdV1(rule, eligibleSubjects)
	return err != nil
}

// ValidateAuthorizationQuorumSet verifies an exact eligible-subject domain and
// then evaluates its released quorum rule.  Signatures by subjects outside the
// Agreement-selected domain are rejected instead of being ignored.
func ValidateAuthorizationQuorumSet(authorizations []ProfileQualifiedObjectAuthorizationV1, objectKind, bodyDigest,
	signatureDomain string, eligibleSubjects []string, quorumRule string, resolver AuthorityKeyResolver, now time.Time) error {
	threshold, err := QuorumThresholdV1(quorumRule, eligibleSubjects)
	if err != nil || len(authorizations) < threshold || len(authorizations) > len(eligibleSubjects) {
		return errors.New("Guarantor authorization quorum is not satisfied")
	}
	eligible := make(map[string]struct{}, len(eligibleSubjects))
	for _, subject := range eligibleSubjects {
		eligible[subject] = struct{}{}
	}
	seen := make(map[string]struct{}, len(authorizations))
	previous := []byte(nil)
	for _, authorization := range authorizations {
		canonical, marshalErr := codec.Marshal(authorization)
		if marshalErr != nil || previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return errors.New("Guarantor authorizations are unsorted or duplicated")
		}
		previous = canonical
		if _, ok := eligible[authorization.AuthoritySubject]; !ok {
			return errors.New("Guarantor authorization subject is outside the selected quorum")
		}
		if _, duplicate := seen[authorization.AuthoritySubject]; duplicate {
			return errors.New("Guarantor authorization subject is duplicated")
		}
		if verifyErr := VerifyObjectAuthorization(authorization, objectKind, bodyDigest, signatureDomain, resolver, now); verifyErr != nil {
			return verifyErr
		}
		seen[authorization.AuthoritySubject] = struct{}{}
	}
	return nil
}

func validateAuthorizationStatement(statement AuthorizationStatementV1) error {
	if statement.SchemaVersion != 1 || !validID(statement.AuthoritySubject) || !validID(statement.ProfileURI) ||
		statement.ProfileVersion == 0 || !digestPattern.MatchString(statement.ProfileDigest) ||
		!validToken(statement.AuthorizedObjectKind, 128) || !digestPattern.MatchString(statement.AuthorizedBodyDigest) ||
		!validUnixTimestampV1(statement.ValidationTimeUnix) {
		return errors.New("Guarantor authorization statement is invalid")
	}
	return nil
}

// validUnixTimestampV1 is the common boundary for protocol timestamps that
// are converted to time.Time. The wire representation is uint64, while Go's
// Unix conversion accepts int64. Rejecting the non-overlapping half of the
// wire domain prevents a crafted in-memory value from wrapping into the past
// before policy or historical-authority validation.
func validUnixTimestampV1(value uint64) bool {
	return value > 0 && value <= math.MaxInt64
}

func validID(value string) bool { return validToken(value, MaxObjectIDBytes) }

func validToken(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && utf8.ValidString(value) && !bytes.ContainsRune([]byte(value), 0)
}

func validDigest(value string) bool { return digestPattern.MatchString(value) }

func sortedUnique(values []string, maximum int, valid func(string) bool) bool {
	if len(values) == 0 || len(values) > maximum || !sort.StringsAreSorted(values) {
		return false
	}
	for index, value := range values {
		if !valid(value) || index > 0 && values[index-1] == value {
			return false
		}
	}
	return true
}

func sameAsset(left, right AssetIdentityV1) bool { return left == right }

func validateAmount(amount AtomicAmountV1, positive bool) error {
	return agentcommerce.ValidateAtomicAmountV1(amount, positive)
}

func compareAmount(left, right AtomicAmountV1) (int, error) {
	if !sameAsset(left.Asset, right.Asset) || validateAmount(left, false) != nil || validateAmount(right, false) != nil {
		return 0, errors.New("amount assets differ")
	}
	if len(left.AmountAtomic) < len(right.AmountAtomic) {
		return -1, nil
	}
	if len(left.AmountAtomic) > len(right.AmountAtomic) {
		return 1, nil
	}
	return bytes.Compare([]byte(left.AmountAtomic), []byte(right.AmountAtomic)), nil
}
