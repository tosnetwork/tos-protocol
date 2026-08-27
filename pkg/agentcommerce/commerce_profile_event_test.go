package agentcommerce

import (
	"math"
	"strings"
	"testing"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type testCommerceVerifier struct{ domain string }

func (v testCommerceVerifier) VerifyCommerceObject(_ string, _ uint64, _ string, _ string, digest string, canonical []byte) error {
	want, err := codec.DigestCanonical(v.domain, canonical)
	if err != nil || want != digest {
		return errDigestMismatch
	}
	return nil
}

type commerceTestError string

func (e commerceTestError) Error() string { return string(e) }

const errDigestMismatch commerceTestError = "digest mismatch"

func TestCommerceProfileEventInlineVerification(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	object, err := codec.Marshal(map[string]interface{}{"claim_id": "claim:1"})
	if err != nil {
		t.Fatal(err)
	}
	digest, err := codec.DigestCanonical("tos.test.claim.v1", object)
	if err != nil {
		t.Fatal(err)
	}
	event := CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "claim", ObjectContentType: "application/vnd.tos.test.claim.v1+cbor", ObjectDigest: digest,
		ObjectSizeBytes: uint64(len(object)), CarriageKind: "inline", AgreementBodyDigest: "sha256:" + strings.Repeat("2", 64),
		ObligationIDs: []string{"coverage"}, CanonicalObjectBytes: object,
		CreatedAtUnix: uint64(now.Add(-time.Minute).Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	if err := VerifyCommerceProfileEventV1(event, now, testCommerceVerifier{domain: "tos.test.claim.v1"}); err != nil {
		t.Fatal(err)
	}
	event.ObjectDigest = "sha256:" + strings.Repeat("f", 64)
	if VerifyCommerceProfileEventV1(event, now, testCommerceVerifier{domain: "tos.test.claim.v1"}) == nil {
		t.Fatal("accepted substituted inline object")
	}
}

func TestMessengerEffectCarriesBoundedCommerceProfileEvent(t *testing.T) {
	payload := make([]byte, 64<<10)
	request := MessengerEffectRequestV1{SchemaVersion: 1, RecipientAgentIDs: []string{"agent:recipient"},
		EventKind: "commerce.profile-event", ContentType: CommerceProfileEventContentType, Payload: payload}
	if _, err := CanonicalMessengerEffectRequest(request); err != nil {
		t.Fatal(err)
	}
	request.Payload = make([]byte, 256<<10)
	if _, err := CanonicalMessengerEffectRequest(request); err == nil {
		t.Fatal("oversized inline profile event bypassed referenced-object carriage")
	}
}

func TestCommerceProfileEventRequiresDescriptorAboveInlineTransportBudget(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	oversized := make([]byte, MaxInlineProfileEventBytes+1)
	event := CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "claim", ObjectContentType: "application/octet-stream",
		ObjectDigest: "sha256:" + strings.Repeat("a", 64), ObjectSizeBytes: uint64(len(oversized)),
		CarriageKind: "inline", CanonicalObjectBytes: oversized,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	if err := ValidateCommerceProfileEventV1(event, now); err == nil {
		t.Fatal("inline commerce object exceeded the Messenger-safe transport budget")
	}
	event.CarriageKind, event.CanonicalObjectBytes = "content_addressed", nil
	event.ObjectDescriptor = &CommerceObjectDescriptorV1{ContentType: event.ObjectContentType,
		ContentDigest: event.ObjectDigest, ContentSize: event.ObjectSizeBytes,
		RetrievalHints: []string{"https://carrier.example/objects/sha256"}}
	if err := ValidateCommerceProfileEventV1(event, now); err != nil {
		t.Fatalf("bounded content-addressed carriage was rejected: %v", err)
	}
}

func TestCommerceProfileEventRejectsUnixTimeOverflow(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	event := CommerceProfileEventV1{SchemaVersion: 1, ProfileURI: "tos.test.profile.v1", ProfileVersion: 1,
		ObjectKind: "claim", ObjectContentType: "application/octet-stream",
		ObjectDigest: "sha256:" + strings.Repeat("a", 64), ObjectSizeBytes: 1,
		CarriageKind: "inline", CanonicalObjectBytes: []byte{1},
		CreatedAtUnix: uint64(math.MaxInt64) + 1, ExpiresAtUnix: uint64(math.MaxInt64) + 2}
	if err := ValidateCommerceProfileEventV1(event, now); err == nil {
		t.Fatal("overflowing Unix timestamp crossed the signed time boundary")
	}
}
