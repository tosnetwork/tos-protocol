package agentgift

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

func testRequest() GiftAddressRequestV1 {
	return GiftAddressRequestV1{
		Schema: SchemaAddressRequest, Network: "tos-local", GlobalID: 42,
		GiftIntentID: strings.Repeat("1", 64), SenderAgentID: "agent_" + strings.Repeat("a", 64),
		RecipientAgentID: "agent_" + strings.Repeat("b", 64), SenderAgentAccount: "-1:" + strings.Repeat("c", 64),
		AssetKind: AssetNativeTOS, AmountAtomic: "1000000000", RequestedValidUntil: 1_900_000_000,
	}
}

func testResponse(t *testing.T) GiftAddressResponseV1 {
	req := testRequest()
	digest, err := RequestDigest(req)
	if err != nil {
		t.Fatal(err)
	}
	return GiftAddressResponseV1{Schema: SchemaAddressResponse, Network: req.Network, GlobalID: req.GlobalID,
		GiftIntentID: req.GiftIntentID, RequestDigest: digest, SenderAgentID: req.SenderAgentID,
		RecipientAgentID: req.RecipientAgentID, AssetKind: req.AssetKind, AmountAtomic: req.AmountAtomic,
		DestinationAddress: "0:" + strings.Repeat("d", 64), ResponseNotAfter: req.RequestedValidUntil - 60}
}

func TestCanonicalRoundTripAndStableDigests(t *testing.T) {
	req := testRequest()
	encoded, err := Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeAddressRequest(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := Encode(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("canonical request changed after round trip")
	}
	response := testResponse(t)
	if err := BindResponse(req, response); err != nil {
		t.Fatal(err)
	}
	responseEncoded, err := Encode(response)
	if err != nil {
		t.Fatal(err)
	}
	decodedResponse, err := DecodeAddressResponse(responseEncoded)
	if err != nil {
		t.Fatal(err)
	}
	reencodedResponse, err := Encode(decodedResponse)
	if err != nil || !bytes.Equal(responseEncoded, reencodedResponse) {
		t.Fatal("canonical response changed after round trip")
	}
	boc := []byte{0xb5, 0xee, 0x9c, 0x72, 1, 2, 3}
	offer := GiftSignedBOCOfferV1{Schema: SchemaSignedBOCOffer, GiftIntentID: req.GiftIntentID,
		AddressRequestDigest: response.RequestDigest, AddressResponseDigest: mustResponseDigest(t, response),
		SignedGiftID: SignedGiftID(boc), ExactSignedBOC: boc, DisplayMessage: "thanks", Padding: []byte{0, 0}}
	offerEncoded, err := Encode(offer)
	if err != nil {
		t.Fatal(err)
	}
	decodedOffer, err := DecodeSignedBOCOffer(offerEncoded)
	if err != nil {
		t.Fatal(err)
	}
	reencodedOffer, err := Encode(decodedOffer)
	if err != nil || !bytes.Equal(offerEncoded, reencodedOffer) {
		t.Fatal("canonical offer changed after round trip")
	}
	assertCanonicalGolden(t, "request", encoded, "4c093dad8edd338b4295a0f2168dc4a7a57e80d221121db0b9cd4ae2dfdac16b")
	assertCanonicalGolden(t, "response", responseEncoded, "5906b2c56025d234cb706bba1f27033620718c44b5a8438fc699b86cb2d2cc53")
	assertCanonicalGolden(t, "offer", offerEncoded, "901b4a535e6b2ac03a2e106050b5403d18474beb31f950d07bda7a95bd86c122")

	requestDigest, _ := RequestDigest(req)
	if requestDigest != "sha256:dcb3eca3490762d3c25f5602f708f79b5d62a7afae7399ef6ddfc91da89559e2" {
		t.Fatalf("request golden changed: %s", requestDigest)
	}
	if responseDigest := mustResponseDigest(t, response); responseDigest != "sha256:31b7ec1823e80f4554edf38c3bd95a950c37f97e315402386935ee5e8af33b01" {
		t.Fatalf("response golden changed: %s", responseDigest)
	}
	if offer.SignedGiftID != "sha256:541287b0ad63a2410690148249091bfcdb6ce4c4e13226cf26565d5ed943ce0e" {
		t.Fatalf("SignedGiftID golden changed: %s", offer.SignedGiftID)
	}
}

func TestStrictDecodeRejectsUnknownFieldsAndNonCanonicalEncoding(t *testing.T) {
	req := testRequest()
	unknown := map[string]any{"schema": req.Schema, "network": req.Network, "global_id": req.GlobalID,
		"gift_intent_id": req.GiftIntentID, "sender_agent_id": req.SenderAgentID, "recipient_agent_id": req.RecipientAgentID,
		"sender_agent_account": req.SenderAgentAccount, "asset_kind": req.AssetKind, "amount_atomic": req.AmountAtomic,
		"requested_valid_until": req.RequestedValidUntil, "recipient_ticket": "forbidden"}
	encoded, err := codec.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeAddressRequest(encoded); err == nil {
		t.Fatal("unknown field was accepted")
	} else {
		assertTypedError(t, err, ErrInvalidCanonical, RetryNever)
	}

	valid, err := Encode(req)
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append([]byte{0xd9, 0xd9, 0xf7}, valid...)
	if _, err := DecodeAddressRequest(nonCanonical); err == nil {
		t.Fatal("tagged/noncanonical CBOR was accepted")
	}
	// {"schema":"x","schema":"y"}: the duplicate is rejected before a
	// typed decoder can overwrite the first value with the second.
	duplicate := []byte{0xa2, 0x66, 's', 'c', 'h', 'e', 'm', 'a', 0x61, 'x', 0x66, 's', 'c', 'h', 'e', 'm', 'a', 0x61, 'y'}
	for name, decode := range map[string]func([]byte) error{
		"request":  func(raw []byte) error { _, err := DecodeAddressRequest(raw); return err },
		"response": func(raw []byte) error { _, err := DecodeAddressResponse(raw); return err },
		"offer":    func(raw []byte) error { _, err := DecodeSignedBOCOffer(raw); return err },
	} {
		if err := decode(duplicate); err == nil {
			t.Fatalf("%s duplicate canonical field was accepted", name)
		}
	}

	responseRaw, err := Encode(testResponse(t))
	if err != nil {
		t.Fatal(err)
	}
	boc := []byte{1, 2, 3}
	offerRaw, err := Encode(GiftSignedBOCOfferV1{Schema: SchemaSignedBOCOffer, GiftIntentID: req.GiftIntentID,
		AddressRequestDigest: "sha256:" + strings.Repeat("1", 64), AddressResponseDigest: "sha256:" + strings.Repeat("2", 64),
		SignedGiftID: SignedGiftID(boc), ExactSignedBOC: boc})
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]struct {
		raw    []byte
		decode func([]byte) error
	}{
		"response": {responseRaw, func(raw []byte) error { _, err := DecodeAddressResponse(raw); return err }},
		"offer":    {offerRaw, func(raw []byte) error { _, err := DecodeSignedBOCOffer(raw); return err }},
	} {
		t.Run(name+" unknown field", func(t *testing.T) {
			var object map[string]any
			if err := codec.Unmarshal(candidate.raw, &object); err != nil {
				t.Fatal(err)
			}
			object["future_authority"] = true
			changed, err := codec.Marshal(object)
			if err != nil {
				t.Fatal(err)
			}
			if err := candidate.decode(changed); err == nil {
				t.Fatal("unknown canonical field was accepted")
			} else {
				assertTypedError(t, err, ErrInvalidCanonical, RetryNever)
			}
		})
	}
}

func TestAmountsBindingsAndBOCIdentityFailClosed(t *testing.T) {
	for _, bad := range []string{"", "0", "01", "+1", "1.0", "1e3", " 1", "18446744073709551616"} {
		if _, err := ParseAmount(bad); err == nil {
			t.Fatalf("accepted amount %q", bad)
		}
	}
	if _, err := ParseActionAmount(strconv.FormatUint(MaxAgentAccountActionAtomic, 10)); err != nil {
		t.Fatalf("rejected maximum signed action amount: %v", err)
	}
	if _, err := ParseActionAmount(strconv.FormatUint(MaxAgentAccountActionAtomic+1, 10)); err == nil {
		t.Fatal("accepted amount above the Agent Account signed-action wire limit")
	}
	req := testRequest()
	response := testResponse(t)
	for name, mutate := range map[string]func(*GiftAddressResponseV1){
		"network":        func(v *GiftAddressResponseV1) { v.Network = "tos-other" },
		"global ID":      func(v *GiftAddressResponseV1) { v.GlobalID++ },
		"intent":         func(v *GiftAddressResponseV1) { v.GiftIntentID = strings.Repeat("2", 64) },
		"request digest": func(v *GiftAddressResponseV1) { v.RequestDigest = "sha256:" + strings.Repeat("3", 64) },
		"sender AgentID": func(v *GiftAddressResponseV1) { v.SenderAgentID = "agent_" + strings.Repeat("3", 64) },
		"recipient AgentID": func(v *GiftAddressResponseV1) {
			v.RecipientAgentID = "agent_" + strings.Repeat("4", 64)
		},
		"amount": func(v *GiftAddressResponseV1) { v.AmountAtomic = "2" },
		"expiry": func(v *GiftAddressResponseV1) { v.ResponseNotAfter = req.RequestedValidUntil + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := response
			mutate(&candidate)
			err := BindResponse(req, candidate)
			if err == nil {
				t.Fatal("response substitution was accepted")
			}
			assertTypedError(t, err, ErrIntentConflict, RetryNever)
		})
	}
	boc := []byte{1, 2, 3}
	offer := GiftSignedBOCOfferV1{Schema: SchemaSignedBOCOffer, GiftIntentID: req.GiftIntentID,
		AddressRequestDigest: "sha256:" + strings.Repeat("1", 64), AddressResponseDigest: "sha256:" + strings.Repeat("2", 64),
		SignedGiftID: SignedGiftID(boc), ExactSignedBOC: append([]byte(nil), boc...)}
	offer.ExactSignedBOC[0] ^= 1
	if err := offer.Validate(); err == nil {
		t.Fatal("changed bytes under one SignedGiftID were accepted")
	}
}

func TestCanonicalObjectsRejectEveryPublishedBound(t *testing.T) {
	req := testRequest()
	req.Network = strings.Repeat("n", MaxNetworkBytes+1)
	if _, err := Encode(req); err == nil {
		t.Fatal("overbound network was accepted")
	}

	offer := GiftSignedBOCOfferV1{Schema: SchemaSignedBOCOffer, GiftIntentID: strings.Repeat("1", 64),
		AddressRequestDigest: "sha256:" + strings.Repeat("2", 64), AddressResponseDigest: "sha256:" + strings.Repeat("3", 64)}
	for name, configure := range map[string]func(*GiftSignedBOCOfferV1){
		"BOC": func(v *GiftSignedBOCOfferV1) {
			v.ExactSignedBOC = make([]byte, MaxSignedBOCBytes+1)
			v.SignedGiftID = SignedGiftID(v.ExactSignedBOC)
		},
		"display message": func(v *GiftSignedBOCOfferV1) {
			v.ExactSignedBOC = []byte{1}
			v.SignedGiftID = SignedGiftID(v.ExactSignedBOC)
			v.DisplayMessage = strings.Repeat("m", MaxDisplayMessageBytes+1)
		},
		"padding": func(v *GiftSignedBOCOfferV1) {
			v.ExactSignedBOC = []byte{1}
			v.SignedGiftID = SignedGiftID(v.ExactSignedBOC)
			v.Padding = make([]byte, MaxPaddingBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := offer
			configure(&candidate)
			if _, err := Encode(candidate); err == nil {
				t.Fatal("overbound canonical object was accepted")
			}
		})
	}
	if _, err := DecodeAddressRequest(make([]byte, MaxCanonicalGiftBytes+1)); err == nil {
		t.Fatal("overbound canonical transport object was accepted")
	}
}

func TestTypedErrorsRejectUnboundedCodesAndRetryDispositions(t *testing.T) {
	cause := errors.New("original diagnostic")
	for _, err := range []error{
		NewError(ErrorCode("gift_future_error"), RetryNever, cause),
		NewError(ErrTerminal, RetryDisposition("retry-sometime"), cause),
	} {
		var typed TypedError
		if errors.As(err, &typed) {
			t.Fatalf("unbounded value produced a TypedError: %+v", typed)
		}
		if err == nil {
			t.Fatal("unbounded typed error value was accepted")
		}
		if !errors.Is(err, cause) {
			t.Fatal("invalid typed error construction lost its cause")
		}
	}

	finalityCause := errors.New("finality read unavailable")
	err := NewError(ErrFinalityUnavailable, RetryAfterFinalizedRead, finalityCause)
	assertTypedError(t, err, ErrFinalityUnavailable, RetryAfterFinalizedRead)
	if !errors.Is(err, finalityCause) {
		t.Fatal("typed error did not preserve its cause")
	}
}

func TestLifecycleRejectsSkippedAndTerminalTransitions(t *testing.T) {
	if err := ValidateSenderTransition(SenderDraft, SenderRecipientResolved); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSenderTransition(SenderDraft, SenderBOCSigned); err == nil {
		t.Fatal("skipped sender transition accepted")
	}
	if err := ValidateSenderTransition(SenderFinalizedPaid, SenderOfferDelivered); err == nil {
		t.Fatal("terminal sender state reopened")
	}
	if SenderTerminal(SenderFinalityUnknown) {
		t.Fatal("unknown finality is not terminal")
	}
	if err := ValidateRecipientTransition(RecipientFinalityUnknown, RecipientBroadcastSubmitted); err != nil {
		t.Fatal(err)
	}
}

func mustResponseDigest(t *testing.T, v GiftAddressResponseV1) string {
	t.Helper()
	digest, err := ResponseDigest(v)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func assertTypedError(t *testing.T, err error, code ErrorCode, retry RetryDisposition) {
	t.Helper()
	var typed TypedError
	if !errors.As(err, &typed) {
		t.Fatalf("expected TypedError, got %T: %v", err, err)
	}
	if typed.Code() != code || typed.Retry() != retry {
		t.Fatalf("typed error = (%q, %q), want (%q, %q)", typed.Code(), typed.Retry(), code, retry)
	}
}

func assertCanonicalGolden(t *testing.T, name string, value []byte, want string) {
	t.Helper()
	digest := sha256.Sum256(value)
	if got := hex.EncodeToString(digest[:]); got != want {
		t.Fatalf("%s canonical golden changed: %s", name, got)
	}
}
