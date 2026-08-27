package agentcommerce

import (
	"crypto/ed25519"
	"errors"
	"math"
	"testing"
	"time"
)

type operationTestResolver struct{ key ed25519.PublicKey }

func (resolver operationTestResolver) AuthorizeAgentOperationKey(agentID string, profile ProfileRefV1,
	key ed25519.PublicKey, _ time.Time, proof []byte) error {
	if agentID != "agent:publisher" || profile.ProfileURI != "tos.identity.agent-key.v1" ||
		!key.Equal(resolver.key) || string(proof) != "proof" {
		return errors.New("unexpected operation authority")
	}
	return nil
}

func TestAgentOperationV1RejectsWrappedAndFutureAuthorityTimes(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	profile := ProfileRefV1{ProfileURI: AgentIntentPayloadProfileURI, ProfileVersion: 1,
		ProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	payload := []byte{0xa1, 0x61, 0x78, 0x01}
	payloadDigest, _ := AgentOperationPayloadDigest(profile, payload)
	body := AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "PUBLICATION",
		OpcodeName: "POST", OpcodeVersion: 1, OperationID: "operation:time", ActorAgentID: "agent:publisher",
		AuthorizationRef: ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1,
			ProfileDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		AudienceDescriptor: "public", OrderingDomain: "publication:time", CreatedAtUnix: uint64(math.MaxInt64) + 1,
		PayloadProfile: profile, PayloadDigest: payloadDigest, PayloadSize: uint64(len(payload))}
	if ValidateAgentOperationBodyV1(body) == nil {
		t.Fatal("creation time above MaxInt64 was accepted")
	}
	body.CreatedAtUnix = uint64(now.Add(MaxAgentOperationClockSkew + time.Second).Unix())
	envelope, err := SignAgentOperationV1(body, body.ActorAgentID, privateKey, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	if VerifyAgentOperationV1(envelope, payload, operationTestResolver{key: publicKey}, now) == nil {
		t.Fatal("future creation time outside clock skew was accepted")
	}
	body.CreatedAtUnix = uint64(now.Unix())
	body.NotBeforeUnix = uint64(math.MaxInt64) + 1
	if ValidateAgentOperationBodyV1(body) == nil {
		t.Fatal("not-before time above MaxInt64 was accepted")
	}
	body.NotBeforeUnix = 0
	body.ExpiresAtUnix = uint64(math.MaxInt64) + 1
	if ValidateAgentOperationBodyV1(body) == nil {
		t.Fatal("expiry above MaxInt64 was accepted")
	}
}

func TestAgentOperationV1BindsPayloadAndAuthority(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_900_000_000, 0).UTC()
	profile := ProfileRefV1{ProfileURI: AgentIntentPayloadProfileURI, ProfileVersion: 1,
		ProfileDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	payload := []byte{0xa1, 0x61, 0x78, 0x01}
	payloadDigest, err := AgentOperationPayloadDigest(profile, payload)
	if err != nil {
		t.Fatal(err)
	}
	authorization := ProfileRefV1{ProfileURI: "tos.identity.agent-key.v1", ProfileVersion: 1,
		ProfileDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	body := AgentOperationBodyV1{SchemaVersion: 1, NetworkID: "tos:test", OpcodeNamespace: "PUBLICATION",
		OpcodeName: "POST", OpcodeVersion: 1, OperationID: "operation:1", ActorAgentID: "agent:publisher",
		AuthorizationRef: authorization, AudienceDescriptor: "public", ObjectID: "service:guarantor:1",
		OrderingDomain: "publication:service:guarantor:1", Sequence: 1, CreatedAtUnix: uint64(now.Unix()),
		NotBeforeUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		PayloadProfile: profile, PayloadDigest: payloadDigest, PayloadSize: uint64(len(payload))}
	envelope, err := SignAgentOperationV1(body, body.ActorAgentID, privateKey, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	resolver := operationTestResolver{key: publicKey}
	if err := VerifyAgentOperationV1(envelope, payload, resolver, now); err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-1] ^= 1
	if VerifyAgentOperationV1(envelope, tampered, resolver, now) == nil {
		t.Fatal("tampered operation payload was accepted")
	}
	envelope.Body.ObjectID = "service:guarantor:2"
	if VerifyAgentOperationV1(envelope, payload, resolver, now) == nil {
		t.Fatal("tampered signed operation body was accepted")
	}
}
