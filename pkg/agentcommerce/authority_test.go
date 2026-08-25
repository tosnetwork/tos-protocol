package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type fixedFenceResolver struct{ key ed25519.PublicKey }

func (r fixedFenceResolver) AuthorizeFenceKey(_ string, key ed25519.PublicKey, _ time.Time) error {
	if !key.Equal(r.key) {
		return errors.New("wrong authority key")
	}
	return nil
}

func TestWriterFenceAndAuthorizedAction(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	fence, err := SignWriterFence(WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: "agent:test",
		InstanceID: "instance:one", LeaseID: "lease:one", WriterGeneration: 3, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), AuthorityID: "authority:test", Scope: []string{"agreement.propose"}}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]SemanticValue{"owner_id": ID("owner:test"), "agent_id": ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("1", 64)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("2", 64))}
	request := []byte("canonical-request")
	action, err := BuildAuthorizedAction("owner:test", "agent:test", "agreement.propose", fields, request, fence, 7,
		"sha256:"+strings.Repeat("3", 64), "", "none", uint64(now.Add(30*time.Second).Unix()))
	if err != nil {
		t.Fatal(err)
	}
	action, err = SignAuthorizedAction(action, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorizedAction(action, fields, request, fence, fixedFenceResolver{key: publicKey}, now); err != nil {
		t.Fatal(err)
	}
	mutated := append([]byte(nil), request...)
	mutated[0] = 'C'
	if err := VerifyAuthorizedAction(action, fields, mutated, fence, fixedFenceResolver{key: publicKey}, now); err == nil {
		t.Fatal("changed request reused an AuthorizedAction")
	}
	tamperedAction := action
	tamperedAction.ExpectedPriorState = "different"
	if err := VerifyAuthorizedAction(tamperedAction, fields, request, fence, fixedFenceResolver{key: publicKey}, now); err == nil {
		t.Fatal("tampered action fields reused the authority proof")
	}
	unsignedAction := action
	unsignedAction.AuthorizationProof = ""
	if err := VerifyAuthorizedAction(unsignedAction, fields, request, fence, fixedFenceResolver{key: publicKey}, now); err == nil {
		t.Fatal("unsigned AuthorizedAction was accepted")
	}
	tampered := fence
	tampered.Body.WriterGeneration++
	if err := VerifyAuthorizedAction(action, fields, request, tampered, fixedFenceResolver{key: publicKey}, now); err == nil {
		t.Fatal("tampered writer generation was accepted")
	}
}

func TestAuthorityInstanceIdentityIsRecoverable(t *testing.T) {
	zero := "sha256:" + strings.Repeat("0", 64)
	request := AuthorityInstanceAllocationRequest{OwnerID: "owner:test", AgentID: "agent:test", PurposeKind: "messenger.contact",
		MandateDigest: "sha256:" + strings.Repeat("1", 64), ApprovalDigestOrZero: zero,
		DownstreamEffectDescriptorDigest: "sha256:" + strings.Repeat("2", 64), PredecessorAuthorityInstanceID: zero}
	digest, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := AuthorityInstanceAllocationRequestDigest(request)
	if err != nil || retry != digest {
		t.Fatalf("allocation digest changed on retry: %q %v", retry, err)
	}
	first, err := DeriveAuthorityInstanceID(request, 1)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveAuthorityInstanceID(request, 2)
	if err != nil || first == second {
		t.Fatal("distinct authority allocation sequence did not distinguish intentional repeats")
	}
}
