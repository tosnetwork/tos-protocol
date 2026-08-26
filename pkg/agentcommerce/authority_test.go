package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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

type fixedCurrentFenceResolver struct {
	fixedFenceResolver
	current WriterFenceBody
	err     error
}

func (r fixedCurrentFenceResolver) ConfirmCurrentWriterFence(fence WriterFence, _ time.Time) error {
	if r.err != nil {
		return r.err
	}
	if fence.Body.OwnerID != r.current.OwnerID || fence.Body.AgentID != r.current.AgentID ||
		fence.Body.InstanceID != r.current.InstanceID || fence.Body.LeaseID != r.current.LeaseID ||
		fence.Body.WriterGeneration != r.current.WriterGeneration || fence.Body.AuthorityID != r.current.AuthorityID {
		return errors.New("writer generation was superseded")
	}
	return nil
}

func TestConfirmCurrentWriterFenceFailsClosedAfterTakeover(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	old := WriterFence{Body: WriterFenceBody{OwnerID: "owner:test", AgentID: "agent:test", InstanceID: "instance:old",
		LeaseID: "lease:old", WriterGeneration: 7, AuthorityID: "authority:test", ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}}
	current := old.Body
	current.InstanceID = "instance:new"
	current.LeaseID = "lease:new"
	current.WriterGeneration++
	resolver := fixedCurrentFenceResolver{current: current}
	if err := ConfirmCurrentWriterFence(old, resolver, now); err == nil {
		t.Fatal("unexpired but superseded writer fence was accepted")
	}
	if err := ConfirmCurrentWriterFence(old, nil, now); err == nil {
		t.Fatal("missing current-writer authority was accepted")
	}
	currentFence := old
	currentFence.Body = current
	if err := ConfirmCurrentWriterFence(currentFence, resolver, now); err != nil {
		t.Fatalf("current writer fence was rejected: %v", err)
	}
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
	wrongPrincipalFields := map[string]SemanticValue{"owner_id": ID("owner:other"), "agent_id": ID("agent:test"),
		"agreement_body_digest": Digest32("sha256:" + strings.Repeat("1", 64)),
		"recipient_set_digest":  Digest32("sha256:" + strings.Repeat("2", 64))}
	if _, err := BuildAuthorizedAction("owner:test", "agent:test", "agreement.propose", wrongPrincipalFields, request, fence, 7,
		"sha256:"+strings.Repeat("3", 64), "", "none", uint64(now.Add(30*time.Second).Unix())); err == nil {
		t.Fatal("semantic owner different from AuthorizedAction owner was accepted")
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

func TestWriterFenceAndAuthorizedActionRejectEd25519TextAliases(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	fence, err := SignWriterFence(WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: "agent:test",
		InstanceID: "instance:one", LeaseID: "lease:one", WriterGeneration: 3, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix()), AuthorityID: "authority:test",
		Scope: []string{"agreement.propose"}}, privateKey)
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
	resolver := fixedFenceResolver{key: publicKey}

	uppercaseKey := "ed25519:" + strings.ToUpper(strings.TrimPrefix(fence.PublicKey, "ed25519:"))
	trailingAlias := ed25519TrailingBitAlias(t, fence.Proof)
	for name, mutate := range map[string]func(*WriterFence){
		"uppercase key hex": func(value *WriterFence) { value.PublicKey = uppercaseKey },
		"key CRLF":          func(value *WriterFence) { value.PublicKey += "\r\n" },
		"proof CRLF":        func(value *WriterFence) { value.Proof += "\r\n" },
		"proof trailing bits": func(value *WriterFence) {
			value.Proof = trailingAlias
		},
	} {
		t.Run("writer fence "+name, func(t *testing.T) {
			mutated := fence
			mutate(&mutated)
			if err := VerifyWriterFence(mutated, resolver, now, "agreement.propose"); err == nil {
				t.Fatal("writer fence accepted a non-canonical Ed25519 spelling")
			}
			if _, err := WriterFenceDigest(mutated); err == nil {
				t.Fatal("writer fence digest accepted a non-canonical Ed25519 spelling")
			}
		})
	}

	actionUppercaseKey := "ed25519:" + strings.ToUpper(strings.TrimPrefix(action.AuthorityPublicKey, "ed25519:"))
	actionTrailingAlias := ed25519TrailingBitAlias(t, action.AuthorizationProof)
	for name, mutate := range map[string]func(*AuthorizedAction){
		"uppercase key hex": func(value *AuthorizedAction) { value.AuthorityPublicKey = actionUppercaseKey },
		"key CRLF":          func(value *AuthorizedAction) { value.AuthorityPublicKey += "\r\n" },
		"proof CRLF":        func(value *AuthorizedAction) { value.AuthorizationProof += "\r\n" },
		"proof trailing bits": func(value *AuthorizedAction) {
			value.AuthorizationProof = actionTrailingAlias
		},
	} {
		t.Run("authorized action "+name, func(t *testing.T) {
			mutated := action
			mutate(&mutated)
			if _, err := AuthorizedActionDigest(mutated); err == nil {
				t.Fatal("AuthorizedAction digest accepted a non-canonical Ed25519 spelling")
			}
			if err := VerifyAuthorizedAction(mutated, fields, request, fence, resolver, now); err == nil {
				t.Fatal("AuthorizedAction accepted a non-canonical Ed25519 spelling")
			}
		})
	}
}

func ed25519TrailingBitAlias(t *testing.T, value string) string {
	t.Helper()
	const prefix = "ed25519:"
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	encoded := strings.TrimPrefix(value, prefix)
	if len(encoded) == len(value) || len(encoded) == 0 {
		t.Fatal("test Ed25519 value has no scheme or payload")
	}
	index := strings.IndexByte(alphabet, encoded[len(encoded)-1])
	if index < 0 {
		t.Fatal("test Ed25519 value is not base64url")
	}
	alternate := encoded[:len(encoded)-1] + string(alphabet[(index&^3)|((index+1)&3)])
	originalBytes, originalErr := base64.RawURLEncoding.DecodeString(encoded)
	alternateBytes, alternateErr := base64.RawURLEncoding.DecodeString(alternate)
	if originalErr != nil || alternateErr != nil || !bytes.Equal(originalBytes, alternateBytes) || alternate == encoded {
		t.Fatal("failed to construct an equivalent non-canonical base64url spelling")
	}
	return prefix + alternate
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
