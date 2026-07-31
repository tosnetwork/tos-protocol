package protocol

import (
	"testing"
	"time"
)

func TestSessionGrantValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	session := SessionGrant{
		Version: BaseEnvelopeVersion, SessionID: "session-0001",
		ServiceID: "edge.example.ai", ProfileID: "tos.ai.inference",
		Client: "client-key-1", RuntimeKeyID: "runtime-key-1",
		ManifestRevision: "manifest-1", Operations: []string{"INVOKE", "CANCEL"},
		MaxRequests: 10, MaxNanoTOS: 1000, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := session.Validate(now); err != nil {
		t.Fatal(err)
	}
	session.Operations = append(session.Operations, "INVOKE")
	if err := session.Validate(now); err == nil {
		t.Fatal("duplicate operation accepted")
	}
}

func TestDelegationMustAttenuate(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	parent := Delegation{
		Version: BaseEnvelopeVersion, DelegationID: "delegation-parent",
		Issuer: "owner", Subject: "controller", Audience: "edge.example.ai",
		Scopes: []string{"tos.ai.invoke", "tos.ai.cancel"}, MaxNanoTOS: 1000,
		MaxActions: 10, NotBefore: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := parent.Validate(now); err != nil {
		t.Fatal(err)
	}
	child := Delegation{
		Version: BaseEnvelopeVersion, DelegationID: "delegation-child",
		Issuer: parent.Subject, Subject: "runtime", Audience: parent.Audience,
		Scopes: []string{"tos.ai.invoke"}, ParentID: parent.DelegationID, Depth: 1,
		MaxNanoTOS: 500, MaxActions: 5, NotBefore: now, ExpiresAt: now.Add(30 * time.Minute),
	}
	if err := child.ValidateChildOf(parent, now); err != nil {
		t.Fatal(err)
	}
	child.Scopes = append(child.Scopes, "tos.ai.admin")
	if err := child.ValidateChildOf(parent, now); err == nil {
		t.Fatal("scope-expanding child accepted")
	}
}
