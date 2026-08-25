package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestOperationAdmissionBindsCarrierActorAudienceAndResources(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	resource, err := AdmissionResourceVectorDigest("publication.publish", 4096, map[string]uint64{"index_entries": 1})
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := NewOperationAdmissionChallenge(OperationAdmissionChallengeBody{SchemaVersion: 1,
		ProfileURI: "tos.operation-admission.hashcash.v1", CarrierID: "carrier:test", ActorID: "agent:test",
		OperationKind: "publication.publish", Audience: "public:indexable", DeclaredBytes: 4096,
		ResourceVectorDigest: resource, DifficultyBits: 8, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Minute).Unix())}, private)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SolveOperationAdmission(challenge, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationAdmission(proof, public, "agent:test", "publication.publish", "public:indexable", 4096, resource, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyOperationAdmission(proof, public, "agent:other", "publication.publish", "public:indexable", 4096, resource, now); err == nil {
		t.Fatal("cross-actor replay was accepted")
	}
	if err := VerifyOperationAdmission(proof, public, "agent:test", "publication.publish", "public:indexable", 4097, resource, now); err == nil {
		t.Fatal("undersized admission proof was accepted")
	}
	proof.Counter++
	if err := VerifyOperationAdmission(proof, public, "agent:test", "publication.publish", "public:indexable", 4096, resource, now); err == nil {
		t.Fatal("changed proof work was accepted")
	}
}
