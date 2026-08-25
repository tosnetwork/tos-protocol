package agentcommerce

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

type pinnedCustodyKey struct{ key ed25519.PublicKey }

func (p pinnedCustodyKey) AuthorizeCustodyKey(authorityID, ownerID, agentID string, key ed25519.PublicKey, _ time.Time) error {
	if authorityID != "authority:owner" || ownerID != "owner:1" || agentID != "agent:buyer" || !bytes.Equal(key, p.key) {
		return errors.New("custody key is not pinned")
	}
	return nil
}

func TestCustodyAuthorizationBindsWriterAgreementAndTransfer(t *testing.T) {
	seed := bytes.Repeat([]byte{0x63}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(1_800_000_000, 0)
	body := CustodyActionAuthorization{SchemaVersion: 1, AuthorityID: "authority:owner", OwnerID: "owner:1", AgentID: "agent:buyer",
		SourceAccount: "-1:source", NetworkID: "tos:testnet", NetworkGlobalID: 42,
		StableActionID: "sha256:" + strings.Repeat("1", 64), ExactRequestDigest: "sha256:" + strings.Repeat("2", 64),
		WriterGeneration: 7, WriterFenceDigest: "sha256:" + strings.Repeat("3", 64), PolicyRevision: 4,
		MandateDigest: "sha256:" + strings.Repeat("4", 64), ApprovalDigestOrZero: "sha256:" + strings.Repeat("0", 64),
		AgreementBodyDigest: "sha256:" + strings.Repeat("5", 64), ObligationInstanceID: "sha256:" + strings.Repeat("6", 64),
		Destination: "0:destination", AmountAtomic: 50, ExpiresAtUnix: uint64(now.Unix() + 60)}
	signed, err := SignCustodyActionAuthorization(body, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCustodyActionAuthorization(signed, pinnedCustodyKey{privateKey.Public().(ed25519.PublicKey)}, now); err != nil {
		t.Fatal(err)
	}
	mutated := signed
	mutated.AmountAtomic++
	if err := VerifyCustodyActionAuthorization(mutated, pinnedCustodyKey{privateKey.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("changed transfer retained custody authorization")
	}
	mutated = signed
	mutated.WriterGeneration++
	if err := VerifyCustodyActionAuthorization(mutated, pinnedCustodyKey{privateKey.Public().(ed25519.PublicKey)}, now); err == nil {
		t.Fatal("changed writer generation retained custody authorization")
	}
}
