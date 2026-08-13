package nativecore

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type senderStub struct{ destination, body, stateInit string }

func (s *senderStub) SendContractCell(_ context.Context, destination string, _ uint64, body, stateInit string) error {
	s.destination, s.body, s.stateInit = destination, body, stateInit
	return nil
}

func TestRelayerTransportsDirectRegistrationWithoutAnchor(t *testing.T) {
	l := testLocator(t)
	policy, privateKey := testPolicy(t)
	objectNonce := bytes32('o')
	id, err := DeriveAgentID(l.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: id,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('a'),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(privateKey, policy.Controllers[0].KeyId, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{}
	relay := &Relayer{Locator: l, Sender: sender, FundingNanoTOS: MinimumRelayFundingNanoTOS}
	hash, err := relay.Submit(context.Background(), &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}, 9)
	if err != nil || hash != built.HashString || sender.destination == "" || sender.body == "" || sender.stateInit == "" {
		t.Fatalf("relay: %v", err)
	}
}

func TestCapabilityRegistrationIsAuthorizedByCanonicalOwnerAgent(t *testing.T) {
	l := testLocator(t)
	policy, privateKey := testPolicy(t)
	ownerNonce := bytes32('o')
	owner, err := DeriveAgentID(l.Network, ownerNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	version := &nativev1.CapabilityVersionV1{Version: "1.0.0", ManifestDigest: "sha256:" + strings.Repeat("55", 32)}
	capabilityNonce := bytes32('c')
	capability, err := DeriveCapabilityID(l.Network, capabilityNonce, owner, version)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: capability,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('a'),
		Payload: &nativev1.NativeActionV1_RegisterCapability{RegisterCapability: &nativev1.RegisterCapabilityV1{
			ObjectNonce: capabilityNonce, OwnerAgentId: owner, InitialVersion: version}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(privateKey, policy.Controllers[0].KeyId, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{}
	relay := &Relayer{Locator: l, Sender: sender, FundingNanoTOS: MinimumRelayFundingNanoTOS}
	if _, err := relay.Submit(context.Background(), &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}, 10); err != nil {
		t.Fatal(err)
	}
	ownerContract, _ := l.Locate(owner)
	if sender.destination != ownerContract.Address || sender.stateInit != "" {
		t.Fatal("Capability registration bypassed owner Agent authorization")
	}
	bodyRaw, _ := base64.StdEncoding.DecodeString(sender.body)
	body, _ := cell.FromBOC(bodyRaw)
	opcode, _ := body.BeginParse().LoadUInt(32)
	if opcode != 0x4e560002 {
		t.Fatalf("opcode = %x", opcode)
	}
}
