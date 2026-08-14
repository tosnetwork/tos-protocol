package nativecore

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type senderStub struct {
	destination, body, stateInit string
	calls                        int
	sendErr                      error
}

type resolverStub struct {
	states map[string]*nativev1.NativeStateV1
}

func (r resolverStub) ResolveState(_ context.Context, objectID, _ string) (*nativev1.NativeStateV1, bool, error) {
	state, found := r.states[objectID]
	return state, found, nil
}

func testRelayer(t *testing.T, locator *Locator, sender ContractCellSender, resolver RelayStateResolver) *Relayer {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	journal, err := NewFileRelayJournal(directory)
	if err != nil {
		t.Fatal(err)
	}
	return &Relayer{Locator: locator, Sender: sender, FundingNanoTOS: MinimumRelayFundingNanoTOS, Journal: journal, Resolver: resolver}
}

func (s *senderStub) SendContractCell(_ context.Context, destination string, _ uint64, body, stateInit string) error {
	s.destination, s.body, s.stateInit = destination, body, stateInit
	s.calls++
	return s.sendErr
}

func TestRelayerSubmissionFailsClosedWithoutDurableDependencies(t *testing.T) {
	relay := &Relayer{Locator: testLocator(t), Sender: &senderStub{}, FundingNanoTOS: MinimumRelayFundingNanoTOS}
	if _, err := relay.Submit(context.Background(), &nativev1.SignedNativeActionV1{Action: &nativev1.NativeActionV1{}}, 1); err == nil {
		t.Fatal("relayer accepted submission without durable journal and finalized resolver")
	}
}

func TestRelayerMirrorsContractCounterpartySignatureShape(t *testing.T) {
	nonempty := []*nativev1.SignatureV1{{}}
	for _, kind := range []Kind{KindUpdateAgentPolicy, KindInitiateRecovery, KindTransferCapability} {
		if err := validateSignatureShape(kind, nonempty); err != nil {
			t.Fatalf("required counterparty shape rejected for kind %d: %v", kind, err)
		}
		if err := validateSignatureShape(kind, nil); err == nil {
			t.Fatalf("empty required counterparty shape accepted for kind %d", kind)
		}
	}
	for _, kind := range []Kind{KindRegisterAgent, KindDelegateAgent, KindCompleteRecovery, KindRevokeAgent,
		KindRegisterCapability, KindAddCapabilityVersion, KindRevokeCapability} {
		if err := validateSignatureShape(kind, nil); err != nil {
			t.Fatalf("empty counterparty shape rejected for kind %d: %v", kind, err)
		}
		if err := validateSignatureShape(kind, nonempty); err == nil {
			t.Fatalf("forbidden counterparty shape accepted for kind %d", kind)
		}
	}
}

func TestRelayerDeduplicatesCanonicalActionAcrossRequestKeys(t *testing.T) {
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
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{}})
	submission := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	forbidden := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}, CounterpartySignatures: []*nativev1.SignatureV1{signature}}
	if _, err := relay.SubmitIdempotent(context.Background(), forbidden, "forbidden-signature-shape"); err == nil || sender.calls != 0 {
		t.Fatalf("forbidden counterparty signature reached paid broadcast: err=%v calls=%d", err, sender.calls)
	}
	hash, err := relay.SubmitIdempotent(context.Background(), submission, "audit-key-one")
	if err != nil || hash != built.HashString || sender.destination == "" || sender.body == "" || sender.stateInit == "" {
		t.Fatalf("relay: %v", err)
	}
	if _, err := relay.SubmitIdempotent(context.Background(), submission, "audit-key-two"); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 {
		t.Fatalf("completed intent caused %d paid broadcasts", sender.calls)
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
	ownerState := &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: owner, Policy: policy}}}
	relay := testRelayer(t, l, sender, resolverStub{states: map[string]*nativev1.NativeStateV1{owner: ownerState}})
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

func TestRelayerResolvesAmbiguousIntentWithoutRebroadcast(t *testing.T) {
	l := testLocator(t)
	policy, privateKey := testPolicy(t)
	objectNonce := bytes32('q')
	id, err := DeriveAgentID(l.Network, objectNonce, policy)
	if err != nil {
		t.Fatal(err)
	}
	action := &nativev1.NativeActionV1{Protocol: Protocol, Network: l.Network, TargetObjectId: id,
		TargetContractCodeHash: l.CodeHash, Generation: 1, Sequence: 1, Nonce: bytes32('r'),
		Payload: &nativev1.NativeActionV1_RegisterAgent{RegisterAgent: &nativev1.RegisterAgentV1{ObjectNonce: objectNonce, InitialPolicy: policy}}}
	built, err := BuildAction(action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(privateKey, policy.Controllers[0].KeyId, built)
	if err != nil {
		t.Fatal(err)
	}
	sender := &senderStub{sendErr: errors.New("ambiguous transport result")}
	resolver := resolverStub{states: map[string]*nativev1.NativeStateV1{}}
	relay := testRelayer(t, l, sender, resolver)
	submission := &nativev1.SignedNativeActionV1{Action: action, AuthoritySignatures: []*nativev1.SignatureV1{signature}}
	if _, err := relay.Submit(context.Background(), submission, 11); err == nil {
		t.Fatal("ambiguous transport result was reported as complete")
	}
	sender.sendErr = nil
	resolver.states[id] = &nativev1.NativeStateV1{State: &nativev1.NativeStateV1_Agent{Agent: &nativev1.AgentStateV1{AgentId: id, LastActionHash: built.HashString, Policy: policy}}}
	hash, err := relay.Submit(context.Background(), submission, 11)
	if err != nil || hash != built.HashString {
		t.Fatalf("read-only ambiguous recovery = %q, %v", hash, err)
	}
	if sender.calls != 1 {
		t.Fatalf("ambiguous intent caused %d paid broadcasts", sender.calls)
	}
}
