package nativeregistry

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
)

type testResolver struct {
	mu      sync.Mutex
	actions map[string]Result
	states  map[string]Result
	err     error
}

type testLocator struct{}

func (testLocator) Locate(nativeprotocol.RegistryAction) (nativeexecution.ContractIdentity, error) {
	return testContract(), nil
}

func (r *testResolver) CheckReady(context.Context) error { return r.err }
func (r *testResolver) Head(context.Context) (FinalizedHead, error) {
	if r.err != nil {
		return FinalizedHead{}, r.err
	}
	return FinalizedHead{Network: testNetwork(), Checkpoint: 9, BlockUnixSeconds: 1_800_000_000}, nil
}
func (r *testResolver) ResolveAction(_ context.Context, id string) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return Result{}, r.err
	}
	value, ok := r.actions[id]
	if !ok {
		return Result{}, ErrCanonicalNotFound
	}
	return value, nil
}
func (r *testResolver) ResolveState(_ context.Context, id, digest string) (Result, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.states[id+"\x00"+digest]
	if !ok && digest == "" {
		value, ok = r.states[id]
	}
	if !ok {
		return Result{}, ErrCanonicalNotFound
	}
	return value, nil
}

type testPublisher struct {
	mu             sync.Mutex
	resolver       *testResolver
	result         Result
	resolveErr     error
	publishErrOnce error
	broadcasts     int
	journal        map[string]string
}

func (p *testPublisher) CheckReady(context.Context) error { return nil }
func (p *testPublisher) Resolve(_ context.Context, _ Submission, actionID, digest string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.resolveErr != nil {
		return p.resolveErr
	}
	stored, ok := p.journal[actionID]
	if !ok {
		return ErrPublisherNotFound
	}
	if stored != digest {
		return errors.New("journal semantic conflict")
	}
	return nil
}
func (p *testPublisher) Publish(_ context.Context, _ Submission, actionID, digest string) error {
	p.mu.Lock()
	if stored, ok := p.journal[actionID]; ok {
		p.mu.Unlock()
		if stored != digest {
			return errors.New("journal semantic conflict")
		}
		return nil
	}
	p.journal[actionID] = digest // durable intent precedes mutation
	p.broadcasts++
	err := p.publishErrOnce
	p.publishErrOnce = nil
	p.mu.Unlock()
	p.resolver.mu.Lock()
	p.resolver.actions[actionID] = p.result
	p.resolver.states[p.result.State.AgentID] = p.result
	p.resolver.mu.Unlock()
	return err
}

func testRegistration(t *testing.T) (Submission, Result) {
	t.Helper()
	network := testNetwork()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	policy := nativeprotocol.ControllerPolicy{Threshold: 1, RecoveryThreshold: 1, Controllers: []nativeprotocol.ControllerKey{{KeyID: "root-1", Algorithm: nativeprotocol.SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "recovery"}}}, RecoveryKeyIDs: []string{"root-1"}, RecoveryTimelock: 10}
	policyCBOR, policyDigest, err := nativeprotocol.EncodeControllerPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(bytesOf(0x31, 32))
	agentID, err := nativeprotocol.AgentID(nativeprotocol.AgentBootstrap{Version: nativeprotocol.Version, Network: network, ObjectNonceBase64: nonce, InitialControllerPolicy: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	payloadCBOR, payloadDigest, err := nativeprotocol.EncodePayload(nativeprotocol.ActionRegisterAgent, nativeprotocol.RegisterAgentPayload{ObjectNonceBase64: nonce, InitialPolicyDigest: policyDigest, InitialPolicyCBORBase64: policyCBOR})
	if err != nil {
		t.Fatal(err)
	}
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: nativeprotocol.ActionRegisterAgent, Network: network, AgentID: agentID, Generation: 1, Sequence: 1, PolicyDigest: policyDigest, PayloadDigest: payloadDigest, PayloadCBORBase64: payloadCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(bytesOf(0x51, 32))}
	signature, err := nativeprotocol.SignAction(privateKey, "root-1", action)
	if err != nil {
		t.Fatal(err)
	}
	state, err := nativeprotocol.DeriveNextState(nil, action, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	actionID, _ := nativeprotocol.ActionDigest(action)
	stateDigest, _ := nativeprotocol.StateDigest(state)
	event := nativeprotocol.RegistryEvent{Version: nativeprotocol.Version, Kind: action.Kind, Network: network, ActionDigest: actionID, AgentID: agentID, Generation: 1, Sequence: 1, StateDigest: stateDigest}
	eventDigest, _ := nativeprotocol.EventDigest(event)
	observation := nativeprotocol.EventObservation{Version: nativeprotocol.Version, Network: network, EventDigest: eventDigest, Reference: nativeprotocol.ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("33", 32), LogicalTime: 7, TransactionHash: "sha256:" + strings.Repeat("44", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32)}, FinalizedCheckpoint: 9, FinalizedRootHash: "sha256:" + strings.Repeat("66", 32), FinalizedFileHash: "sha256:" + strings.Repeat("77", 32), BlockUnixSeconds: 1_800_000_000, InclusionProofDigest: "sha256:" + strings.Repeat("88", 32)}
	contract := testContract()
	unsigned, err := nativeexecution.Build(nil, action, "", policy, nil, 1_800_000_000, contract)
	if err != nil {
		t.Fatal(err)
	}
	executionSignature, err := nativeexecution.Sign(privateKey, "root-1", unsigned.Execution)
	if err != nil {
		t.Fatal(err)
	}
	unsigned.Execution.AuthoritySignatures = []nativeexecution.Signature{executionSignature}
	return Submission{Version: nativeprotocol.Version, Action: action, AuthorityPolicyCBORBase64: policyCBOR, AuthoritySignatures: []nativeprotocol.Signature{signature}, Execution: unsigned.Execution}, Result{ActionID: actionID, Action: action, Event: event, State: state, Observation: observation}
}

func testContract() nativeexecution.ContractIdentity {
	return nativeexecution.ContractIdentity{Network: testNetwork(), Address: "0:" + strings.Repeat("33", 32), ActionAnchorAddress: "0:" + strings.Repeat("99", 32), AllowedCodeHash: "tvm-cell-sha256:" + strings.Repeat("55", 32)}
}

func testNetwork() nativeprotocol.NetworkDomain {
	return nativeprotocol.NetworkDomain{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
}

func TestSubmitRequiresTypedJournalAbsenceAndLiveFinality(t *testing.T) {
	submission, result := testRegistration(t)
	resolver := &testResolver{actions: map[string]Result{}, states: map[string]Result{}}
	publisher := &testPublisher{resolver: resolver, result: result, resolveErr: errors.New("proxy returned 404"), journal: map[string]string{}}
	service, _ := New(resolver, publisher, testLocator{})
	if _, _, err := service.Submit(context.Background(), submission); err == nil {
		t.Fatal("generic absence was accepted")
	}
	if publisher.broadcasts != 0 {
		t.Fatalf("generic absence caused %d broadcasts", publisher.broadcasts)
	}
	publisher.resolveErr = nil
	got, created, err := service.Submit(context.Background(), submission)
	if err != nil || !created || got.ActionID != result.ActionID || publisher.broadcasts != 1 {
		t.Fatalf("submit: created=%v broadcasts=%d result=%+v err=%v", created, publisher.broadcasts, got, err)
	}
	if _, created, err = service.Submit(context.Background(), submission); err != nil || created || publisher.broadcasts != 1 {
		t.Fatalf("replay: created=%v broadcasts=%d err=%v", created, publisher.broadcasts, err)
	}
}

func TestLostPublishResponseRecoversReadOnlyWithoutRebroadcast(t *testing.T) {
	submission, result := testRegistration(t)
	resolver := &testResolver{actions: map[string]Result{}, states: map[string]Result{}}
	publisher := &testPublisher{resolver: resolver, result: result, publishErrOnce: errors.New("lost response"), journal: map[string]string{}}
	service, _ := New(resolver, publisher, testLocator{})
	if _, _, err := service.Submit(context.Background(), submission); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("lost response not ambiguous: %v", err)
	}
	if publisher.broadcasts != 1 {
		t.Fatalf("got %d broadcasts", publisher.broadcasts)
	}
	if _, created, err := service.Submit(context.Background(), submission); err != nil || created || publisher.broadcasts != 1 {
		t.Fatalf("recovery: created=%v broadcasts=%d err=%v", created, publisher.broadcasts, err)
	}
}

func bytesOf(first byte, size int) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = first + byte(i)
	}
	return value
}
