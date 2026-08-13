//go:build integration

package atosrpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeprotocol"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

type nativeAcceptancePolicy struct {
	value   nativeprotocol.ControllerPolicy
	cbor    string
	digest  string
	private map[string]ed25519.PrivateKey
}

type nativeAcceptance struct {
	t       *testing.T
	client  atostosv1connect.NativeRegistryServiceClient
	token   string
	locator *nativeexecution.ObjectLocator
	network nativeprotocol.NetworkDomain
	serial  int
	runID   string
}

// TestPhase5BNativeRegistryLocalnet traverses the production ConnectRPC,
// publisher Unix socket, hardened tosctl and three-validator resolver paths.
// It is opt-in because it requires those external processes; unit tests never
// replace this acceptance gate with an in-memory authority.
func TestPhase5BNativeRegistryLocalnet(t *testing.T) {
	baseURL := os.Getenv("TOS_PHASE5B_RPC_URL")
	codePath := os.Getenv("TOS_PHASE5B_CODE_BOC")
	if baseURL == "" || codePath == "" {
		t.Skip("set TOS_PHASE5B_RPC_URL and TOS_PHASE5B_CODE_BOC for real localnet acceptance")
	}
	codeBOC, err := os.ReadFile(codePath)
	if err != nil {
		t.Fatal(err)
	}
	network := nativeprotocol.NetworkDomain{
		NetworkID:       requiredEnv(t, "TOS_PHASE5B_NETWORK_ID"),
		GenesisRootHash: requiredEnv(t, "TOS_PHASE5B_GENESIS_ROOT"),
		GenesisFileHash: requiredEnv(t, "TOS_PHASE5B_GENESIS_FILE"),
	}
	locator, err := nativeexecution.NewObjectLocator(network, 0,
		base64.StdEncoding.EncodeToString(codeBOC), requiredEnv(t, "TOS_PHASE5B_CODE_HASH"))
	if err != nil {
		t.Fatal(err)
	}
	a := &nativeAcceptance{t: t, token: requiredEnv(t, "TOS_PHASE5B_TOKEN"), locator: locator, network: network,
		runID:  requiredEnv(t, "TOS_PHASE5B_RUN_ID"),
		client: atostosv1connect.NewNativeRegistryServiceClient(http.DefaultClient, baseURL)}

	owner1 := acceptancePolicy(t, "a", 0x10)
	owner1Rotated := acceptancePolicy(t, "a2", 0x30)
	owner2 := acceptancePolicy(t, "b", 0x50)
	owner2Recovered := acceptancePolicy(t, "b2", 0x70)

	agent1, agent1State := a.registerAgent(owner1, 0x96)
	capabilityNonce := a.nonce(0xa6)
	capabilityID, err := nativeprotocol.CapabilityID(nativeprotocol.CapabilityBootstrap{
		Version: nativeprotocol.Version, Network: network, OwnerAgentID: agent1,
		ObjectNonceBase64: capabilityNonce,
	})
	if err != nil {
		t.Fatal(err)
	}

	delegatePayload := nativeprotocol.DelegationPayload{
		DelegateKeyID: "quote-a", Purposes: []string{"quote"}, Resources: []string{capabilityID},
		ValidFromCheckpoint:     1,
		ValidUntilCheckpoint:    1_000_000_000,
		MaxStalenessCheckpoints: 100,
	}
	agent1State = a.submitAction(&agent1State.State, nativeprotocol.ActionDelegateAgent, agent1, "", "",
		agent1State.State.Generation, agent1State.State.Sequence+1, owner1, nil, delegatePayload, 0)

	version1 := nativeprotocol.CapabilityVersionPayload{
		OwnerAgentID: agent1,
		Manifest: nativeprotocol.ManifestReference{Digest: acceptanceDigest(0xb1),
			MediaType: "application/vnd.atos.native-capability+json", SizeBytes: 128,
			Locations: []string{"https://example.invalid/native/manifest-v1"}},
		Endpoints:         []nativeprotocol.EndpointReference{{Transport: "a2a", EndpointDigest: acceptanceDigest(0xb2), RecipientKeyID: "receipt-a"}},
		QuoteSignerKeyIDs: []string{"quote-a"}, ReceiptSignerKeyIDs: []string{"receipt-a"},
		ValidFromCheckpoint:  1,
		ValidUntilCheckpoint: 1_000_000_000,
	}
	capabilityState := a.submitAction(nil, nativeprotocol.ActionRegisterCapability, agent1, capabilityID, "1.0.0",
		1, 1, owner1, nil, nativeprotocol.RegisterCapabilityPayload{ObjectNonceBase64: capabilityNonce, Version: version1}, 0)
	version2 := version1
	version2.Manifest.Digest = acceptanceDigest(0xb3)
	version2.Manifest.Locations = []string{"https://example.invalid/native/manifest-v2"}
	version2.Endpoints = []nativeprotocol.EndpointReference{{Transport: "a2a", EndpointDigest: acceptanceDigest(0xb4), RecipientKeyID: "receipt-a"}}
	capabilityState = a.submitAction(&capabilityState.State, nativeprotocol.ActionUpdateCapability, agent1, capabilityID, "2.0.0",
		capabilityState.State.Generation, capabilityState.State.Sequence+1, owner1, nil, version2, 0)

	agent1State = a.submitAction(&agent1State.State, nativeprotocol.ActionUpdateAgentPolicy, agent1, "", "",
		agent1State.State.Generation, agent1State.State.Sequence+1, owner1, nil,
		nativeprotocol.UpdatePolicyPayload{NewPolicyDigest: owner1Rotated.digest, NewPolicyCBORBase64: owner1Rotated.cbor}, 0)
	a.assertOldKeyRejected(agent1State.State, owner1Rotated, owner1, nativeprotocol.ActionDelegateAgent,
		nativeprotocol.DelegationPayload{DelegateKeyID: "quote-a2", Purposes: []string{"quote"}, Resources: []string{capabilityID}, ValidFromCheckpoint: 1, ValidUntilCheckpoint: 1_000_000_000, MaxStalenessCheckpoints: 10})

	agent2, agent2State := a.registerAgent(owner2, 0xc5)
	capabilityState = a.submitAction(&capabilityState.State, nativeprotocol.ActionTransferCapability, agent1, capabilityID, "",
		capabilityState.State.Generation+1, 1, owner1Rotated, &owner2,
		nativeprotocol.TransferCapabilityPayload{CurrentOwnerAgentID: agent1, NewOwnerAgentID: agent2,
			NewOwnerPolicyDigest: owner2.digest, NewOwnerPolicyCBORBase64: owner2.cbor}, 0)
	if capabilityState.State.OwnerAgentID != agent2 {
		t.Fatalf("transfer owner=%s want=%s", capabilityState.State.OwnerAgentID, agent2)
	}
	a.assertOldCapabilityKeyRejected(capabilityState.State, agent2, owner2, owner1Rotated)

	// The signed not-before time is deliberately conservative: it must be no
	// earlier than the actual inclusion time plus the old canonical timelock.
	// The accelerated localnet advances consensus time faster than wall time.
	// An offline signer deliberately chooses a conservative future not-before
	// value; submission below waits on canonical TOS time, never local time.
	// Derive the recovery not-before boundary exclusively from finalized TOS
	// time. A long-running accelerated localnet can be far ahead of wall time,
	// and an offline/gateway clock must never select registry authority time.
	executeAfter := agent2State.Observation.BlockUnixSeconds + 120
	initiation := a.submitAction(&agent2State.State, nativeprotocol.ActionInitiateRecovery, agent2, "", "",
		agent2State.State.Generation, agent2State.State.Sequence+1, owner2, nil,
		nativeprotocol.InitiateRecoveryPayload{NewPolicyDigest: owner2Recovered.digest,
			ExecuteAfterUnixSeconds: executeAfter, NewPolicyCBORBase64: owner2Recovered.cbor}, 0)
	initiationDigest, _ := nativeprotocol.ActionDigest(initiation.Action)
	recoverPayload := nativeprotocol.RecoverAgentPayload{NewPolicyDigest: owner2Recovered.digest,
		InitiationActionDigest: initiationDigest, InitiationReference: initiation.Observation.Reference,
		ExecuteAfterUnixSeconds: executeAfter}
	early := a.buildSubmission(&initiation.State, nativeprotocol.ActionRecoverAgent, agent2, "", "",
		initiation.State.Generation+1, 1, owner2, nil, recoverPayload, executeAfter)
	a.expectRejected(early, "recovery before canonical not-before time")
	agent2State = a.submit(early)
	if agent2State.State.CurrentPolicyDigest != owner2Recovered.digest {
		t.Fatal("recovery did not install the committed policy")
	}
	a.assertOldKeyRejected(agent2State.State, owner2Recovered, owner2, nativeprotocol.ActionDelegateAgent,
		nativeprotocol.DelegationPayload{DelegateKeyID: "quote-b2", Purposes: []string{"quote"}, Resources: []string{capabilityID}, ValidFromCheckpoint: 1, ValidUntilCheckpoint: 1_000_000_000, MaxStalenessCheckpoints: 10})

	capabilityState = a.submitAction(&capabilityState.State, nativeprotocol.ActionRevokeCapability, agent2, capabilityID, "1.0.0",
		capabilityState.State.Generation, capabilityState.State.Sequence+1, owner2Recovered, nil,
		nativeprotocol.RevocationPayload{Scope: "version", ReasonCode: "superseded"}, 0)
	capabilityState = a.submitAction(&capabilityState.State, nativeprotocol.ActionRevokeCapability, agent2, capabilityID, "",
		capabilityState.State.Generation, capabilityState.State.Sequence+1, owner2Recovered, nil,
		nativeprotocol.RevocationPayload{Scope: "lineage", ReasonCode: "retired"}, 0)
	a.assertCapabilityTombstone(capabilityState.State, agent2, owner2Recovered)

	agent2State = a.submitAction(&agent2State.State, nativeprotocol.ActionRevokeAgent, agent2, "", "",
		agent2State.State.Generation, agent2State.State.Sequence+1, owner2Recovered, nil,
		nativeprotocol.RevocationPayload{Scope: "agent", ReasonCode: "retired"}, 0)
	a.assertAgentTombstone(agent2State.State, owner2Recovered)

	// Current state is resolved again over the public read path, not reused
	// from the mutation response.
	resolved := a.resolveState(capabilityID, "")
	resolvedDigest, _ := nativeprotocol.StateDigest(resolved.State)
	expectedDigest, _ := nativeprotocol.StateDigest(capabilityState.State)
	if resolvedDigest != expectedDigest || !resolved.State.Tombstoned {
		t.Fatal("live canonical resolver did not reproduce Capability tombstone")
	}
	t.Logf("Phase5B localnet accepted: agent1=%s agent2=%s capability=%s checkpoint=%d reference=%s",
		agent1, agent2, capabilityID, resolved.Observation.FinalizedCheckpoint, resolved.Observation.Reference.TransactionHash)
}

// TestPhase5BEmptyReplicaResolution proves that a newly constructed protocol
// process with an empty bbolt database reconstructs current and historical
// registry state exclusively through the production read-only chain resolver.
func TestPhase5BEmptyReplicaResolution(t *testing.T) {
	baseURL := os.Getenv("TOS_PHASE5B_EMPTY_RPC_URL")
	if baseURL == "" {
		t.Skip("set TOS_PHASE5B_EMPTY_RPC_URL for empty-replica localnet acceptance")
	}
	a := &nativeAcceptance{t: t, token: requiredEnv(t, "TOS_PHASE5B_TOKEN"), runID: requiredEnv(t, "TOS_PHASE5B_RUN_ID"),
		client: atostosv1connect.NewNativeRegistryServiceClient(http.DefaultClient, baseURL)}
	agent1 := a.resolveState(requiredEnv(t, "TOS_PHASE5B_AGENT1_ID"), "")
	if agent1.State.Tombstoned || agent1.State.CurrentPolicyDigest == "" || agent1.State.Sequence < 2 {
		t.Fatal("empty replica did not reconstruct the rotated first Agent")
	}
	agent2 := a.resolveState(requiredEnv(t, "TOS_PHASE5B_AGENT2_ID"), "")
	if !agent2.State.Tombstoned || agent2.State.PendingRecovery.ExecuteAfterUnixSeconds != 0 {
		t.Fatal("empty replica did not reconstruct the recovered Agent tombstone")
	}
	capability := a.resolveState(requiredEnv(t, "TOS_PHASE5B_CAPABILITY_ID"), "")
	if !capability.State.Tombstoned || capability.State.OwnerAgentID != agent2.State.AgentID || len(capability.State.CapabilityVersions) != 2 ||
		!capability.State.CapabilityVersions[0].Revoked || capability.State.CapabilityVersions[1].Revoked {
		t.Fatal("empty replica did not reconstruct the transferred Capability tombstone")
	}
	t.Logf("empty replica reconstructed agent1=%s agent2=%s capability=%s checkpoint=%d",
		agent1.State.AgentID, agent2.State.AgentID, capability.State.CapabilityID, capability.Observation.FinalizedCheckpoint)
}

func acceptancePolicy(t *testing.T, suffix string, seed byte) nativeAcceptancePolicy {
	t.Helper()
	private := map[string]ed25519.PrivateKey{}
	key := func(id string, value byte, purposes ...string) nativeprotocol.ControllerKey {
		priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{value}, ed25519.SeedSize))
		private[id] = priv
		sort.Strings(purposes)
		return nativeprotocol.ControllerKey{KeyID: id, Algorithm: nativeprotocol.SignatureAlgorithm,
			PublicKeyBase64: base64.RawURLEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), Weight: 1, Purposes: purposes}
	}
	quoteID, receiptID, rootID := "quote-"+suffix, "receipt-"+suffix, "root-"+suffix
	policy := nativeprotocol.ControllerPolicy{Threshold: 1, RecoveryThreshold: 1,
		Controllers: []nativeprotocol.ControllerKey{
			key(quoteID, seed+1, "quote"), key(receiptID, seed+2, "receipt"),
			key(rootID, seed+3, "agent_control", "capability_control", "delegation", "recovery"),
		}, RecoveryKeyIDs: []string{rootID}, RecoveryTimelock: 2}
	sort.Slice(policy.Controllers, func(i, j int) bool { return policy.Controllers[i].KeyID < policy.Controllers[j].KeyID })
	cbor, digest, err := nativeprotocol.EncodeControllerPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	return nativeAcceptancePolicy{value: policy, cbor: cbor, digest: digest, private: private}
}

func (a *nativeAcceptance) registerAgent(policy nativeAcceptancePolicy, nonceByte byte) (string, nativeregistry.Result) {
	nonce := a.nonce(nonceByte)
	id, err := nativeprotocol.AgentID(nativeprotocol.AgentBootstrap{Version: nativeprotocol.Version,
		Network: a.network, ObjectNonceBase64: nonce, InitialControllerPolicy: policy.digest})
	if err != nil {
		a.t.Fatal(err)
	}
	a.t.Logf("registering agent=%s", id)
	result := a.submitAction(nil, nativeprotocol.ActionRegisterAgent, id, "", "", 1, 1, policy, nil,
		nativeprotocol.RegisterAgentPayload{ObjectNonceBase64: nonce, InitialPolicyDigest: policy.digest, InitialPolicyCBORBase64: policy.cbor}, 0)
	return id, result
}

func (a *nativeAcceptance) submitAction(previous *nativeprotocol.RegistryState, kind nativeprotocol.ActionKind,
	agentID, capabilityID, version string, generation, sequence uint64, policy nativeAcceptancePolicy,
	newOwner *nativeAcceptancePolicy, payload any, observedUnixSeconds uint64) nativeregistry.Result {
	return a.submit(a.buildSubmission(previous, kind, agentID, capabilityID, version, generation, sequence,
		policy, newOwner, payload, observedUnixSeconds))
}

func (a *nativeAcceptance) buildSubmission(previous *nativeprotocol.RegistryState, kind nativeprotocol.ActionKind,
	agentID, capabilityID, version string, generation, sequence uint64, policy nativeAcceptancePolicy,
	newOwner *nativeAcceptancePolicy, payload any, observedUnixSeconds uint64) nativeregistry.Submission {
	a.t.Helper()
	payloadCBOR, payloadDigest, err := nativeprotocol.EncodePayload(kind, payload)
	if err != nil {
		a.t.Fatal(err)
	}
	previousDigest := ""
	if previous != nil {
		previousDigest, err = nativeprotocol.StateDigest(*previous)
		if err != nil {
			a.t.Fatal(err)
		}
		a.t.Logf("building %s from predecessor=%s last_action=%s", kind, previousDigest, previous.LastActionDigest)
	}
	a.serial++
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: kind, Network: a.network,
		AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: version,
		Generation: generation, Sequence: sequence, PreviousStateDigest: previousDigest,
		PolicyDigest: policy.digest, PayloadDigest: payloadDigest, PayloadCBORBase64: payloadCBOR,
		NonceBase64: a.nonce(byte(0xd0 + a.serial))}
	expectedPolicy := policy.digest
	if kind == nativeprotocol.ActionRegisterAgent {
		expectedPolicy = ""
	}
	contract, err := a.locator.Locate(action)
	if err != nil {
		a.t.Fatal(err)
	}
	var newPolicy *nativeprotocol.ControllerPolicy
	if newOwner != nil {
		newPolicy = &newOwner.value
	}
	unsigned, err := nativeexecution.Build(previous, action, expectedPolicy, policy.value, newPolicy, observedUnixSeconds, contract)
	if err != nil {
		a.t.Fatalf("build %s: %v", kind, err)
	}
	authorityKey := policy.value.RecoveryKeyIDs[0]
	semantic, err := nativeprotocol.SignAction(policy.private[authorityKey], authorityKey, action)
	if err != nil {
		a.t.Fatal(err)
	}
	tvm, err := nativeexecution.Sign(policy.private[authorityKey], authorityKey, unsigned.Execution)
	if err != nil {
		a.t.Fatal(err)
	}
	unsigned.Execution.AuthoritySignatures = []nativeexecution.Signature{tvm}
	submission := nativeregistry.Submission{Version: nativeprotocol.Version, Action: action,
		AuthorityPolicyCBORBase64: policy.cbor, AuthoritySignatures: []nativeprotocol.Signature{semantic}, Execution: unsigned.Execution}
	if newOwner != nil {
		newKey := newOwner.value.RecoveryKeyIDs[0]
		newSemantic, _ := nativeprotocol.SignAction(newOwner.private[newKey], newKey, action)
		newTVM, _ := nativeexecution.Sign(newOwner.private[newKey], newKey, unsigned.Execution)
		submission.NewOwnerSignatures = []nativeprotocol.Signature{newSemantic}
		submission.Execution.NewOwnerSignatures = []nativeexecution.Signature{newTVM}
	}
	if err := nativeexecution.Validate(submission.Execution, submission.Action, contract); err != nil {
		a.t.Fatalf("locally validate %s execution: %v", kind, err)
	}
	return submission
}

func (a *nativeAcceptance) submit(submission nativeregistry.Submission) nativeregistry.Result {
	a.t.Helper()
	actionID, _ := nativeprotocol.ActionDigest(submission.Action)
	a.t.Logf("submitting %s action=%s anchor=%s", submission.Action.Kind, actionID, submission.Execution.ActionAnchorAddress)
	wire, err := nativeAcceptanceSubmissionToProto(submission)
	if err != nil {
		a.t.Fatal(err)
	}
	a.serial++
	requestTimeout := 2 * time.Minute
	if submission.Action.Kind == nativeprotocol.ActionRecoverAgent {
		requestTimeout = 5 * time.Minute
	}
	request := connect.NewRequest(&atostosv1.SubmitNativeRegistryActionRequest{Context: &atostosv1.RequestContext{
		RequestId: fmt.Sprintf("phase5b-submit-%s-%d", a.runID, a.serial), CallerId: "phase5b-acceptance",
		IdempotencyKey: fmt.Sprintf("phase5b-idempotency-%s-%d", a.runID, a.serial), DeadlineUnixMillis: time.Now().Add(requestTimeout).UnixMilli()}, Submission: wire})
	request.Header().Set("Authorization", "Bearer "+a.token)
	deadline := time.Now().Add(requestTimeout)
	var response *connect.Response[atostosv1.SubmitNativeRegistryActionResponse]
	for {
		response, err = a.client.SubmitNativeRegistryAction(context.Background(), request)
		retryable := err != nil && (connect.CodeOf(err) == connect.CodeUnavailable ||
			(submission.Action.Kind == nativeprotocol.ActionRecoverAgent && connect.CodeOf(err) == connect.CodeInvalidArgument &&
				strings.Contains(err.Error(), "recovery.execute_after_unix_seconds")))
		if err == nil || !retryable || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		a.t.Fatalf("submit %s: %v", submission.Action.Kind, err)
	}
	result, err := nativeResultFromProto(response.Msg.Result)
	if err != nil {
		a.t.Fatal(err)
	}
	boc, err := base64.RawURLEncoding.DecodeString(submission.Execution.ActionCellBOCBase64)
	if err != nil {
		a.t.Fatalf("decode submitted %s BOC: %v", submission.Action.Kind, err)
	}
	root, err := cell.FromBOC(boc)
	if err != nil {
		a.t.Fatalf("parse submitted %s BOC: %v", submission.Action.Kind, err)
	}
	decoded, err := nativeexecution.DecodeActionCell(root)
	if err != nil {
		a.t.Fatalf("decode submitted %s execution: %v", submission.Action.Kind, err)
	}
	if !reflect.DeepEqual(result.State, decoded.Next) {
		a.t.Fatalf("%s public result changed canonical state\nwant: %#v\n got: %#v", submission.Action.Kind, decoded.Next, result.State)
	}
	a.t.Logf("received %s state policy_bytes=%d agent_nonce=%d capability_nonce=%d", submission.Action.Kind, len(result.State.CurrentPolicyCBORBase64), len(result.State.AgentNonceBase64), len(result.State.CapabilityNonceBase64))
	// Exact semantic replay through the full public path must be read-only.
	replay := connect.NewRequest(request.Msg)
	replay.Header().Set("Authorization", "Bearer "+a.token)
	replayed, err := a.client.SubmitNativeRegistryAction(context.Background(), replay)
	if err != nil || replayed == nil || replayed.Msg.Created || replayed.Msg.Result.ActionId != response.Msg.Result.ActionId {
		created := false
		if replayed != nil {
			created = replayed.Msg.GetCreated()
		}
		a.t.Fatalf("non-idempotent %s replay: created=%v err=%v", submission.Action.Kind, created, err)
	}
	return result
}

func (a *nativeAcceptance) expectRejected(submission nativeregistry.Submission, label string) {
	a.t.Helper()
	wire, err := nativeAcceptanceSubmissionToProto(submission)
	if err != nil {
		a.t.Fatal(err)
	}
	a.serial++
	request := connect.NewRequest(&atostosv1.SubmitNativeRegistryActionRequest{Context: &atostosv1.RequestContext{
		RequestId: fmt.Sprintf("phase5b-reject-%s-%d", a.runID, a.serial), CallerId: "phase5b-acceptance",
		IdempotencyKey: fmt.Sprintf("phase5b-reject-key-%s-%d", a.runID, a.serial), DeadlineUnixMillis: time.Now().Add(30 * time.Second).UnixMilli()}, Submission: wire})
	request.Header().Set("Authorization", "Bearer "+a.token)
	if _, err := a.client.SubmitNativeRegistryAction(context.Background(), request); err == nil {
		a.t.Fatalf("%s was accepted", label)
	}
}

func (a *nativeAcceptance) resolveState(objectID, expectedDigest string) nativeregistry.Result {
	a.t.Helper()
	a.serial++
	request := &atostosv1.ResolveNativeRegistryStateRequest{Context: &atostosv1.RequestContext{
		RequestId: fmt.Sprintf("phase5b-resolve-%s-%d", a.runID, a.serial), CallerId: "phase5b-acceptance",
		DeadlineUnixMillis: time.Now().Add(30 * time.Second).UnixMilli()}, ExpectedStateDigest: expectedDigest}
	if len(objectID) > 6 && objectID[:6] == "agent_" {
		request.AgentId = objectID
	} else {
		request.CapabilityId = objectID
	}
	wire := connect.NewRequest(request)
	wire.Header().Set("Authorization", "Bearer "+a.token)
	response, err := a.client.ResolveNativeRegistryState(context.Background(), wire)
	found := response != nil && response.Msg != nil && response.Msg.Found
	if err != nil || !found {
		a.t.Fatalf("resolve state %s: found=%v err=%v", objectID, found, err)
	}
	result, err := protoAs[nativeregistry.Result](response.Msg.Result)
	if err != nil {
		a.t.Fatal(err)
	}
	return result
}

func (a *nativeAcceptance) assertOldKeyRejected(state nativeprotocol.RegistryState, live, old nativeAcceptancePolicy,
	kind nativeprotocol.ActionKind, payload any) {
	a.t.Helper()
	submission := a.buildSubmission(&state, kind, state.AgentID, "", "", state.Generation, state.Sequence+1, live, nil, payload, 0)
	oldKey := old.value.RecoveryKeyIDs[0]
	submission.AuthoritySignatures[0], _ = nativeprotocol.SignAction(old.private[oldKey], oldKey, submission.Action)
	submission.Execution.AuthoritySignatures[0], _ = nativeexecution.Sign(old.private[oldKey], oldKey, submission.Execution)
	a.expectRejected(submission, "former Agent controller")
}

func (a *nativeAcceptance) assertOldCapabilityKeyRejected(state nativeprotocol.RegistryState, currentOwner string,
	live, old nativeAcceptancePolicy) {
	a.t.Helper()
	payload := nativeprotocol.CapabilityVersionPayload{OwnerAgentID: currentOwner,
		Manifest:          nativeprotocol.ManifestReference{Digest: acceptanceDigest(0xe1), MediaType: "application/vnd.atos.native-capability+json", SizeBytes: 64, Locations: []string{"https://example.invalid/native/manifest-v2"}},
		Endpoints:         []nativeprotocol.EndpointReference{{Transport: "a2a", EndpointDigest: acceptanceDigest(0xe2), RecipientKeyID: "receipt-b"}},
		QuoteSignerKeyIDs: []string{"quote-b"}, ReceiptSignerKeyIDs: []string{"receipt-b"}, ValidFromCheckpoint: 1, ValidUntilCheckpoint: 100_000}
	submission := a.buildSubmission(&state, nativeprotocol.ActionUpdateCapability, currentOwner, state.CapabilityID, "3.0.0",
		state.Generation, state.Sequence+1, live, nil, payload, 0)
	oldKey := old.value.RecoveryKeyIDs[0]
	submission.AuthoritySignatures[0], _ = nativeprotocol.SignAction(old.private[oldKey], oldKey, submission.Action)
	submission.Execution.AuthoritySignatures[0], _ = nativeexecution.Sign(old.private[oldKey], oldKey, submission.Execution)
	a.expectRejected(submission, "former Capability owner")
}

func (a *nativeAcceptance) assertCapabilityTombstone(state nativeprotocol.RegistryState, owner string, policy nativeAcceptancePolicy) {
	a.t.Helper()
	payload := nativeprotocol.CapabilityVersionPayload{OwnerAgentID: owner,
		Manifest:          nativeprotocol.ManifestReference{Digest: acceptanceDigest(0xf1), MediaType: "application/vnd.atos.native-capability+json", SizeBytes: 64, Locations: []string{"https://example.invalid/native/after-tombstone"}},
		Endpoints:         []nativeprotocol.EndpointReference{{Transport: "a2a", EndpointDigest: acceptanceDigest(0xf2), RecipientKeyID: "receipt-b2"}},
		QuoteSignerKeyIDs: []string{"quote-b2"}, ReceiptSignerKeyIDs: []string{"receipt-b2"}, ValidFromCheckpoint: 1, ValidUntilCheckpoint: 100_000}
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: nativeprotocol.ActionUpdateCapability,
		Network: a.network, AgentID: owner, CapabilityID: state.CapabilityID, CapabilityVersion: "3.0.0",
		Generation: state.Generation, Sequence: state.Sequence + 1, PolicyDigest: policy.digest, NonceBase64: a.nonce(0xf3)}
	action.PreviousStateDigest, _ = nativeprotocol.StateDigest(state)
	action.PayloadCBORBase64, action.PayloadDigest, _ = nativeprotocol.EncodePayload(action.Kind, payload)
	// Tombstone rejection occurs before any executable next state can exist;
	// reuse of a prior execution is deliberately malformed and must not reach
	// the publisher.
	submission := nativeregistry.Submission{Version: nativeprotocol.Version, Action: action,
		AuthorityPolicyCBORBase64: policy.cbor, Execution: nativeexecution.Execution{Version: nativeexecution.Version}}
	a.expectRejected(submission, "Capability tombstone resurrection")
}

func (a *nativeAcceptance) assertAgentTombstone(state nativeprotocol.RegistryState, policy nativeAcceptancePolicy) {
	a.t.Helper()
	payload := nativeprotocol.UpdatePolicyPayload{NewPolicyDigest: policy.digest, NewPolicyCBORBase64: policy.cbor}
	action := nativeprotocol.RegistryAction{Version: nativeprotocol.Version, Kind: nativeprotocol.ActionUpdateAgentPolicy,
		Network: a.network, AgentID: state.AgentID, Generation: state.Generation, Sequence: state.Sequence + 1,
		PolicyDigest: policy.digest, NonceBase64: a.nonce(0xf4)}
	action.PreviousStateDigest, _ = nativeprotocol.StateDigest(state)
	action.PayloadCBORBase64, action.PayloadDigest, _ = nativeprotocol.EncodePayload(action.Kind, payload)
	a.expectRejected(nativeregistry.Submission{Version: nativeprotocol.Version, Action: action,
		AuthorityPolicyCBORBase64: policy.cbor, Execution: nativeexecution.Execution{Version: nativeexecution.Version}}, "Agent tombstone resurrection")
}

func (a *nativeAcceptance) nonce(value byte) string {
	digest := sha256.Sum256(append([]byte("tos.phase5b.localnet-acceptance.v1\x00"+a.runID+"\x00"), value))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func acceptanceDigest(value byte) string {
	return fmt.Sprintf("sha256:%x", bytes.Repeat([]byte{value}, 32))
}

func requiredEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is required", key)
	}
	return value
}

func nativeAcceptanceSubmissionToProto(value nativeregistry.Submission) (*atostosv1.NativeRegistrySubmissionV1, error) {
	action, err := nativeToProto[atostosv1.NativeRegistryActionV1](value.Action)
	if err != nil {
		return nil, err
	}
	semantic := func(values []nativeprotocol.Signature) *atostosv1.NativeAuthorizationSetV1 {
		result := &atostosv1.NativeAuthorizationSetV1{Signatures: make([]*atostosv1.NativeSemanticSignatureV1, len(values))}
		for index, signature := range values {
			result.Signatures[index] = &atostosv1.NativeSemanticSignatureV1{Version: signature.Version,
				Algorithm: signature.Algorithm, KeyId: signature.KeyID, SignatureBase64Url: signature.SignatureBase64}
		}
		return result
	}
	tvm := func(values []nativeexecution.Signature) []*atostosv1.NativeRegistryTVMSignatureV1 {
		result := make([]*atostosv1.NativeRegistryTVMSignatureV1, len(values))
		for index, signature := range values {
			result[index] = &atostosv1.NativeRegistryTVMSignatureV1{Version: signature.Version,
				Algorithm: signature.Algorithm, KeyId: signature.KeyID, SignatureBase64Url: signature.SignatureBase64}
		}
		return result
	}
	execution := value.Execution
	return &atostosv1.NativeRegistrySubmissionV1{Version: value.Version, Action: action,
		AuthorityPolicyCborBase64Url: value.AuthorityPolicyCBORBase64,
		AuthoritySignatures:          semantic(value.AuthoritySignatures),
		NewOwnerSignatures:           semantic(value.NewOwnerSignatures),
		Execution: &atostosv1.NativeRegistryTVMExecutionV1{Version: execution.Version,
			ContractAddress: execution.ContractAddress, ActionAnchorAddress: execution.ActionAnchorAddress,
			ContractCodeHash: execution.ContractCodeHash, PortableActionDigest: execution.PortableActionDigest,
			ActionCellBocBase64Url: execution.ActionCellBOCBase64, ActionCellHash: execution.ActionCellHash,
			PreviousTvmStateHash: execution.PreviousTVMStateHash, ExpectedTvmStateHash: execution.ExpectedTVMStateHash,
			ExpectedPortableStateDigest: execution.ExpectedPortableStateDigest,
			AuthoritySignatures:         tvm(execution.AuthoritySignatures), NewOwnerSignatures: tvm(execution.NewOwnerSignatures)}}, nil
}
