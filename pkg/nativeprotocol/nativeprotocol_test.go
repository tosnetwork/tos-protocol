package nativeprotocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"
)

type fixtureValues struct {
	network                             NetworkDomain
	policy                              ControllerPolicy
	policyDigest, agentID, capabilityID string
	action                              RegistryAction
	privateKey                          ed25519.PrivateKey
}

func fixture(t *testing.T) fixtureValues {
	t.Helper()
	network := NetworkDomain{NetworkID: "tos-testnet", GenesisRootHash: "sha256:" + strings.Repeat("11", 32), GenesisFileHash: "sha256:" + strings.Repeat("22", 32)}
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	policy := ControllerPolicy{Threshold: 1, RecoveryThreshold: 1, Controllers: []ControllerKey{{KeyID: "controller-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "capability_control", "recovery"}}}, RecoveryKeyIDs: []string{"controller-1"}, RecoveryTimelock: 86400}
	policyDigest, err := ControllerPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, 32)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	agentID, err := AgentID(AgentBootstrap{Version: Version, Network: network, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), InitialControllerPolicy: policyDigest})
	if err != nil {
		t.Fatal(err)
	}
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	capabilityID, err := CapabilityID(CapabilityBootstrap{Version: Version, Network: network, OwnerAgentID: agentID, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		t.Fatal(err)
	}
	payload := CapabilityVersionPayload{OwnerAgentID: agentID, Manifest: ManifestReference{Digest: "sha256:" + strings.Repeat("33", 32), MediaType: "application/vnd.atos.native-capability+json", SizeBytes: 1234, Locations: []string{"https://provider.example/manifests/v1"}}, Endpoints: []EndpointReference{{Transport: "https", EndpointDigest: "sha256:" + strings.Repeat("44", 32), RecipientKeyID: "recipient-1"}}, QuoteSignerKeyIDs: []string{"quote-1"}, ReceiptSignerKeyIDs: []string{"receipt-1"}, ValidFromCheckpoint: 10, ValidUntilCheckpoint: 1000}
	payloadCBOR, payloadDigest, err := EncodePayload(ActionRegisterCapability, payload)
	if err != nil {
		t.Fatal(err)
	}
	actionNonce := make([]byte, 32)
	for i := range actionNonce {
		actionNonce[i] = byte(0x70 + i)
	}
	action := RegistryAction{Version: Version, Kind: ActionRegisterCapability, Network: network, AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, PolicyDigest: policyDigest, PayloadDigest: payloadDigest, PayloadCBORBase64: payloadCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(actionNonce)}
	return fixtureValues{network, policy, policyDigest, agentID, capabilityID, action, privateKey}
}

func TestNormativeVectors(t *testing.T) {
	f := fixture(t)
	actionDigest, err := ActionDigest(f.action)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalAction(f.action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignAction(f.privateKey, "controller-1", f.action)
	if err != nil {
		t.Fatal(err)
	}
	event := RegistryEvent{Version: Version, Kind: f.action.Kind, Network: f.network, ActionDigest: actionDigest, AgentID: f.agentID, CapabilityID: f.capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, StateDigest: "sha256:" + strings.Repeat("55", 32)}
	eventDigest, err := EventDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: eventDigest, Reference: ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("66", 32), LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("77", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), EventIndex: 1}, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: 1800000000, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	observationDigest, err := ObservationDigest(observation)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{"policy": f.policyDigest, "agent": f.agentID, "capability": f.capabilityID, "action": actionDigest, "canonical": base64.StdEncoding.EncodeToString(canonical), "signature": signature.SignatureBase64, "event": eventDigest, "observation": observationDigest, "payload_digest": f.action.PayloadDigest, "payload_cbor": f.action.PayloadCBORBase64}
	want := map[string]string{
		"policy":         "sha256:bd9edfc6aacd6f25665dd5c8b6822cfe0a046e42e0af91096bcf5d97c0782655",
		"agent":          "agent_87681831573fb7507d50fe4a76d1e99b8a68236dc69e5e31b8aed771ff279a1e",
		"capability":     "cap_426469858712a8e359f37a62901d05215bd31ced5e8885f62236db05b990ff21",
		"action":         "sha256:4ad143484c2e588d4cbfef10ee3d731fab06f2341506e5a8f084982a5dcf9c5f",
		"signature":      "ZkiZ9cMUzYB2rJAORxcg-NREhahuKZQyvZMaXJtt4po9F6hTmcFbP9NHGWM-H7aiozs_WkSe4R-w_SgCaBIxDQ",
		"event":          "sha256:ddef7e540442f96437816782fafd82482ed84178c40b8d23069813ec89d5bd60",
		"observation":    "sha256:80476336b5fe26317f16b7849c928974115c4ee23dcb1099fe3160335a14e92d",
		"payload_digest": "sha256:ab198cf69541951d6407e23701bf26085b4b7bf0cad004bd1a552fe6b4e4afe3",
		"payload_cbor":   "p2htYW5pZmVzdKRmZGlnZXN0eEdzaGEyNTY6MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM2lsb2NhdGlvbnOBeCVodHRwczovL3Byb3ZpZGVyLmV4YW1wbGUvbWFuaWZlc3RzL3Yxam1lZGlhX3R5cGV4K2FwcGxpY2F0aW9uL3ZuZC5hdG9zLm5hdGl2ZS1jYXBhYmlsaXR5K2pzb25qc2l6ZV9ieXRlcxkE0mllbmRwb2ludHOBo2l0cmFuc3BvcnRlaHR0cHNvZW5kcG9pbnRfZGlnZXN0eEdzaGEyNTY6NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NHByZWNpcGllbnRfa2V5X2lka3JlY2lwaWVudC0xbm93bmVyX2FnZW50X2lkeEZhZ2VudF84NzY4MTgzMTU3M2ZiNzUwN2Q1MGZlNGE3NmQxZTk5YjhhNjgyMzZkYzY5ZTVlMzFiOGFlZDc3MWZmMjc5YTFldHF1b3RlX3NpZ25lcl9rZXlfaWRzgWdxdW90ZS0xdXZhbGlkX2Zyb21fY2hlY2twb2ludAp2cmVjZWlwdF9zaWduZXJfa2V5X2lkc4FpcmVjZWlwdC0xdnZhbGlkX3VudGlsX2NoZWNrcG9pbnQZA-g",
		"canonical":      "rWRraW5kc3JlZ2lzdGVyX2NhcGFiaWxpdHlnbmV0d29ya6NqbmV0d29ya19pZGt0b3MtdGVzdG5ldHFnZW5lc2lzX2ZpbGVfaGFzaHhHc2hhMjU2OjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjJxZ2VuZXNpc19yb290X2hhc2h4R3NoYTI1NjoxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExZ3ZlcnNpb252dG9zX25hdGl2ZV9yZWdpc3RyeV92MWhhZ2VudF9pZHhGYWdlbnRfODc2ODE4MzE1NzNmYjc1MDdkNTBmZTRhNzZkMWU5OWI4YTY4MjM2ZGM2OWU1ZTMxYjhhZWQ3NzFmZjI3OWExZWhzZXF1ZW5jZQFqZ2VuZXJhdGlvbgFtY2FwYWJpbGl0eV9pZHhEY2FwXzQyNjQ2OTg1ODcxMmE4ZTM1OWYzN2E2MjkwMWQwNTIxNWJkMzFjZWQ1ZTg4ODVmNjIyMzZkYjA1Yjk5MGZmMjFtcG9saWN5X2RpZ2VzdHhHc2hhMjU2OmJkOWVkZmM2YWFjZDZmMjU2NjVkZDVjOGI2ODIyY2ZlMGEwNDZlNDJlMGFmOTEwOTZiY2Y1ZDk3YzA3ODI2NTVucGF5bG9hZF9kaWdlc3R4R3NoYTI1NjphYjE5OGNmNjk1NDE5NTFkNjQwN2UyMzcwMWJmMjYwODViNGI3YmYwY2FkMDA0YmQxYTU1MmZlNmI0ZTRhZmUzb25vbmNlX2Jhc2U2NHVybHgrY0hGeWMzUjFkbmQ0ZVhwN2ZIMS1mNENCZ29PRWhZYUhpSW1LaTR5TmpvOHJjYXBhYmlsaXR5X3ZlcnNpb25lMS4yLjN1cHJldmlvdXNfc3RhdGVfZGlnZXN0YHZwYXlsb2FkX2Nib3JfYmFzZTY0dXJseQLncDJodFlXNXBabVZ6ZEtSbVpHbG5aWE4wZUVkemFHRXlOVFk2TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TTJsc2IyTmhkR2x2Ym5PQmVDVm9kSFJ3Y3pvdkwzQnliM1pwWkdWeUxtVjRZVzF3YkdVdmJXRnVhV1psYzNSekwzWXhhbTFsWkdsaFgzUjVjR1Y0SzJGd2NHeHBZMkYwYVc5dUwzWnVaQzVoZEc5ekxtNWhkR2wyWlMxallYQmhZbWxzYVhSNUsycHpiMjVxYzJsNlpWOWllWFJsY3hrRTBtbGxibVJ3YjJsdWRIT0JvMmwwY21GdWMzQnZjblJsYUhSMGNITnZaVzVrY0c5cGJuUmZaR2xuWlhOMGVFZHphR0V5TlRZNk5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5IQnlaV05wY0dsbGJuUmZhMlY1WDJsa2EzSmxZMmx3YVdWdWRDMHhibTkzYm1WeVgyRm5aVzUwWDJsa2VFWmhaMlZ1ZEY4NE56WTRNVGd6TVRVM00yWmlOelV3TjJRMU1HWmxOR0UzTm1ReFpUazVZamhoTmpneU16WmtZelk1WlRWbE16RmlPR0ZsWkRjM01XWm1NamM1WVRGbGRIRjFiM1JsWDNOcFoyNWxjbDlyWlhsZmFXUnpnV2R4ZFc5MFpTMHhkWFpoYkdsa1gyWnliMjFmWTJobFkydHdiMmx1ZEFwMmNtVmpaV2x3ZEY5emFXZHVaWEpmYTJWNVgybGtjNEZwY21WalpXbHdkQzB4ZG5aaGJHbGtYM1Z1ZEdsc1gyTm9aV05yY0c5cGJuUVpBLWc=",
	}
	for key, value := range got {
		if value != want[key] {
			t.Fatalf("%s=%s want %s", key, value, want[key])
		}
	}
	if err := VerifyAuthorization(f.action, f.policy, []Signature{signature}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateEventForAction(f.action, event); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureBindsVersionAlgorithmAndKeyID(t *testing.T) {
	f := fixture(t)
	signature, _ := SignAction(f.privateKey, "controller-1", f.action)
	for name, mutate := range map[string]func(*Signature){"version": func(s *Signature) { s.Version = "v2" }, "algorithm": func(s *Signature) { s.Algorithm = "other" }, "key_id": func(s *Signature) { s.KeyID = "settlement-key" }} {
		t.Run(name, func(t *testing.T) {
			changed := signature
			mutate(&changed)
			if err := VerifyAction(f.privateKey.Public().(ed25519.PublicKey), f.action, changed); err == nil {
				t.Fatal("signature metadata substitution accepted")
			}
		})
	}
}

func TestPolicyRejectsDuplicatePhysicalKeyAndWeight(t *testing.T) {
	f := fixture(t)
	duplicate := f.policy.Controllers[0]
	duplicate.KeyID = "controller-2"
	duplicate.Purposes = []string{"settlement"}
	f.policy.Controllers = append(f.policy.Controllers, duplicate)
	if err := ValidateControllerPolicy(f.policy); err == nil {
		t.Fatal("duplicate public key accepted")
	}
}

func TestWeightedThresholdUsesUniqueSortedSignatures(t *testing.T) {
	f := fixture(t)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(0x80 + i)
	}
	second := ed25519.NewKeyFromSeed(seed)
	f.policy.Threshold = 2
	f.policy.Controllers = append(f.policy.Controllers, ControllerKey{KeyID: "controller-2", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(second.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"capability_control"}})
	firstSignature, _ := SignAction(f.privateKey, "controller-1", f.action)
	secondSignature, _ := SignAction(second, "controller-2", f.action)
	if err := VerifyAuthorization(f.action, f.policy, []Signature{firstSignature}); ErrorCodeOf(err) != CodePolicyUnauthorized {
		t.Fatalf("threshold err=%v", err)
	}
	if err := VerifyAuthorization(f.action, f.policy, []Signature{firstSignature, secondSignature}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(f.action, f.policy, []Signature{secondSignature, firstSignature}); err == nil {
		t.Fatal("unsorted signature set accepted")
	}
	if err := VerifyAuthorization(f.action, f.policy, []Signature{firstSignature, firstSignature}); err == nil {
		t.Fatal("duplicate signature weight accepted")
	}
}

func TestStrictEventTupleAndSeparateFinalityObservation(t *testing.T) {
	f := fixture(t)
	actionDigest, _ := ActionDigest(f.action)
	base := RegistryEvent{Version: Version, Kind: ActionRegisterAgent, Network: f.network, ActionDigest: actionDigest, AgentID: f.agentID, Generation: 1, Sequence: 1, StateDigest: "sha256:" + strings.Repeat("55", 32)}
	bad := base
	bad.CapabilityVersion = "1.2.3"
	if _, err := EventDigest(bad); err == nil {
		t.Fatal("Agent event with Capability version accepted")
	}
	bad = base
	bad.CapabilityID = "garbage"
	if _, err := EventDigest(bad); err == nil {
		t.Fatal("Agent event with Capability ID accepted")
	}
	bad = base
	bad.Kind = ActionRevokeCapability
	bad.CapabilityID = f.capabilityID
	bad.CapabilityVersion = "01.not-semver"
	if _, err := EventDigest(bad); err == nil {
		t.Fatal("invalid revoked Capability version accepted")
	}
	eventDigest, _ := EventDigest(base)
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: eventDigest, Reference: ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("66", 32), LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("77", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), EventIndex: 1}, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: 1800000000, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	if _, err := ObservationDigest(observation); err != nil {
		t.Fatal(err)
	}
	observation.Reference.TransactionHash = ""
	if _, err := ObservationDigest(observation); err == nil {
		t.Fatal("observation without transaction identity accepted")
	}
}

func TestRecoveryGenerationAndCanonicalTime(t *testing.T) {
	f := fixture(t)
	previous := RegistryEvent{Version: Version, Kind: ActionUpdateAgentPolicy, Network: f.network, ActionDigest: "sha256:" + strings.Repeat("11", 32), AgentID: f.agentID, Generation: 2, Sequence: 9, PreviousStateDigest: "sha256:" + strings.Repeat("22", 32), StateDigest: "sha256:" + strings.Repeat("33", 32)}
	payload := RecoverAgentPayload{NewPolicyDigest: f.policyDigest, InitiationActionDigest: "sha256:" + strings.Repeat("44", 32), InitiationReference: ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("55", 32), LogicalTime: 12, TransactionHash: "sha256:" + strings.Repeat("66", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32)}, ExecuteAfterUnixSeconds: 200}
	encoded, digest, err := EncodePayload(ActionRecoverAgent, payload)
	if err != nil {
		t.Fatal(err)
	}
	action := RegistryAction{Version: Version, Kind: ActionRecoverAgent, Network: f.network, AgentID: f.agentID, Generation: 3, Sequence: 1, PreviousStateDigest: previous.StateDigest, PolicyDigest: f.policyDigest, PayloadDigest: digest, PayloadCBORBase64: encoded, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzero(32))}
	if err := ValidateTransition(&previous, action, 199); ErrorCodeOf(err) != CodeTimelockPending {
		t.Fatalf("early recovery err=%v", err)
	}
	if err := ValidateTransition(&previous, action, 200); err != nil {
		t.Fatal(err)
	}
	action.Generation = 2
	if err := ValidateTransition(&previous, action, 200); err == nil {
		t.Fatal("recovery without generation increment accepted")
	}
}

func TestRecoveryBindsFinalizedInitiationAndOldPolicyTimelock(t *testing.T) {
	f := fixture(t)
	previous := RegistryEvent{Version: Version, Kind: ActionUpdateAgentPolicy, Network: f.network, ActionDigest: "sha256:" + strings.Repeat("11", 32), AgentID: f.agentID, Generation: 2, Sequence: 9, PreviousStateDigest: "sha256:" + strings.Repeat("22", 32), StateDigest: "sha256:" + strings.Repeat("33", 32)}
	reference := ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("55", 32), LogicalTime: 12, TransactionHash: "sha256:" + strings.Repeat("66", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32)}
	blockTime := uint64(1_800_000_000)
	executeAfter := blockTime + f.policy.RecoveryTimelock
	initCBOR, initPayloadDigest, _ := EncodePayload(ActionInitiateRecovery, InitiateRecoveryPayload{NewPolicyDigest: f.policyDigest, ExecuteAfterUnixSeconds: executeAfter})
	initiation := RegistryAction{Version: Version, Kind: ActionInitiateRecovery, Network: f.network, AgentID: f.agentID, Generation: 2, Sequence: 10, PreviousStateDigest: previous.StateDigest, PolicyDigest: f.policyDigest, PayloadDigest: initPayloadDigest, PayloadCBORBase64: initCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzero(32))}
	initDigest, _ := ActionDigest(initiation)
	initiationEvent := RegistryEvent{Version: Version, Kind: initiation.Kind, Network: f.network, ActionDigest: initDigest, AgentID: f.agentID, Generation: 2, Sequence: 10, PreviousStateDigest: previous.StateDigest, StateDigest: "sha256:" + strings.Repeat("88", 32)}
	initEventDigest, _ := EventDigest(initiationEvent)
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: initEventDigest, Reference: reference, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: blockTime, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	recoveryCBOR, recoveryDigest, _ := EncodePayload(ActionRecoverAgent, RecoverAgentPayload{NewPolicyDigest: f.policyDigest, InitiationActionDigest: initDigest, InitiationReference: reference, ExecuteAfterUnixSeconds: executeAfter})
	recovery := RegistryAction{Version: Version, Kind: ActionRecoverAgent, Network: f.network, AgentID: f.agentID, Generation: 3, Sequence: 1, PreviousStateDigest: previous.StateDigest, PolicyDigest: f.policyDigest, PayloadDigest: recoveryDigest, PayloadCBORBase64: recoveryCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzero(32))}
	if err := ValidateRecoveryTransition(previous, recovery, initiation, initiationEvent, observation, f.policy, executeAfter); err != nil {
		t.Fatal(err)
	}
	changed := observation
	changed.Reference.LogicalTime++
	if err := ValidateRecoveryTransition(previous, recovery, initiation, initiationEvent, changed, f.policy, executeAfter); err == nil {
		t.Fatal("different initiation reference accepted")
	}
}

func TestDelegationUsesFinalizedCheckpointIntervalAndStaleness(t *testing.T) {
	payload := DelegationPayload{DelegateKeyID: "delegate-1", Purposes: []string{"invoke"}, Resources: []string{"atos://capability/example"}, ValidFromCheckpoint: 10, ValidUntilCheckpoint: 20, MaxStalenessCheckpoints: 3}
	if err := ValidateDelegationAt(payload, 10, 13); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDelegationAt(payload, 20, 20); ErrorCodeOf(err) != CodePolicyUnauthorized {
		t.Fatalf("upper bound err=%v", err)
	}
	if err := ValidateDelegationAt(payload, 12, 16); ErrorCodeOf(err) != CodeStaleAuthority {
		t.Fatalf("stale err=%v", err)
	}
}

func TestIdentifierAndURIAliasesFail(t *testing.T) {
	f := fixture(t)
	uri, _ := AgentURI(f.agentID)
	kind, id, version, err := ParseURI(uri)
	if err != nil || kind != "agent" || id != f.agentID || version != "" {
		t.Fatal("canonical URI failed")
	}
	for _, value := range []string{"ATOS://agent/" + f.agentID, "atos://agent/" + strings.ToUpper(f.agentID), "atos://agent/" + f.agentID + "/", "atos://capability/" + f.capabilityID + "/versions/01.2.3", "atos://capability/" + f.capabilityID + "/versions/1.2.3-01"} {
		if _, _, _, err := ParseURI(value); err == nil {
			t.Fatalf("alias accepted: %s", value)
		}
	}
}
func makeNonzero(size int) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = byte(i + 1)
	}
	return value
}
