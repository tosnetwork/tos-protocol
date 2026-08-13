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
	policyCBOR                          string
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
	quoteSeed := make([]byte, 32)
	receiptSeed := make([]byte, 32)
	for i := range quoteSeed {
		quoteSeed[i] = byte(0x41 + i)
		receiptSeed[i] = byte(0x81 + i)
	}
	quoteKey := ed25519.NewKeyFromSeed(quoteSeed).Public().(ed25519.PublicKey)
	receiptKey := ed25519.NewKeyFromSeed(receiptSeed).Public().(ed25519.PublicKey)
	policy := ControllerPolicy{Threshold: 1, RecoveryThreshold: 1, Controllers: []ControllerKey{
		{KeyID: "controller-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "capability_control", "recovery"}},
		{KeyID: "quote-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(quoteKey), Weight: 1, Purposes: []string{"quote"}},
		{KeyID: "receipt-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(receiptKey), Weight: 1, Purposes: []string{"receipt"}},
	}, RecoveryKeyIDs: []string{"controller-1"}, RecoveryTimelock: 86400}
	policyCBOR, policyDigest, err := EncodeControllerPolicy(policy)
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
	registration := RegisterCapabilityPayload{ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(nonce), Version: payload}
	payloadCBOR, payloadDigest, err := EncodePayload(ActionRegisterCapability, registration)
	if err != nil {
		t.Fatal(err)
	}
	actionNonce := make([]byte, 32)
	for i := range actionNonce {
		actionNonce[i] = byte(0x70 + i)
	}
	action := RegistryAction{Version: Version, Kind: ActionRegisterCapability, Network: network, AgentID: agentID, CapabilityID: capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, PolicyDigest: policyDigest, PayloadDigest: payloadDigest, PayloadCBORBase64: payloadCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(actionNonce)}
	return fixtureValues{network, policy, policyCBOR, policyDigest, agentID, capabilityID, action, privateKey}
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
	state, err := DeriveNextState(nil, f.action, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, err := StateDigest(state)
	if err != nil {
		t.Fatal(err)
	}
	event := RegistryEvent{Version: Version, Kind: f.action.Kind, Network: f.network, ActionDigest: actionDigest, AgentID: f.agentID, CapabilityID: f.capabilityID, CapabilityVersion: "1.2.3", Generation: 1, Sequence: 1, StateDigest: stateDigest}
	eventDigest, err := EventDigest(event)
	if err != nil {
		t.Fatal(err)
	}
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: eventDigest, Reference: ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("66", 32), LogicalTime: 42, TransactionHash: "sha256:" + strings.Repeat("77", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("88", 32), EventIndex: 1}, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: 1800000000, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	observationDigest, err := ObservationDigest(observation)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{"policy": f.policyDigest, "agent": f.agentID, "capability": f.capabilityID, "action": actionDigest, "canonical": base64.StdEncoding.EncodeToString(canonical), "signature": signature.SignatureBase64, "event": eventDigest, "state": stateDigest, "observation": observationDigest, "payload_digest": f.action.PayloadDigest, "payload_cbor": f.action.PayloadCBORBase64}
	want := map[string]string{
		"policy":         "sha256:00d58d79a585ae06876df7ea62cec5f871dc885b23c56d4ede3cdd1d0aabc772",
		"agent":          "agent_8e96ff0c392ce24384900f835061e049e5af0a3c855250ff4b094775863ee764",
		"capability":     "cap_ae5544f5e0be8dda14c366ec1da68f0870128afecc5485ebbce69a96f6446637",
		"action":         "sha256:220a7cb98dc0edb4850f5f24c767218ed02062ad96279568f965b8236ab6e128",
		"signature":      "kL-yp8rPod7hzi6krrLDJgZZJ4zC_kAqVEzvn4wFtxVn0Vwl3UE9jQ5_RZXkE60XwoBNZ_gPZt-oYmFwOQcNBg",
		"event":          "sha256:cf37b77cccb01dc00c41d5a85364f7a6a9340e04c5bbf8333400c9e7fb1d3e08",
		"state":          "sha256:cbb35e8819bb020fd5bfd0225cea66972bd730a644d9740295f561b0626bccd6",
		"observation":    "sha256:e03f4d16d00658a362596a2a807ab21c325ad12e3c664533254c619685fee2b5",
		"payload_digest": "sha256:07fd9ef49268b87e3bd556fe14d603b44cc6336e300081911507125d7b694866",
		"payload_cbor":   "omd2ZXJzaW9up2htYW5pZmVzdKRmZGlnZXN0eEdzaGEyNTY6MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM2lsb2NhdGlvbnOBeCVodHRwczovL3Byb3ZpZGVyLmV4YW1wbGUvbWFuaWZlc3RzL3Yxam1lZGlhX3R5cGV4K2FwcGxpY2F0aW9uL3ZuZC5hdG9zLm5hdGl2ZS1jYXBhYmlsaXR5K2pzb25qc2l6ZV9ieXRlcxkE0mllbmRwb2ludHOBo2l0cmFuc3BvcnRlaHR0cHNvZW5kcG9pbnRfZGlnZXN0eEdzaGEyNTY6NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NHByZWNpcGllbnRfa2V5X2lka3JlY2lwaWVudC0xbm93bmVyX2FnZW50X2lkeEZhZ2VudF84ZTk2ZmYwYzM5MmNlMjQzODQ5MDBmODM1MDYxZTA0OWU1YWYwYTNjODU1MjUwZmY0YjA5NDc3NTg2M2VlNzY0dHF1b3RlX3NpZ25lcl9rZXlfaWRzgWdxdW90ZS0xdXZhbGlkX2Zyb21fY2hlY2twb2ludAp2cmVjZWlwdF9zaWduZXJfa2V5X2lkc4FpcmVjZWlwdC0xdnZhbGlkX3VudGlsX2NoZWNrcG9pbnQZA-h2b2JqZWN0X25vbmNlX2Jhc2U2NHVybHgrUUVGQ1EwUkZSa2RJU1VwTFRFMU9UMUJSVWxOVVZWWlhXRmxhVzF4ZFhsOA",
		"canonical":      "rWRraW5kc3JlZ2lzdGVyX2NhcGFiaWxpdHlnbmV0d29ya6NqbmV0d29ya19pZGt0b3MtdGVzdG5ldHFnZW5lc2lzX2ZpbGVfaGFzaHhHc2hhMjU2OjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjIyMjJxZ2VuZXNpc19yb290X2hhc2h4R3NoYTI1NjoxMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExMTExZ3ZlcnNpb252dG9zX25hdGl2ZV9yZWdpc3RyeV92MWhhZ2VudF9pZHhGYWdlbnRfOGU5NmZmMGMzOTJjZTI0Mzg0OTAwZjgzNTA2MWUwNDllNWFmMGEzYzg1NTI1MGZmNGIwOTQ3NzU4NjNlZTc2NGhzZXF1ZW5jZQFqZ2VuZXJhdGlvbgFtY2FwYWJpbGl0eV9pZHhEY2FwX2FlNTU0NGY1ZTBiZThkZGExNGMzNjZlYzFkYTY4ZjA4NzAxMjhhZmVjYzU0ODVlYmJjZTY5YTk2ZjY0NDY2MzdtcG9saWN5X2RpZ2VzdHhHc2hhMjU2OjAwZDU4ZDc5YTU4NWFlMDY4NzZkZjdlYTYyY2VjNWY4NzFkYzg4NWIyM2M1NmQ0ZWRlM2NkZDFkMGFhYmM3NzJucGF5bG9hZF9kaWdlc3R4R3NoYTI1NjowN2ZkOWVmNDkyNjhiODdlM2JkNTU2ZmUxNGQ2MDNiNDRjYzYzMzZlMzAwMDgxOTExNTA3MTI1ZDdiNjk0ODY2b25vbmNlX2Jhc2U2NHVybHgrY0hGeWMzUjFkbmQ0ZVhwN2ZIMS1mNENCZ29PRWhZYUhpSW1LaTR5TmpvOHJjYXBhYmlsaXR5X3ZlcnNpb25lMS4yLjN1cHJldmlvdXNfc3RhdGVfZGlnZXN0YHZwYXlsb2FkX2Nib3JfYmFzZTY0dXJseQNOb21kMlpYSnphVzl1cDJodFlXNXBabVZ6ZEtSbVpHbG5aWE4wZUVkemFHRXlOVFk2TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TXpNek16TTJsc2IyTmhkR2x2Ym5PQmVDVm9kSFJ3Y3pvdkwzQnliM1pwWkdWeUxtVjRZVzF3YkdVdmJXRnVhV1psYzNSekwzWXhhbTFsWkdsaFgzUjVjR1Y0SzJGd2NHeHBZMkYwYVc5dUwzWnVaQzVoZEc5ekxtNWhkR2wyWlMxallYQmhZbWxzYVhSNUsycHpiMjVxYzJsNlpWOWllWFJsY3hrRTBtbGxibVJ3YjJsdWRIT0JvMmwwY21GdWMzQnZjblJsYUhSMGNITnZaVzVrY0c5cGJuUmZaR2xuWlhOMGVFZHphR0V5TlRZNk5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5EUTBORFEwTkRRME5IQnlaV05wY0dsbGJuUmZhMlY1WDJsa2EzSmxZMmx3YVdWdWRDMHhibTkzYm1WeVgyRm5aVzUwWDJsa2VFWmhaMlZ1ZEY4NFpUazJabVl3WXpNNU1tTmxNalF6T0RRNU1EQm1PRE0xTURZeFpUQTBPV1UxWVdZd1lUTmpPRFUxTWpVd1ptWTBZakE1TkRjM05UZzJNMlZsTnpZMGRIRjFiM1JsWDNOcFoyNWxjbDlyWlhsZmFXUnpnV2R4ZFc5MFpTMHhkWFpoYkdsa1gyWnliMjFmWTJobFkydHdiMmx1ZEFwMmNtVmpaV2x3ZEY5emFXZHVaWEpmYTJWNVgybGtjNEZwY21WalpXbHdkQzB4ZG5aaGJHbGtYM1Z1ZEdsc1gyTm9aV05yY0c5cGJuUVpBLWgyYjJKcVpXTjBYMjV2Ym1ObFgySmhjMlUyTkhWeWJIZ3JVVVZHUTFFd1VrWlNhMlJKVTFWd1RGUkZNVTlVTVVKU1ZXeE9WVlpXV2xoWFJteGhWekY0WkZoc09B",
	}
	mismatch := false
	for key, value := range got {
		if value != want[key] {
			t.Logf("%s=%s want %s", key, value, want[key])
			mismatch = true
		}
	}
	if mismatch {
		t.Fatal("normative vector mismatch")
	}
	if err := VerifyAuthorization(f.action, f.policyDigest, f.policy, []Signature{signature}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateEventTransition(nil, f.action, f.policyDigest, 0, event); err != nil {
		t.Fatal(err)
	}
}

func TestConsensusExecutionLimitsRejectUnrepresentableActions(t *testing.T) {
	f := fixture(t)
	var registration RegisterCapabilityPayload
	if err := DecodePayload(f.action, &registration); err != nil {
		t.Fatal(err)
	}
	registration.Version.Manifest.Locations = make([]string, MaxManifestLocations+1)
	for i := range registration.Version.Manifest.Locations {
		registration.Version.Manifest.Locations[i] = string(rune('a' + i))
	}
	if _, _, err := EncodePayload(ActionRegisterCapability, registration); ErrorCodeOf(err) != CodeCanonicalEncoding {
		t.Fatalf("locations above consensus limit: %v", err)
	}

	oversize := RevocationPayload{Scope: "agent", ReasonCode: "operator_request"}
	payloadCBOR, payloadDigest, err := EncodePayload(ActionRevokeAgent, oversize)
	if err != nil {
		t.Fatal(err)
	}
	action := RegistryAction{
		Version: Version, Kind: ActionRevokeAgent, Network: f.network, AgentID: f.agentID,
		Generation: 1, Sequence: 2, PreviousStateDigest: "sha256:" + strings.Repeat("55", 32),
		PolicyDigest: f.policyDigest, PayloadDigest: payloadDigest,
		PayloadCBORBase64: payloadCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x33, 32)),
	}
	// The action fields themselves are bounded; attempting to smuggle an
	// over-limit payload is rejected during canonical payload decoding.
	action.PayloadCBORBase64 = base64.RawURLEncoding.EncodeToString(make([]byte, MaxCanonicalPayloadBytes+1))
	if _, err := CanonicalAction(action); ErrorCodeOf(err) != CodeCanonicalEncoding {
		t.Fatalf("oversize payload accepted: %v", err)
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
	f.policy.Controllers = append(f.policy.Controllers, ControllerKey{})
	copy(f.policy.Controllers[2:], f.policy.Controllers[1:])
	f.policy.Controllers[1] = ControllerKey{KeyID: "controller-2", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(second.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"capability_control"}}
	changedPolicyDigest, err := ControllerPolicyDigest(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	f.action.PolicyDigest = changedPolicyDigest
	firstSignature, _ := SignAction(f.privateKey, "controller-1", f.action)
	secondSignature, _ := SignAction(second, "controller-2", f.action)
	if err := VerifyAuthorization(f.action, changedPolicyDigest, f.policy, []Signature{firstSignature}); ErrorCodeOf(err) != CodePolicyUnauthorized {
		t.Fatalf("threshold err=%v", err)
	}
	if err := VerifyAuthorization(f.action, changedPolicyDigest, f.policy, []Signature{firstSignature, secondSignature}); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(f.action, changedPolicyDigest, f.policy, []Signature{secondSignature, firstSignature}); err == nil {
		t.Fatal("unsorted signature set accepted")
	}
	if err := VerifyAuthorization(f.action, changedPolicyDigest, f.policy, []Signature{firstSignature, firstSignature}); err == nil {
		t.Fatal("duplicate signature weight accepted")
	}
}

func TestAuthorizationRejectsSelfConsistentNoncanonicalPolicy(t *testing.T) {
	f := fixture(t)
	attackerPolicy, attackerPrivate := ownerPolicy(t, 0x11)
	_, attackerDigest, err := EncodeControllerPolicy(attackerPolicy)
	if err != nil {
		t.Fatal(err)
	}
	changed := f.action
	changed.PolicyDigest = attackerDigest
	signature, err := SignAction(attackerPrivate, "controller-1", changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyAuthorization(changed, f.policyDigest, attackerPolicy, []Signature{signature}); ErrorCodeOf(err) != CodePolicyUnauthorized {
		t.Fatalf("attacker policy accepted: %v", err)
	}
}

func TestCapabilityTransferChangesOwnerGenerationAndRejectsOldOwner(t *testing.T) {
	f := fixture(t)
	state, err := DeriveNextState(nil, f.action, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	newPolicy, newPrivate := ownerPolicy(t, 0x31)
	newPolicyCBOR, newPolicyDigest, err := EncodeControllerPolicy(newPolicy)
	if err != nil {
		t.Fatal(err)
	}
	newAgentID, err := AgentID(AgentBootstrap{Version: Version, Network: f.network, ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0xc0, 32)), InitialControllerPolicy: newPolicyDigest})
	if err != nil {
		t.Fatal(err)
	}
	stateDigest, _ := StateDigest(state)
	transferCBOR, transferDigest, _ := EncodePayload(ActionTransferCapability, TransferCapabilityPayload{CurrentOwnerAgentID: f.agentID, NewOwnerAgentID: newAgentID, NewOwnerPolicyDigest: newPolicyDigest, NewOwnerPolicyCBORBase64: newPolicyCBOR})
	transfer := RegistryAction{Version: Version, Kind: ActionTransferCapability, Network: f.network, AgentID: f.agentID, CapabilityID: f.capabilityID, Generation: 2, Sequence: 1, PreviousStateDigest: stateDigest, PolicyDigest: f.policyDigest, PayloadDigest: transferDigest, PayloadCBORBase64: transferCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x21, 32))}
	currentSignature, _ := SignAction(f.privateKey, "controller-1", transfer)
	newSignature, _ := SignAction(newPrivate, "controller-1", transfer)
	if err := VerifyAuthorization(transfer, f.policyDigest, f.policy, []Signature{currentSignature}); ErrorCodeOf(err) != CodePurposeUnauthorized {
		t.Fatalf("single-sided transfer authorization accepted: %v", err)
	}
	if err := VerifyTransferAuthorization(transfer, f.policyDigest, f.policy, newPolicyDigest, newPolicy, []Signature{currentSignature}, []Signature{newSignature}); err != nil {
		t.Fatal(err)
	}
	transferred, err := DeriveNextState(&state, transfer, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.OwnerAgentID != newAgentID || transferred.Generation != 2 || transferred.Sequence != 1 {
		t.Fatalf("bad transferred state: %#v", transferred)
	}

	version := CapabilityVersionPayload{OwnerAgentID: newAgentID, Manifest: ManifestReference{Digest: "sha256:" + strings.Repeat("31", 32), MediaType: "application/vnd.atos.native-capability+json", SizeBytes: 32, Locations: []string{"https://new.example/v2"}}, Endpoints: []EndpointReference{{Transport: "https", EndpointDigest: "sha256:" + strings.Repeat("32", 32), RecipientKeyID: "recipient-2"}}, QuoteSignerKeyIDs: []string{"quote-1"}, ReceiptSignerKeyIDs: []string{"receipt-1"}, ValidFromCheckpoint: 20, ValidUntilCheckpoint: 2000}
	versionCBOR, versionDigest, _ := EncodePayload(ActionUpdateCapability, version)
	transferredDigest, _ := StateDigest(transferred)
	update := RegistryAction{Version: Version, Kind: ActionUpdateCapability, Network: f.network, AgentID: newAgentID, CapabilityID: f.capabilityID, CapabilityVersion: "2.0.0", Generation: 2, Sequence: 2, PreviousStateDigest: transferredDigest, PolicyDigest: newPolicyDigest, PayloadDigest: versionDigest, PayloadCBORBase64: versionCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x41, 32))}
	newState, err := DeriveNextState(&transferred, update, newPolicyDigest, 0)
	if err != nil || !hasCapabilityVersion(newState.CapabilityVersions, "2.0.0") {
		t.Fatalf("new owner update failed: %v", err)
	}
	stale := update
	stale.AgentID = f.agentID
	stale.PolicyDigest = f.policyDigest
	if _, err := DeriveNextState(&transferred, stale, f.policyDigest, 0); err == nil {
		t.Fatal("former owner updated transferred Capability")
	}
}

func TestTombstoneAndVersionImmutabilityFailClosed(t *testing.T) {
	f := fixture(t)
	bootstrap, _, _, _, _, _ := recoveryFixture(t, f)
	bootstrapDigest, _ := StateDigest(bootstrap)
	revokeCBOR, revokeDigest, _ := EncodePayload(ActionRevokeAgent, RevocationPayload{Scope: "agent", ReasonCode: "retired"})
	revoke := RegistryAction{Version: Version, Kind: ActionRevokeAgent, Network: f.network, AgentID: f.agentID, Generation: 1, Sequence: 2, PreviousStateDigest: bootstrapDigest, PolicyDigest: f.policyDigest, PayloadDigest: revokeDigest, PayloadCBORBase64: revokeCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x22, 32))}
	tombstone, err := DeriveNextState(&bootstrap, revoke, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	tombstoneDigest, _ := StateDigest(tombstone)
	updateCBOR, updateDigest, _ := EncodePayload(ActionUpdateAgentPolicy, UpdatePolicyPayload{NewPolicyDigest: f.policyDigest, NewPolicyCBORBase64: f.policyCBOR})
	update := RegistryAction{Version: Version, Kind: ActionUpdateAgentPolicy, Network: f.network, AgentID: f.agentID, Generation: 1, Sequence: 3, PreviousStateDigest: tombstoneDigest, PolicyDigest: f.policyDigest, PayloadDigest: updateDigest, PayloadCBORBase64: updateCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x42, 32))}
	if _, err := DeriveNextState(&tombstone, update, f.policyDigest, 0); ErrorCodeOf(err) != CodePermanentlyRevoked {
		t.Fatalf("tombstone revived: %v", err)
	}

	capState, _ := DeriveNextState(nil, f.action, f.policyDigest, 0)
	capDigest, _ := StateDigest(capState)
	var registration RegisterCapabilityPayload
	if err := DecodePayload(f.action, &registration); err != nil {
		t.Fatal(err)
	}
	versionCBOR, versionDigest, _ := EncodePayload(ActionUpdateCapability, registration.Version)
	duplicate := RegistryAction{Version: Version, Kind: ActionUpdateCapability, Network: f.network, AgentID: f.agentID, CapabilityID: f.capabilityID, CapabilityVersion: f.action.CapabilityVersion, Generation: 1, Sequence: 2, PreviousStateDigest: capDigest, PolicyDigest: f.policyDigest, PayloadDigest: versionDigest, PayloadCBORBase64: versionCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x62, 32))}
	if _, err := DeriveNextState(&capState, duplicate, f.policyDigest, 0); err == nil {
		t.Fatal("immutable Capability version overwritten")
	}
}

func TestCapabilityBootstrapAndStateDigestAreRecomputed(t *testing.T) {
	f := fixture(t)
	changed := f.action
	changed.CapabilityID = "cap_" + strings.Repeat("ab", 32)
	if _, err := ActionDigest(changed); ErrorCodeOf(err) != CodeInvalidIdentifier {
		t.Fatalf("substituted Capability ID accepted: %v", err)
	}
	state, _ := DeriveNextState(nil, f.action, f.policyDigest, 0)
	actionDigest, _ := ActionDigest(f.action)
	stateDigest, _ := StateDigest(state)
	event := RegistryEvent{Version: Version, Kind: f.action.Kind, Network: f.network, ActionDigest: actionDigest, AgentID: f.agentID, CapabilityID: f.capabilityID, CapabilityVersion: f.action.CapabilityVersion, Generation: 1, Sequence: 1, StateDigest: stateDigest}
	forged := state
	forged.OwnerAgentID = "agent_" + strings.Repeat("cd", 32)
	forgedDigest, _ := StateDigest(forged)
	event.StateDigest = forgedDigest
	if _, err := ValidateEventTransition(nil, f.action, f.policyDigest, 0, event); err == nil {
		t.Fatal("event accepted arbitrary non-derived state")
	}
}

func TestCanonicalAccountASCIIAndSignerConstraints(t *testing.T) {
	f := fixture(t)
	base := ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("11", 32), LogicalTime: 1, TransactionHash: "sha256:" + strings.Repeat("22", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("33", 32)}
	for _, account := range []string{"00:" + strings.Repeat("11", 32), "-0:" + strings.Repeat("11", 32), "-1:" + strings.Repeat("11", 32)} {
		changed := base
		changed.Account = account
		if err := changed.Validate(); err == nil {
			t.Fatalf("account alias accepted: %s", account)
		}
	}
	var registration RegisterCapabilityPayload
	if err := DecodePayload(f.action, &registration); err != nil {
		t.Fatal(err)
	}
	registration.Version.Manifest.Locations = []string{"https://example.invalid/\u96ea"}
	if _, _, err := EncodePayload(ActionRegisterCapability, registration); err == nil {
		t.Fatal("Unicode retrieval location accepted")
	}
	registration.Version.Manifest.Locations = []string{"https://example.invalid/v1"}
	registration.Version.ReceiptSignerKeyIDs = []string{"quote-1"}
	if _, _, err := EncodePayload(ActionRegisterCapability, registration); err == nil {
		t.Fatal("overlapping Quote/Receipt signer accepted")
	}

	registration.Version.ReceiptSignerKeyIDs = []string{"missing-receipt"}
	payloadCBOR, payloadDigest, err := EncodePayload(ActionRegisterCapability, registration)
	if err != nil {
		t.Fatal(err)
	}
	action := f.action
	action.PayloadCBORBase64 = payloadCBOR
	action.PayloadDigest = payloadDigest
	signature, _ := SignAction(f.privateKey, "controller-1", action)
	if err := VerifyAuthorization(action, f.policyDigest, f.policy, []Signature{signature}); ErrorCodeOf(err) != CodePurposeUnauthorized {
		t.Fatalf("unknown Receipt signer accepted: %v", err)
	}
}

func ownerPolicy(t *testing.T, first byte) (ControllerPolicy, ed25519.PrivateKey) {
	t.Helper()
	controllerSeed := makeNonzeroFrom(first, 32)
	quoteSeed := makeNonzeroFrom(first+0x20, 32)
	receiptSeed := makeNonzeroFrom(first+0x40, 32)
	controller := ed25519.NewKeyFromSeed(controllerSeed)
	quote := ed25519.NewKeyFromSeed(quoteSeed).Public().(ed25519.PublicKey)
	receipt := ed25519.NewKeyFromSeed(receiptSeed).Public().(ed25519.PublicKey)
	policy := ControllerPolicy{Threshold: 1, RecoveryThreshold: 1, Controllers: []ControllerKey{
		{KeyID: "controller-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(controller.Public().(ed25519.PublicKey)), Weight: 1, Purposes: []string{"agent_control", "capability_control", "recovery"}},
		{KeyID: "quote-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(quote), Weight: 1, Purposes: []string{"quote"}},
		{KeyID: "receipt-1", Algorithm: SignatureAlgorithm, PublicKeyBase64: base64.RawURLEncoding.EncodeToString(receipt), Weight: 1, Purposes: []string{"receipt"}},
	}, RecoveryKeyIDs: []string{"controller-1"}, RecoveryTimelock: 86400}
	if err := ValidateControllerPolicy(policy); err != nil {
		t.Fatal(err)
	}
	return policy, controller
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
	_, initiation, previous, _, observation, recovery := recoveryFixture(t, f)
	if err := ValidateTransition(&previous, recovery, f.policyDigest, observation.BlockUnixSeconds+f.policy.RecoveryTimelock-1); ErrorCodeOf(err) != CodeTimelockPending {
		t.Fatalf("early recovery err=%v", err)
	}
	if err := ValidateTransition(&previous, recovery, f.policyDigest, observation.BlockUnixSeconds+f.policy.RecoveryTimelock); err != nil {
		t.Fatal(err)
	}
	recovery.Generation = previous.Generation
	if err := ValidateTransition(&previous, recovery, f.policyDigest, observation.BlockUnixSeconds+f.policy.RecoveryTimelock); err == nil {
		t.Fatal("recovery without generation increment accepted")
	}
	_ = initiation
}

func TestRecoveryWeightCountsOnlyDesignatedRecoveryKeys(t *testing.T) {
	f := fixture(t)
	_, _, _, _, _, recovery := recoveryFixture(t, f)
	policy := f.policy
	policy.Controllers = append([]ControllerKey(nil), policy.Controllers...)
	policy.Controllers[1].Purposes = []string{"quote", "recovery"}
	if err := ValidateControllerPolicy(policy); err != nil {
		t.Fatal(err)
	}
	if err := validateAuthorizationKeyIDs(recovery, policy, "recovery", []string{"quote-1"}); ErrorCodeOf(err) != CodePurposeUnauthorized {
		t.Fatalf("non-designated recovery key contributed threshold weight: %v", err)
	}
}

func TestRecoveryBindsFinalizedInitiationAndOldPolicyTimelock(t *testing.T) {
	f := fixture(t)
	bootstrap, initiation, previous, initiationEvent, observation, recovery := recoveryFixture(t, f)
	executeAfter := observation.BlockUnixSeconds + f.policy.RecoveryTimelock
	if err := ValidateRecoveryTransition(bootstrap, previous, recovery, initiation, initiationEvent, observation, executeAfter); err != nil {
		t.Fatal(err)
	}
	// Offline signers may conservatively choose a later not-before time; the
	// canonical inclusion time is unknowable before the action is signed.
	laterBootstrap, laterInitiation, laterPrevious, laterEvent, laterObservation, laterRecovery := recoveryFixture(t, f)
	laterExecuteAfter := laterObservation.BlockUnixSeconds + f.policy.RecoveryTimelock + 30
	var laterInitiatePayload InitiateRecoveryPayload
	if err := DecodePayload(laterInitiation, &laterInitiatePayload); err != nil {
		t.Fatal(err)
	}
	laterInitiatePayload.ExecuteAfterUnixSeconds = laterExecuteAfter
	laterInitiation.PayloadCBORBase64, laterInitiation.PayloadDigest, _ = EncodePayload(ActionInitiateRecovery, laterInitiatePayload)
	laterPrevious, _ = DeriveNextState(&laterBootstrap, laterInitiation, f.policyDigest, 0)
	laterActionDigest, _ := ActionDigest(laterInitiation)
	laterStateDigest, _ := StateDigest(laterPrevious)
	laterEvent.ActionDigest, laterEvent.StateDigest = laterActionDigest, laterStateDigest
	laterEvent.Sequence, laterEvent.PreviousStateDigest = laterInitiation.Sequence, laterInitiation.PreviousStateDigest
	laterEventDigest, _ := EventDigest(laterEvent)
	laterObservation.EventDigest = laterEventDigest
	var laterRecoverPayload RecoverAgentPayload
	if err := DecodePayload(laterRecovery, &laterRecoverPayload); err != nil {
		t.Fatal(err)
	}
	laterRecoverPayload.ExecuteAfterUnixSeconds = laterExecuteAfter
	laterRecoverPayload.InitiationActionDigest = laterActionDigest
	laterRecovery.PreviousStateDigest = laterStateDigest
	laterRecovery.PayloadCBORBase64, laterRecovery.PayloadDigest, _ = EncodePayload(ActionRecoverAgent, laterRecoverPayload)
	if err := ValidateRecoveryTransition(laterBootstrap, laterPrevious, laterRecovery, laterInitiation, laterEvent, laterObservation, laterExecuteAfter); err != nil {
		t.Fatalf("later safe not-before rejected: %v", err)
	}
	laterObservation.BlockUnixSeconds = laterExecuteAfter - f.policy.RecoveryTimelock + 1
	if err := ValidateRecoveryTransition(laterBootstrap, laterPrevious, laterRecovery, laterInitiation, laterEvent, laterObservation, laterExecuteAfter); ErrorCodeOf(err) != CodeTimelockPending {
		t.Fatalf("too-short inclusion-relative timelock accepted: %v", err)
	}
	changed := observation
	changed.Reference.LogicalTime++
	if err := ValidateRecoveryTransition(bootstrap, previous, recovery, initiation, initiationEvent, changed, executeAfter); err == nil {
		t.Fatal("different initiation reference accepted")
	}
	changed = observation
	changed.Network.NetworkID = "tos-other"
	if err := ValidateRecoveryTransition(bootstrap, previous, recovery, initiation, initiationEvent, changed, executeAfter); err == nil {
		t.Fatal("cross-network initiation observation accepted")
	}

	// A later canonical action supersedes the pending recovery. The old
	// initiation cannot be selected from a parallel or stale branch.
	previousDigest, _ := StateDigest(previous)
	revokeCBOR, revokeDigest, _ := EncodePayload(ActionRevokeAgent, RevocationPayload{Scope: "agent", ReasonCode: "security"})
	revoke := RegistryAction{Version: Version, Kind: ActionRevokeAgent, Network: f.network, AgentID: f.agentID, Generation: 1, Sequence: 3, PreviousStateDigest: previousDigest, PolicyDigest: f.policyDigest, PayloadDigest: revokeDigest, PayloadCBORBase64: revokeCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x31, 32))}
	superseded, err := DeriveNextState(&previous, revoke, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateRecoveryTransition(bootstrap, superseded, recovery, initiation, initiationEvent, observation, executeAfter); err == nil {
		t.Fatal("superseded recovery initiation accepted")
	}
}

func recoveryFixture(t *testing.T, f fixtureValues) (RegistryState, RegistryAction, RegistryState, RegistryEvent, EventObservation, RegistryAction) {
	t.Helper()
	registerCBOR, registerDigest, err := EncodePayload(ActionRegisterAgent, RegisterAgentPayload{ObjectNonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0xa0, 32)), InitialPolicyDigest: f.policyDigest, InitialPolicyCBORBase64: f.policyCBOR})
	if err != nil {
		t.Fatal(err)
	}
	registration := RegistryAction{Version: Version, Kind: ActionRegisterAgent, Network: f.network, AgentID: f.agentID, Generation: 1, Sequence: 1, PolicyDigest: f.policyDigest, PayloadDigest: registerDigest, PayloadCBORBase64: registerCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x61, 32))}
	bootstrap, err := DeriveNextState(nil, registration, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapDigest, _ := StateDigest(bootstrap)
	blockTime := uint64(1_800_000_000)
	executeAfter := blockTime + f.policy.RecoveryTimelock
	initCBOR, initPayloadDigest, _ := EncodePayload(ActionInitiateRecovery, InitiateRecoveryPayload{NewPolicyDigest: f.policyDigest, ExecuteAfterUnixSeconds: executeAfter, NewPolicyCBORBase64: f.policyCBOR})
	initiation := RegistryAction{Version: Version, Kind: ActionInitiateRecovery, Network: f.network, AgentID: f.agentID, Generation: 1, Sequence: 2, PreviousStateDigest: bootstrapDigest, PolicyDigest: f.policyDigest, PayloadDigest: initPayloadDigest, PayloadCBORBase64: initCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x71, 32))}
	previous, err := DeriveNextState(&bootstrap, initiation, f.policyDigest, 0)
	if err != nil {
		t.Fatal(err)
	}
	initDigest, _ := ActionDigest(initiation)
	previousDigest, _ := StateDigest(previous)
	initiationEvent := RegistryEvent{Version: Version, Kind: initiation.Kind, Network: f.network, ActionDigest: initDigest, AgentID: f.agentID, Generation: 1, Sequence: 2, PreviousStateDigest: bootstrapDigest, StateDigest: previousDigest}
	initEventDigest, _ := EventDigest(initiationEvent)
	reference := ChainReference{Workchain: 0, Account: "0:" + strings.Repeat("55", 32), LogicalTime: 12, TransactionHash: "sha256:" + strings.Repeat("66", 32), ContractCodeHash: "tvm-cell-sha256:" + strings.Repeat("77", 32)}
	observation := EventObservation{Version: Version, Network: f.network, EventDigest: initEventDigest, Reference: reference, FinalizedCheckpoint: 100, FinalizedRootHash: "sha256:" + strings.Repeat("99", 32), FinalizedFileHash: "sha256:" + strings.Repeat("aa", 32), BlockUnixSeconds: blockTime, InclusionProofDigest: "sha256:" + strings.Repeat("bb", 32)}
	recoveryCBOR, recoveryDigest, _ := EncodePayload(ActionRecoverAgent, RecoverAgentPayload{NewPolicyDigest: f.policyDigest, InitiationActionDigest: initDigest, InitiationReference: reference, ExecuteAfterUnixSeconds: executeAfter})
	recovery := RegistryAction{Version: Version, Kind: ActionRecoverAgent, Network: f.network, AgentID: f.agentID, Generation: 2, Sequence: 1, PreviousStateDigest: previousDigest, PolicyDigest: f.policyDigest, PayloadDigest: recoveryDigest, PayloadCBORBase64: recoveryCBOR, NonceBase64: base64.RawURLEncoding.EncodeToString(makeNonzeroFrom(0x91, 32))}
	return bootstrap, initiation, previous, initiationEvent, observation, recovery
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

func TestRegistryStateCanonicalizesEmptyCollections(t *testing.T) {
	f := fixture(t)
	bootstrap, _, _, _, _, _ := recoveryFixture(t, f)
	withNil := bootstrap
	withNil.CapabilityVersions = nil
	withNil.DelegationActionDigests = nil
	withEmpty := bootstrap
	withEmpty.CapabilityVersions = []CapabilityVersionState{}
	withEmpty.DelegationActionDigests = []string{}
	nilDigest, err := StateDigest(withNil)
	if err != nil {
		t.Fatal(err)
	}
	emptyDigest, err := StateDigest(withEmpty)
	if err != nil || nilDigest != emptyDigest {
		t.Fatalf("nil/empty collection alias changed state identity: nil=%s empty=%s err=%v", nilDigest, emptyDigest, err)
	}
	canonical, err := CanonicalState(withNil)
	if err != nil || canonical.CapabilityVersions == nil || canonical.DelegationActionDigests == nil {
		t.Fatalf("state was not normalized to canonical arrays: %+v err=%v", canonical, err)
	}
}

func makeNonzero(size int) []byte {
	return makeNonzeroFrom(1, size)
}
func makeNonzeroFrom(first byte, size int) []byte {
	value := make([]byte, size)
	for i := range value {
		value[i] = first + byte(i)
	}
	return value
}
