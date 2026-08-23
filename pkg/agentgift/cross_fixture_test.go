package agentgift

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRustAgentAccountFixtureIsAcceptedByIndependentGoVerifier(t *testing.T) {
	var fixture struct {
		Schema              string `json:"schema"`
		Account             string `json:"account"`
		ControllerPublicKey string `json:"controller_public_key"`
		Target              string `json:"target"`
		AmountAtomic        string `json:"amount_atomic"`
		ExactSignedBOC      string `json:"exact_signed_boc"`
		GlobalID            int32  `json:"global_id"`
		Seqno               uint32 `json:"seqno"`
		ValidUntil          uint32 `json:"valid_until"`
	}
	raw, err := os.ReadFile("testdata/rust_agent_native_send_v1.json")
	if err != nil || json.Unmarshal(raw, &fixture) != nil || fixture.Schema != "tos.agent-gift.rust-fixture.v1" {
		t.Fatal("invalid Rust cross-implementation fixture")
	}
	boc, err := base64.StdEncoding.DecodeString(fixture.ExactSignedBOC)
	if err != nil || base64.StdEncoding.EncodeToString(boc) != fixture.ExactSignedBOC {
		t.Fatal("non-canonical fixture BOC")
	}
	publicKey, err := hex.DecodeString(fixture.ControllerPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid fixture key")
	}
	request := GiftAddressRequestV1{Schema: SchemaAddressRequest, Network: "tos-fixture", GlobalID: fixture.GlobalID, GiftIntentID: repeatHex("a"), SenderAgentID: "agent_" + repeatHex("b"), RecipientAgentID: "agent_" + repeatHex("c"), SenderAgentAccount: fixture.Account, AssetKind: AssetNativeTOS, AmountAtomic: fixture.AmountAtomic, RequestedValidUntil: fixture.ValidUntil}
	requestDigest, _ := RequestDigest(request)
	response := GiftAddressResponseV1{Schema: SchemaAddressResponse, Network: request.Network, GlobalID: request.GlobalID, GiftIntentID: request.GiftIntentID, RequestDigest: requestDigest, SenderAgentID: request.SenderAgentID, RecipientAgentID: request.RecipientAgentID, AssetKind: request.AssetKind, AmountAtomic: request.AmountAtomic, DestinationAddress: fixture.Target, ResponseNotAfter: fixture.ValidUntil}
	parsed, err := VerifyAgentNativeSend(VerifyNativeSendInput{ExactSignedBOC: boc, Request: request, Response: response, Account: FinalizedAgentAccount{Active: true, Address: fixture.Account, CodeHash: AgentAccountCodeHash, DeploymentID: "sha256:" + repeatHex("d"), GlobalID: fixture.GlobalID, TVMVersion: MinimumAgentAccountTVMVersion, ControllerPublicKey: publicKey, Seqno: fixture.Seqno, BalanceAtomic: 2_000_000_000, MaxPerTxAtomic: 2_000_000_000, DailyRemainingAtomic: 2_000_000_000, DefaultTaskTimeoutSecs: 3_600}, ExpectedSignedGiftID: SignedGiftID(boc), FeeReserveAtomic: 1_000_000, FinalizedChainTime: 1_999_999_000, MinimumInclusionMargin: 60})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.DestinationAddress != fixture.Target || parsed.AmountAtomic != 1_000_000_000 || parsed.Seqno != fixture.Seqno || parsed.ValidUntil != fixture.ValidUntil {
		t.Fatalf("wrong parsed Rust fixture: %+v", parsed)
	}
}

func repeatHex(value string) string {
	result := ""
	for len(result) < 64 {
		result += value
	}
	return result
}
