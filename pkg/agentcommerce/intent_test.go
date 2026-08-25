package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

type fixedIntentResolver struct{ key ed25519.PublicKey }

func (r fixedIntentResolver) AuthorizeIntentKey(_ string, key ed25519.PublicKey, _ time.Time) error {
	if !key.Equal(r.key) {
		return errors.New("wrong key")
	}
	return nil
}

func validIntentBody(now time.Time) AgentIntentBody {
	detail := []byte("Review one repository and deliver a bounded report.")
	digest := sha256.Sum256(detail)
	return AgentIntentBody{
		SchemaVersion: 1,
		NetworkID:     "tos:testnet",
		IssuerAgentID: "agent:" + strings.Repeat("a", 64),
		Audience:      "public:indexable",
		ObjectID:      "intent:" + strings.Repeat("b", 64),
		Revision:      1,
		CreatedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		Payload: AgentIntentPayload{
			DiscoveryCard: DiscoveryCard{
				Summary:        "Security review needed",
				IntentModes:    []IntentMode{IntentBuy, IntentRequest},
				SubjectClasses: []SubjectClass{SubjectService},
				TaxonomyPaths:  []string{"tos.taxonomy.v1/service/security/review"},
				Keywords:       []IntentKeyword{{Text: "review", Language: "en"}, {Text: "security", Language: "en"}},
				ValueState:     ValueRange,
				ValueHints: []ValueHint{{Role: "budget", AssetNamespace: "tos.asset", AssetIdentifier: "native",
					AmountKind: "range", MinimumDecimal: "40", MaximumDecimal: "60", Unit: "per_contract"}},
				Schedule:         IntentSchedule{Flexibility: "flexible"},
				FulfillmentModes: []string{"digital_delivery", "remote"},
				Languages:        []string{"en"},
			},
			DetailDescriptor:      ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(digest[:]), ContentSize: uint64(len(detail)), InlineContent: detail},
			ReplyRoutes:           []ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: "agent:" + strings.Repeat("a", 64)}},
			SettlementPreferences: []SettlementPreference{{AdapterURI: "tos.payment.direct.v1"}},
		},
	}
}

func TestSignedIntentRoundTrip(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	signed, err := SignIntent(validIntentBody(now), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyIntent(signed, fixedIntentResolver{key: publicKey}, now); err != nil {
		t.Fatal(err)
	}
	first, err := IntentBodyDigest(signed.Body)
	if err != nil {
		t.Fatal(err)
	}
	signed.Body.Payload.DiscoveryCard.Summary = "mutated"
	second, err := IntentBodyDigest(signed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if first == second || VerifyIntent(signed, fixedIntentResolver{key: publicKey}, now) == nil {
		t.Fatal("intent mutation preserved digest or signature")
	}
}

func TestIntentRevisionAndBoundsFailClosed(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validIntentBody(now)
	body.Revision = 2
	if err := ValidateIntentBody(body, now); err == nil {
		t.Fatal("successor without predecessor was accepted")
	}
	body = validIntentBody(now)
	body.Payload.DiscoveryCard.Keywords[1], body.Payload.DiscoveryCard.Keywords[0] = body.Payload.DiscoveryCard.Keywords[0], body.Payload.DiscoveryCard.Keywords[1]
	if err := ValidateIntentBody(body, now); err == nil {
		t.Fatal("unsorted keyword set was accepted")
	}
	body = validIntentBody(now)
	body.ExpiresAtUnix = uint64(now.Add(MaxIntentLifetime + time.Second).Unix())
	if err := ValidateIntentBody(body, now); err == nil {
		t.Fatal("overlong intent lifetime was accepted")
	}
}

func TestIntentWithdrawalBindsExactRevisionAndRejectsReplayMutation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(2_000_000_000, 0).UTC()
	body := AgentIntentWithdrawalBody{SchemaVersion: 1, NetworkID: "tos:test", IssuerAgentID: "agent:issuer",
		Audience: "public", ObjectID: "intent:service:1", IntentRevision: 3,
		IntentDigest: "sha256:" + strings.Repeat("1", 64), ReasonCode: "capacity-unavailable",
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	withdrawal, err := SignIntentWithdrawal(body, private)
	if err != nil {
		t.Fatal(err)
	}
	resolver := fixedIntentResolver{key: public}
	if err := VerifyIntentWithdrawal(withdrawal, resolver, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	mutated := withdrawal
	mutated.Body.IntentRevision++
	if err := VerifyIntentWithdrawal(mutated, resolver, now.Add(time.Second)); err == nil {
		t.Fatal("withdrawal signature survived revision substitution")
	}
}
