package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	commerce "github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type objectVector struct {
	Name                string `json:"name"`
	Domain              string `json:"digest_domain"`
	JSONModel           any    `json:"json_model"`
	CanonicalCBORBase64 string `json:"canonical_cbor_base64"`
	Digest              string `json:"digest"`
}

type signatureVector struct {
	Name               string `json:"name"`
	ObjectName         string `json:"object_name"`
	MessageFormula     string `json:"message_formula"`
	MessageDomain      string `json:"message_domain"`
	PublicKey          string `json:"public_key"`
	Signature          string `json:"signature"`
	ExpectedMessageHex string `json:"expected_message_hex"`
}

type document struct {
	Schema            string            `json:"schema"`
	Objects           []objectVector    `json:"objects"`
	Signatures        []signatureVector `json:"signatures"`
	NegativeMutations []string          `json:"negative_mutations"`
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: agent-commerce-fixtures OUTPUT")
	}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	key := ed25519.NewKeyFromSeed(seed)
	now := time.Unix(2_000_000_000, 0).UTC()
	detail := []byte("review one bounded source tree")
	detailDigest := sha256.Sum256(detail)
	agentID := "agent:" + strings.Repeat("a", 64)
	intentBody := commerce.AgentIntentBody{SchemaVersion: 1, NetworkID: "tos:testnet", IssuerAgentID: agentID,
		Audience: "public:indexable", ObjectID: "intent:" + strings.Repeat("b", 64), Revision: 1,
		CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), Payload: commerce.AgentIntentPayload{
			DiscoveryCard: commerce.DiscoveryCard{Summary: "Review source", IntentModes: []commerce.IntentMode{commerce.IntentRequest},
				SubjectClasses: []commerce.SubjectClass{commerce.SubjectService}, TaxonomyPaths: []string{"tos.taxonomy.v1/service/security/review"},
				Keywords: []commerce.IntentKeyword{{Text: "review", Language: "en"}}, ValueState: commerce.ValueSpecified,
				ValueHints: []commerce.ValueHint{{Role: "budget", AssetNamespace: "tos.native", AssetIdentifier: "TOS", AmountKind: "exact", MinimumDecimal: "50", MaximumDecimal: "50", Unit: "total"}},
				Schedule:   commerce.IntentSchedule{Flexibility: "flexible"}, FulfillmentModes: []string{"remote"}},
			DetailDescriptor: commerce.ContentDescriptor{ContentType: "text/plain", ContentDigest: "sha256:" + hex.EncodeToString(detailDigest[:]),
				ContentSize: uint64(len(detail)), InlineContent: detail}, ReplyRoutes: []commerce.ReplyRoute{{ProfileURI: "tos.messenger.direct.v1", AgentID: agentID}}}}
	signedIntent, mustErr := commerce.SignIntent(intentBody, key)
	must(mustErr)
	intentDigest, _ := commerce.IntentBodyDigest(intentBody)
	withdrawalBody := commerce.AgentIntentWithdrawalBody{SchemaVersion: 1, NetworkID: intentBody.NetworkID, IssuerAgentID: agentID,
		Audience: intentBody.Audience, ObjectID: intentBody.ObjectID, IntentRevision: 1, IntentDigest: intentDigest,
		ReasonCode: "capacity-unavailable", CreatedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(30 * time.Minute).Unix())}
	signedWithdrawal, mustErr := commerce.SignIntentWithdrawal(withdrawalBody, key)
	must(mustErr)

	profileDigest := commerce.AgentSignatureProfileDigest()
	buyer := "agent:" + strings.Repeat("c", 64)
	agreement := commerce.AgentAgreementBody{SchemaVersion: 1, AgreementID: "agreement:" + strings.Repeat("d", 64), Version: 1,
		NetworkContext: "tos:testnet", Participants: []commerce.AgreementParticipant{{AgentID: agentID, Roles: []string{"provider"}}, {AgentID: buyer, Roles: []string{"buyer"}}},
		ReferencedIntents: []string{intentDigest}, TermsContentType: "text/plain", Terms: []byte("one bounded review for 50 atomic units"),
		Obligations: []commerce.AgreementObligation{{ObligationID: "work", Kind: "service", ObligorAgentID: agentID, BeneficiaryAgentID: buyer,
			SubjectContentType: "text/plain", Subject: []byte("perform review"), ConfidentialityPolicy: "private", CancellationPolicy: "before-start",
			DisputePolicy: "evidence", AuthorizationPredicateIDs: []string{"provider-work"}}},
		AuthorizationPredicates: []commerce.AgreementAuthorizationPredicate{{PredicateID: "provider-work",
			AuthoritySubject: commerce.AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: agentID},
			RoleScope:        []string{"provider"}, ObligationIDs: []string{"work"}, EvidenceProfileURI: commerce.EvidenceProfileAgentSignature,
			EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}},
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	agreement, mustErr = commerce.PrepareAgreementTargets(agreement)
	must(mustErr)
	applicationV2 := commerce.IntentApplication{SchemaVersion: 2, IntentDigest: intentDigest,
		IntentIssuerAgentID: agentID, ApplicantAgentID: buyer, Message: "A non-authorizing generic Agreement proposal.",
		SettlementOffers:      []commerce.SettlementPreference{{AdapterURI: "tos.payment.direct.v1", Required: true}},
		ProposedAgreementBody: &agreement, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	must(commerce.ValidateIntentApplication(applicationV2))

	fence, mustErr := commerce.SignWriterFence(commerce.WriterFenceBody{SchemaVersion: 1, OwnerID: "owner:test", AgentID: agentID,
		InstanceID: "instance:test", LeaseID: "lease:test", WriterGeneration: 7, IssuedAtUnix: uint64(now.Unix()),
		ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()), AuthorityID: "authority:test", Scope: []string{"messenger.contact"}}, key)
	must(mustErr)
	request, mustErr := commerce.CanonicalMessengerEffectRequest(commerce.MessengerEffectRequestV1{SchemaVersion: 1,
		RecipientAgentIDs: []string{buyer}, EventKind: "text", ContentType: "text/plain", Payload: []byte("Can we confirm scope?")})
	must(mustErr)
	fields := map[string]commerce.SemanticValue{"owner_id": commerce.ID("owner:test"), "agent_id": commerce.ID(agentID),
		"recipient_agent_id": commerce.ID(buyer), "intent_reference_digest": commerce.Digest32(intentDigest),
		"authority_instance_id": commerce.Digest32("sha256:" + strings.Repeat("e", 64))}
	action, mustErr := commerce.BuildAuthorizedAction("owner:test", agentID, "messenger.contact", fields, request, fence, 3,
		"sha256:"+strings.Repeat("f", 64), "", "no-contact", uint64(now.Add(30*time.Minute).Unix()))
	must(mustErr)
	action, mustErr = commerce.SignAuthorizedAction(action, key)
	must(mustErr)
	externalPaymentBody := commerce.ExternalPaymentAttestationBody{SchemaVersion: 1,
		AdapterURI: "tos.payment.external-attested.v1", AttestorID: "attestor:test",
		PaymentRequestDigest: "sha256:" + strings.Repeat("1", 64), StableActionID: "sha256:" + strings.Repeat("2", 64),
		ExactTransferReference: "external:test:transfer:1", FinalityReference: "external:test:finality:1",
		ResolvedAtUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())}
	externalPayment, mustErr := commerce.SignExternalPaymentAttestation(externalPaymentBody, key)
	must(mustErr)

	doc := document{Schema: "tos.agent-commerce-core-conformance.v1",
		NegativeMutations: []string{"mutated-intent-summary", "mutated-signature", "noncanonical-cbor"}}
	add := func(name, domain string, value any) {
		canonical, err := codec.Marshal(value)
		must(err)
		digest, err := codec.Digest(domain, value)
		must(err)
		doc.Objects = append(doc.Objects, objectVector{Name: name, Domain: domain, JSONModel: value,
			CanonicalCBORBase64: base64.StdEncoding.EncodeToString(canonical), Digest: digest})
	}
	add("intent_body", "tos.agent-intent-body.v1", intentBody)
	add("signed_intent", "tos.fixture.signed-agent-intent.v1", signedIntent)
	add("intent_withdrawal_body", "tos.agent-intent-withdrawal-body.v1", withdrawalBody)
	add("signed_intent_withdrawal", "tos.fixture.signed-intent-withdrawal.v1", signedWithdrawal)
	add("agreement_body", "tos.agent-agreement-body.v1", agreement)
	add("intent_application_v2", "tos.intent-application.v1", applicationV2)
	add("writer_fence_body", "tos.fixture.writer-fence-body.v1", fence.Body)
	add("writer_fence", "tos.writer-fence-envelope.v1", fence)
	add("authorized_action", "tos.fixture.authorized-action.v1", action)
	add("external_payment_attestation_body", "tos.external-payment-attestation-body.v1", externalPaymentBody)
	add("signed_external_payment_attestation", "tos.fixture.signed-external-payment-attestation.v1", externalPayment)

	canonicalIntent, _ := codec.Marshal(intentBody)
	canonicalWithdrawal, _ := codec.Marshal(withdrawalBody)
	canonicalFence, _ := codec.Marshal(fence.Body)
	unsignedAction := action
	unsignedAction.AuthorizationProof = ""
	canonicalAction, _ := codec.Marshal(unsignedAction)
	canonicalExternalPayment, _ := codec.Marshal(externalPaymentBody)
	doc.Signatures = []signatureVector{
		signature("intent", "intent_body", "length-framed-sha256", "tos.agent-intent-signature.v1", signedIntent.PublicKey, signedIntent.Signature, canonicalIntent),
		signature("intent_withdrawal", "intent_withdrawal_body", "length-framed-sha256", "tos.agent-intent-withdrawal-signature.v1", signedWithdrawal.PublicKey, signedWithdrawal.Signature, canonicalWithdrawal),
		signature("writer_fence", "writer_fence_body", "framed-sha256", "tos.writer-fence.v1", fence.PublicKey, fence.Proof, canonicalFence),
		signature("authorized_action", "authorized_action", "framed-sha256", "tos.authorized-action-proof.v1", action.AuthorityPublicKey, action.AuthorizationProof, canonicalAction),
		signature("external_payment_attestation", "external_payment_attestation_body", "domain-text-digest-sha256",
			"TOS-EXTERNAL-PAYMENT-ATTESTATION-V1", externalPayment.PublicKey, externalPayment.Signature, canonicalExternalPayment),
	}
	raw, mustErr := json.MarshalIndent(doc, "", "  ")
	must(mustErr)
	must(os.WriteFile(os.Args[1], append(raw, '\n'), 0o644))
}

func signature(name, object, formula, domain, public, proof string, canonical []byte) signatureVector {
	var message []byte
	switch formula {
	case "length-framed-sha256":
		hash := sha256.New()
		hash.Write([]byte(domain + "\x00"))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
		hash.Write(length[:])
		hash.Write(canonical)
		message = hash.Sum(nil)
	case "framed-sha256":
		hash := sha256.New()
		hash.Write([]byte(domain + "\x00"))
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(canonical)))
		hash.Write(length[:])
		hash.Write(canonical)
		message = hash.Sum(nil)
	case "domain-text-digest-sha256":
		digest := sha256.New()
		digest.Write([]byte("TOS-PROTOCOL-CBOR\x00"))
		var domainLength [2]byte
		binary.BigEndian.PutUint16(domainLength[:], uint16(len("tos.external-payment-attestation-body.v1")))
		digest.Write(domainLength[:])
		digest.Write([]byte("tos.external-payment-attestation-body.v1"))
		digest.Write(canonical)
		bodyDigest := "sha256:" + hex.EncodeToString(digest.Sum(nil))
		value := sha256.Sum256([]byte(domain + "\x00" + bodyDigest))
		message = value[:]
	default:
		panic("unknown formula")
	}
	return signatureVector{Name: name, ObjectName: object, MessageFormula: formula, MessageDomain: domain,
		PublicKey: public, Signature: proof, ExpectedMessageHex: hex.EncodeToString(message)}
}

func must(err error) {
	if err != nil {
		panic(fmt.Sprintf("fixture generation: %v", err))
	}
}
