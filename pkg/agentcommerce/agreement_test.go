package agentcommerce

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type agreementKeyResolver map[string]ed25519.PublicKey

func (r agreementKeyResolver) AuthorizeIntentKey(agentID string, key ed25519.PublicKey, _ time.Time) error {
	allowed := r[agentID]
	if allowed == nil || !allowed.Equal(key) {
		return errors.New("key is not authorized")
	}
	return nil
}

func validAgreementBody(t *testing.T, now time.Time) AgentAgreementBody {
	t.Helper()
	profileDigest := AgentSignatureProfileDigest()
	provider := "agent:" + strings.Repeat("a", 64)
	buyer := "agent:" + strings.Repeat("b", 64)
	body := AgentAgreementBody{
		SchemaVersion:  1,
		AgreementID:    "agreement:" + strings.Repeat("c", 64),
		Version:        1,
		NetworkContext: "tos:testnet",
		Participants: []AgreementParticipant{
			{AgentID: provider, Roles: []string{"provider"}},
			{AgentID: buyer, Roles: []string{"buyer"}},
		},
		ReferencedIntents: []string{"sha256:" + strings.Repeat("d", 64)},
		TermsContentType:  "text/plain",
		Terms:             []byte("Review the submitted source and deliver one report for 50 atomic units."),
		Obligations: []AgreementObligation{
			{ObligationID: "deliverable:report", Kind: "deliverable", ObligorAgentID: provider, BeneficiaryAgentID: buyer,
				SubjectContentType: "text/plain", Subject: []byte("bounded security report"), ConfidentialityPolicy: "private-to-participants",
				CancellationPolicy: "mutual-before-start", DisputePolicy: "manual-v1", AuthorizationPredicateIDs: []string{"predicate:provider"}},
			{ObligationID: "payment:final", Kind: "payment", ObligorAgentID: buyer, BeneficiaryAgentID: provider,
				DependsOnObligationIDs: []string{"deliverable:report"}, SubjectContentType: "text/plain", Subject: []byte("payment after accepted delivery"),
				Amount:                &AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "50", Unit: "total"},
				ConfidentialityPolicy: "participants", CancellationPolicy: "due-after-acceptance", DisputePolicy: "manual-v1",
				SettlementAdapterURI: "tos.payment.direct.v1", SettlementParameters: []byte("network=tos:testnet"),
				AuthorizationPredicateIDs: []string{"predicate:buyer"}},
		},
		AuthorizationPredicates: []AgreementAuthorizationPredicate{
			{PredicateID: "predicate:buyer", AuthoritySubject: AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: buyer},
				RoleScope: []string{"buyer"}, ObligationIDs: []string{"payment:final"}, EvidenceProfileURI: EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
			{PredicateID: "predicate:provider", AuthoritySubject: AgreementAuthoritySubject{SubjectKind: "agent", SubjectNamespace: "tos.agent", SubjectIdentifier: provider},
				RoleScope: []string{"provider"}, ObligationIDs: []string{"deliverable:report"}, EvidenceProfileURI: EvidenceProfileAgentSignature,
				EvidenceProfileVersion: 1, EvidenceProfileDigest: profileDigest, ExpiresAtUnix: uint64(now.Add(time.Hour).Unix())},
		},
		ValidFromUnix: uint64(now.Unix()), ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
	}
	prepared, err := PrepareAgreementTargets(body)
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func TestAgreementTargetsAndDigestBindEveryObligation(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	if err := ValidateAgreementBody(body); err != nil {
		t.Fatal(err)
	}
	first, err := AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	mutated := body
	mutated.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	mutated.Obligations[1].Amount = &AgreementAmount{AssetNamespace: "tos.asset", AssetIdentifier: "native", AmountAtomic: "51", Unit: "total"}
	if err := ValidateAgreementBody(mutated); err == nil {
		t.Fatal("authority targets did not detect a changed amount")
	}
	mutated.AuthorizationPredicates = append([]AgreementAuthorizationPredicate(nil), mutated.AuthorizationPredicates...)
	for index := range mutated.AuthorizationPredicates {
		mutated.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	mutated, err = PrepareAgreementTargets(mutated)
	if err != nil {
		t.Fatal(err)
	}
	second, err := AgreementBodyDigest(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("changed obligation preserved Agreement digest")
	}
}

func TestAgreementRequiresAcyclicObligorAuthorizedGraph(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	broken := body
	broken.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	broken.Obligations[0].DependsOnObligationIDs = []string{"payment:final"}
	for index := range broken.AuthorizationPredicates {
		broken.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	if _, err := PrepareAgreementTargets(broken); err == nil {
		t.Fatal("cyclic obligation graph was accepted")
	}
	broken = body
	broken.Obligations = append([]AgreementObligation(nil), body.Obligations...)
	broken.Obligations[0].AuthorizationPredicateIDs = []string{"predicate:buyer"}
	for index := range broken.AuthorizationPredicates {
		broken.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	if _, err := PrepareAgreementTargets(broken); err == nil {
		t.Fatal("obligation without obligor authority was accepted")
	}
}

func TestCompleteAgentEvidenceAuthorizesAgreement(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	body := validAgreementBody(t, now)
	digest, err := AgreementBodyDigest(body)
	if err != nil {
		t.Fatal(err)
	}
	keys := agreementKeyResolver{}
	agreement := AgentAgreement{Body: body}
	for _, predicate := range body.AuthorizationPredicates {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[predicate.AuthoritySubject.SubjectIdentifier] = publicKey
		acceptance, err := SignAgreementAcceptance(AgreementAcceptanceBody{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
			AcceptingSubject: predicate.AuthoritySubject, AcceptedRoles: predicate.RoleScope,
			PredicateIDs: []string{predicate.PredicateID}, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			ExpiresAtUnix: uint64(now.Add(time.Hour).Unix()),
		}, privateKey)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeSignedAgreementAcceptance(acceptance)
		if err != nil {
			t.Fatal(err)
		}
		agreement.AuthorizationEvidence = append(agreement.AuthorizationEvidence, AgreementAuthorizationEvidence{
			AgreementID: body.AgreementID, AgreementVersion: body.Version, AgreementBodyDigest: digest,
			AuthoritySubject: predicate.AuthoritySubject, PredicateIDs: []string{predicate.PredicateID},
			EvidenceProfileURI: predicate.EvidenceProfileURI, EvidenceProfileVersion: predicate.EvidenceProfileVersion,
			EvidenceProfileDigest: predicate.EvidenceProfileDigest, EvidenceTargetProjectionDigests: []string{predicate.EvidenceTargetProjectionDigest},
			EvidenceContentType: AgreementAcceptanceContentType, Evidence: encoded,
		})
	}
	if err := ValidateAgreementAuthorization(agreement, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err != nil {
		t.Fatal(err)
	}
	missing := agreement
	missing.AuthorizationEvidence = missing.AuthorizationEvidence[:1]
	if err := ValidateAgreementAuthorization(missing, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err == nil {
		t.Fatal("partially authorized Agreement was accepted")
	}
	replayed := agreement
	replayed.Body.Terms = []byte("different terms")
	for index := range replayed.Body.AuthorizationPredicates {
		replayed.Body.AuthorizationPredicates[index].EvidenceTargetProjectionDigest = ""
	}
	replayed.Body, err = PrepareAgreementTargets(replayed.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateAgreementAuthorization(replayed, AgentSignatureEvidenceVerifier{Resolver: keys}, now); err == nil {
		t.Fatal("evidence replayed onto another Agreement body")
	}
}
