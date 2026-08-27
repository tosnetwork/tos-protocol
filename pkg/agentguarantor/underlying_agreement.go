package agentguarantor

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/agentcommerce"
)

// UnderlyingAgreementResolver returns the complete, authorization-bearing
// Agreement committed by digest. Implementations must resolve immutable
// content, not a mutable database row or a caller-selected projection.
type UnderlyingAgreementResolver interface {
	ResolveUnderlyingAgreement(bodyDigest string) (agentcommerce.AgentAgreement, error)
}

// VerifyCoveredUnderlyingAgreementV1 derives third-party status from the
// complete Agreement. A Guarantor request cannot create coverage for a missing
// obligation, an obligation of another covered party, or its own obligation.
func VerifyCoveredUnderlyingAgreementV1(agreement agentcommerce.AgentAgreement, expectedDigest,
	coveredPartyAgentID, guarantorAgentID string, coveredObligationIDs []string,
	verifier agentcommerce.AgreementEvidenceVerifier, now time.Time) error {
	if verifier == nil || !validDigest(expectedDigest) || !validID(coveredPartyAgentID) ||
		!validID(guarantorAgentID) || coveredPartyAgentID == guarantorAgentID ||
		!sortedUnique(coveredObligationIDs, 256, func(value string) bool { return validToken(value, 128) }) {
		return errors.New("covered underlying Agreement context is invalid")
	}
	digest, err := agentcommerce.AgreementBodyDigest(agreement.Body)
	if err != nil || digest != expectedDigest ||
		agentcommerce.ValidateAgreementAuthorization(agreement, verifier, now) != nil {
		return errors.New("covered underlying Agreement is absent, substituted, or unauthorized")
	}
	obligations := make(map[string]agentcommerce.AgreementObligation, len(agreement.Body.Obligations))
	for _, obligation := range agreement.Body.Obligations {
		obligations[obligation.ObligationID] = obligation
	}
	for _, obligationID := range coveredObligationIDs {
		obligation, found := obligations[obligationID]
		if !found || obligation.ObligorAgentID != coveredPartyAgentID ||
			obligation.ObligorAgentID == guarantorAgentID {
			return errors.New("covered obligation is missing or is not a third-party obligation")
		}
	}
	return nil
}

func resolveAndVerifyCoveredUnderlyingAgreementV1(resolver UnderlyingAgreementResolver,
	agreementVerifier agentcommerce.AgreementEvidenceVerifier, digest, coveredPartyAgentID,
	guarantorAgentID string, obligationIDs []string, now time.Time) error {
	if resolver == nil {
		return errors.New("complete underlying Agreement resolver is unavailable")
	}
	agreement, err := resolver.ResolveUnderlyingAgreement(digest)
	if err != nil {
		return errors.New("complete underlying Agreement cannot be resolved")
	}
	return VerifyCoveredUnderlyingAgreementV1(agreement, digest, coveredPartyAgentID,
		guarantorAgentID, obligationIDs, agreementVerifier, now)
}
