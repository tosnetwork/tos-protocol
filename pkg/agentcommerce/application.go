package agentcommerce

import (
	"bytes"
	"errors"
	"unicode/utf8"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

const IntentApplicationContentType = "application/vnd.tos.intent-application.v1+cbor"

// IntentApplication is authenticated negotiation input, not Agreement or
// payment authority. It binds a first contact to one signed Intent while
// keeping the later canonical Agreement promotion explicit.
type IntentApplication struct {
	SchemaVersion       uint16                 `json:"schema_version"`
	IntentDigest        string                 `json:"intent_digest"`
	IntentIssuerAgentID string                 `json:"intent_issuer_agent_id"`
	ApplicantAgentID    string                 `json:"applicant_agent_id"`
	Message             string                 `json:"message"`
	CapabilityHints     []CapabilityHint       `json:"capability_hints,omitempty"`
	SettlementOffers    []SettlementPreference `json:"settlement_offers,omitempty"`
	ProposedAmount      *AgreementAmount       `json:"proposed_amount,omitempty"`
	PaymentDestination  []byte                 `json:"payment_destination,omitempty"`
	// ProposedAgreementBody is an optional, non-authorizing generic graph. It
	// lets OFFER, SELL, EXCHANGE, COLLABORATE, and complex REQUEST applications
	// express arbitrary business-neutral obligations without adding a workflow
	// API per trade type. Authority still requires later typed evidence.
	ProposedAgreementBody *AgentAgreementBody `json:"proposed_agreement_body,omitempty"`
	ExpiresAtUnix         uint64              `json:"expires_at_unix"`
}

func ValidateIntentApplication(application IntentApplication) error {
	if (application.SchemaVersion != 1 && application.SchemaVersion != 2) || !canonicalDigestPattern.MatchString(application.IntentDigest) ||
		!boundedIdentifier(application.IntentIssuerAgentID, 256) || !boundedIdentifier(application.ApplicantAgentID, 256) ||
		application.IntentIssuerAgentID == application.ApplicantAgentID || len(application.Message) == 0 || len(application.Message) > 16<<10 ||
		!utf8.ValidString(application.Message) || len(application.CapabilityHints) > MaxIntentCapabilityHints ||
		len(application.SettlementOffers) > MaxIntentSettlementProfiles || len(application.PaymentDestination) > 4096 || application.ExpiresAtUnix == 0 {
		return errors.New("Intent application is invalid or unbounded")
	}
	previousCapability := ""
	for _, hint := range application.CapabilityHints {
		key := hint.CapabilityNamespace + "\x00" + hint.CapabilityIdentifier + "\x00" + hint.Relation
		if key <= previousCapability || !boundedIdentifier(hint.Relation, 64) || !boundedIdentifier(hint.CapabilityNamespace, 128) ||
			!boundedIdentifier(hint.CapabilityIdentifier, 256) {
			return errors.New("Intent application capabilities are invalid, unsorted, or duplicated")
		}
		previousCapability = key
	}
	previousAdapter := ""
	for _, offer := range application.SettlementOffers {
		if !boundedIdentifier(offer.AdapterURI, 256) || len(offer.Parameters) > 4096 || offer.AdapterURI <= previousAdapter {
			return errors.New("Intent application settlement offers are invalid, unsorted, or duplicated")
		}
		previousAdapter = offer.AdapterURI
	}
	if application.ProposedAmount != nil && validateAgreementAmount(*application.ProposedAmount) != nil {
		return errors.New("Intent application proposed amount is invalid")
	}
	if application.ProposedAgreementBody != nil {
		if application.SchemaVersion != 2 || ValidateAgreementBody(*application.ProposedAgreementBody) != nil {
			return errors.New("Intent application proposed Agreement is invalid")
		}
	} else if application.SchemaVersion == 2 {
		return errors.New("V2 Intent application lacks its generic Agreement proposal")
	}
	return nil
}

func CanonicalIntentApplication(application IntentApplication) ([]byte, error) {
	if err := ValidateIntentApplication(application); err != nil {
		return nil, err
	}
	return codec.Marshal(application)
}

func DecodeIntentApplication(canonical []byte) (IntentApplication, error) {
	var application IntentApplication
	if err := codec.Unmarshal(canonical, &application); err != nil {
		return application, err
	}
	if err := ValidateIntentApplication(application); err != nil {
		return application, err
	}
	reencoded, err := codec.Marshal(application)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return application, errors.New("Intent application is not canonical")
	}
	return application, nil
}
