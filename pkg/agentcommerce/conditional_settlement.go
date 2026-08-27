package agentcommerce

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type ProfileQualifiedSettlementParametersV1 struct {
	SchemaVersion            uint16       `json:"schema_version"`
	SettlementAdapterProfile ProfileRefV1 `json:"settlement_adapter_profile"`
	PayoutDestinationDigest  string       `json:"payout_destination_digest"`
	AdapterParameters        []byte       `json:"adapter_parameters"`
}

type ConditionalSettlementTemplateV1 struct {
	TemplateID                 string                                 `json:"template_id"`
	AgreementObligationID      string                                 `json:"agreement_obligation_id"`
	ConditionProfile           ProfileRefV1                           `json:"condition_profile"`
	AuthorizedDecisionProfile  ProfileRefV1                           `json:"authorized_decision_profile"`
	PayerAgentID               string                                 `json:"payer_agent_id"`
	PayeeAgentID               string                                 `json:"payee_agent_id"`
	Asset                      AssetIdentityV1                        `json:"asset"`
	MaximumPerInstance         AtomicAmountV1                         `json:"maximum_per_instance"`
	MaximumAggregateAmount     AtomicAmountV1                         `json:"maximum_aggregate_amount"`
	MaximumInstances           uint64                                 `json:"maximum_instances"`
	FirstSequence              uint64                                 `json:"first_sequence"`
	SettlementAdapterProfile   ProfileRefV1                           `json:"settlement_adapter_profile"`
	SettlementParameters       ProfileQualifiedSettlementParametersV1 `json:"settlement_parameters"`
	SettlementParametersDigest string                                 `json:"settlement_parameters_digest"`
	PayoutDestinationBinding   PayoutDestinationBindingV1             `json:"payout_destination_binding"`
	MaterializationDomain      string                                 `json:"materialization_domain"`
	CancellationPolicyDigest   string                                 `json:"cancellation_policy_digest"`
	DisputePolicyDigest        string                                 `json:"dispute_policy_digest"`
}

func ValidateProfileQualifiedSettlementParametersV1(parameters ProfileQualifiedSettlementParametersV1) error {
	if parameters.SchemaVersion != 1 || ValidateProfileRefV1(parameters.SettlementAdapterProfile) != nil ||
		!canonicalDigestPattern.MatchString(parameters.PayoutDestinationDigest) ||
		len(parameters.AdapterParameters) == 0 || len(parameters.AdapterParameters) > MaxProfilePayloadBytes {
		return errors.New("profile-qualified settlement parameters are invalid")
	}
	var canonical interface{}
	if err := codec.Unmarshal(parameters.AdapterParameters, &canonical); err != nil {
		return errors.New("settlement Adapter parameters are not canonical")
	}
	return nil
}

func SettlementParametersDigestV1(parameters ProfileQualifiedSettlementParametersV1) (string, error) {
	if err := ValidateProfileQualifiedSettlementParametersV1(parameters); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.agent-guarantor-settlement-parameters.v1", parameters)
}

func ValidateConditionalSettlementTemplateV1(template ConditionalSettlementTemplateV1) error {
	if !boundedIdentifier(template.TemplateID, 256) || !boundedIdentifier(template.AgreementObligationID, 128) ||
		ValidateProfileRefV1(template.ConditionProfile) != nil || ValidateProfileRefV1(template.AuthorizedDecisionProfile) != nil ||
		!boundedIdentifier(template.PayerAgentID, 256) || !boundedIdentifier(template.PayeeAgentID, 256) ||
		template.PayerAgentID == template.PayeeAgentID || ValidateAssetIdentityV1(template.Asset) != nil ||
		ValidateAtomicAmountV1(template.MaximumPerInstance, true) != nil ||
		ValidateAtomicAmountV1(template.MaximumAggregateAmount, true) != nil ||
		template.MaximumPerInstance.Asset != template.Asset || template.MaximumAggregateAmount.Asset != template.Asset ||
		compareCanonicalUnsigned(template.MaximumPerInstance.AmountAtomic, template.MaximumAggregateAmount.AmountAtomic) > 0 ||
		template.MaximumInstances == 0 || template.MaximumInstances > 1_000_000 || template.FirstSequence != 1 ||
		ValidateProfileRefV1(template.SettlementAdapterProfile) != nil ||
		ValidateProfileQualifiedSettlementParametersV1(template.SettlementParameters) != nil ||
		template.SettlementParameters.SettlementAdapterProfile != template.SettlementAdapterProfile ||
		!canonicalDigestPattern.MatchString(template.SettlementParametersDigest) ||
		ValidatePayoutDestinationBindingV1(template.PayoutDestinationBinding) != nil ||
		!boundedIdentifier(template.MaterializationDomain, 256) ||
		!canonicalDigestPattern.MatchString(template.CancellationPolicyDigest) ||
		!canonicalDigestPattern.MatchString(template.DisputePolicyDigest) {
		return errors.New("conditional settlement template is invalid")
	}
	destinationDigest, err := PayoutDestinationDigestV1(template.PayoutDestinationBinding.PayoutDestination)
	if err != nil || destinationDigest != template.SettlementParameters.PayoutDestinationDigest {
		return errors.New("conditional settlement destination digest mismatch")
	}
	wantParameters, err := SettlementParametersDigestV1(template.SettlementParameters)
	if err != nil || wantParameters != template.SettlementParametersDigest {
		return errors.New("conditional settlement parameters digest mismatch")
	}
	return nil
}

func ConditionalSettlementTemplateDigestV1(template ConditionalSettlementTemplateV1) (string, error) {
	if err := ValidateConditionalSettlementTemplateV1(template); err != nil {
		return "", err
	}
	return codec.Digest("tos.service.conditional-settlement-template.v1", template)
}

// DecodeConditionalSettlementTemplateV1 rejects permissive and noncanonical
// encodings before an Agreement verifier can use the template as authority.
func DecodeConditionalSettlementTemplateV1(canonical []byte) (ConditionalSettlementTemplateV1, error) {
	var template ConditionalSettlementTemplateV1
	if err := codec.Unmarshal(canonical, &template); err != nil {
		return template, err
	}
	if err := ValidateConditionalSettlementTemplateV1(template); err != nil {
		return template, err
	}
	reencoded, err := codec.Marshal(template)
	if err != nil || !bytes.Equal(reencoded, canonical) {
		return template, errors.New("conditional settlement template is not canonical")
	}
	return template, nil
}
