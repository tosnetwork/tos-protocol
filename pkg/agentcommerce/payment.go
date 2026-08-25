package agentcommerce

import (
	"errors"
	"time"

	"github.com/tosnetwork/tos-service-protocol/pkg/codec"
)

type AgreementPaymentRequest struct {
	SchemaVersion         uint16          `json:"schema_version"`
	OwnerID               string          `json:"owner_id"`
	AgentID               string          `json:"agent_id"`
	AgreementBodyDigest   string          `json:"agreement_body_digest"`
	AgreementObligationID string          `json:"agreement_obligation_id"`
	ObligationInstanceID  string          `json:"obligation_instance_id"`
	PayerAgentID          string          `json:"payer_agent_id"`
	PayeeAgentID          string          `json:"payee_agent_id"`
	NetworkID             string          `json:"network_id"`
	Amount                AgreementAmount `json:"amount"`
	Destination           []byte          `json:"destination"`
	SettlementAdapterURI  string          `json:"settlement_adapter_uri"`
	SemanticActionKind    string          `json:"semantic_action_kind,omitempty"`
	AdapterProfileDigest  string          `json:"adapter_profile_digest,omitempty"`
	ExternalSystemID      string          `json:"external_system_id,omitempty"`
	StableActionID        string          `json:"stable_action_id"`
	ExpiresAtUnix         uint64          `json:"expires_at_unix"`
}

type AgreementPaymentEvidence struct {
	PaymentRequestDigest   string `json:"payment_request_digest"`
	StableActionID         string `json:"stable_action_id"`
	ExactTransferReference string `json:"exact_transfer_reference"`
	AdapterEvidenceProfile string `json:"adapter_evidence_profile"`
	ResolvedState          string `json:"resolved_state"`
	ResolvedAtUnix         uint64 `json:"resolved_at_unix"`
	FinalityReference      string `json:"finality_reference"`
	Evidence               []byte `json:"evidence"`
}

type PaymentEvidenceVerifier interface {
	VerifyPaymentEvidence(AgreementPaymentRequest, AgreementPaymentEvidence, time.Time) error
}

func BuildAgreementPaymentRequest(ownerID, agentID, networkID string, destination []byte,
	obligation SettlementObligation) (AgreementPaymentRequest, error) {
	return BuildAgreementPaymentRequestAmount(ownerID, agentID, networkID, destination, obligation, obligation.Amount)
}

// BuildAgreementPaymentRequestAmount supports an exact partial payment while
// preserving the obligation's asset identity and never exceeding its amount.
func BuildAgreementPaymentRequestAmount(ownerID, agentID, networkID string, destination []byte,
	obligation SettlementObligation, requested AgreementAmount) (AgreementPaymentRequest, error) {
	if err := ValidateSettlementObligation(obligation); err != nil || !boundedIdentifier(ownerID, 256) || !boundedIdentifier(agentID, 256) ||
		!boundedIdentifier(networkID, 128) || len(destination) == 0 || len(destination) > 64<<10 || obligation.Amount.AmountAtomic == "" ||
		validateAgreementAmount(requested) != nil || requested.AssetNamespace != obligation.Amount.AssetNamespace ||
		requested.AssetIdentifier != obligation.Amount.AssetIdentifier || requested.Unit != obligation.Amount.Unit || requested.AmountAtomic == "" ||
		compareAmounts(requested, obligation.Amount) > 0 || amountIsZero(requested) {
		return AgreementPaymentRequest{}, errors.New("direct payment input is invalid")
	}
	assetDigest, err := codec.Digest("tos.agreement-payment-asset.v1", struct {
		Namespace  string `json:"namespace"`
		Identifier string `json:"identifier"`
		Unit       string `json:"unit"`
	}{obligation.Amount.AssetNamespace, obligation.Amount.AssetIdentifier, obligation.Amount.Unit})
	if err != nil {
		return AgreementPaymentRequest{}, err
	}
	destinationDigest, err := codec.Digest("tos.agreement-payment-destination.v1", struct {
		NetworkID   string `json:"network_id"`
		AdapterURI  string `json:"adapter_uri"`
		Destination []byte `json:"destination"`
	}{networkID, obligation.SettlementAdapterURI, destination})
	if err != nil {
		return AgreementPaymentRequest{}, err
	}
	fields := map[string]SemanticValue{"owner_id": ID(ownerID), "agent_id": ID(agentID),
		"agreement_body_digest": Digest32(obligation.AgreementBodyDigest), "obligation_instance_id": Digest32(obligation.ObligationInstanceID),
		"payer_id": ID(obligation.PayerAgentID), "payee_id": ID(obligation.PayeeAgentID), "network_id": ID(networkID),
		"asset_digest": Digest32(assetDigest), "amount_atomic": ID(requested.AmountAtomic), "destination_digest": Digest32(destinationDigest)}
	actionID, _, err := DeriveStableActionID("payment.direct", fields)
	if err != nil {
		return AgreementPaymentRequest{}, err
	}
	request := AgreementPaymentRequest{SchemaVersion: 1, OwnerID: ownerID, AgentID: agentID, AgreementBodyDigest: obligation.AgreementBodyDigest,
		AgreementObligationID: obligation.AgreementObligationID, ObligationInstanceID: obligation.ObligationInstanceID,
		PayerAgentID: obligation.PayerAgentID, PayeeAgentID: obligation.PayeeAgentID, NetworkID: networkID, Amount: requested,
		Destination: append([]byte(nil), destination...), SettlementAdapterURI: obligation.SettlementAdapterURI,
		StableActionID: actionID, ExpiresAtUnix: obligation.ExpiresAtUnix}
	if request.ExpiresAtUnix == 0 {
		return AgreementPaymentRequest{}, errors.New("direct payment requires an exact expiry")
	}
	return request, nil
}

// BuildExternalAgreementPaymentRequestAmount derives the distinct
// settlement.external identity. External systems use an amount digest and an
// owner-pinned Adapter profile/system identity, so a takeover implementation
// cannot accidentally retry the same payment under payment.direct.
func BuildExternalAgreementPaymentRequestAmount(ownerID, agentID, networkID, systemID,
	adapterProfileDigest string, destination []byte, obligation SettlementObligation,
	requested AgreementAmount) (AgreementPaymentRequest, error) {
	if err := ValidateSettlementObligation(obligation); err != nil || !boundedIdentifier(ownerID, 256) ||
		!boundedIdentifier(agentID, 256) || !boundedIdentifier(networkID, 128) || !boundedIdentifier(systemID, 256) ||
		!canonicalDigestPattern.MatchString(adapterProfileDigest) || len(destination) == 0 || len(destination) > 64<<10 ||
		validateAgreementAmount(requested) != nil || requested.AssetNamespace != obligation.Amount.AssetNamespace ||
		requested.AssetIdentifier != obligation.Amount.AssetIdentifier || requested.Unit != obligation.Amount.Unit ||
		compareAmounts(requested, obligation.Amount) > 0 || amountIsZero(requested) {
		return AgreementPaymentRequest{}, errors.New("external payment input is invalid")
	}
	assetDigest, amountDigest, destinationDigest, err := paymentComponentDigests(networkID, obligation.SettlementAdapterURI, destination, requested)
	if err != nil {
		return AgreementPaymentRequest{}, err
	}
	fields := map[string]SemanticValue{"owner_id": ID(ownerID), "agent_id": ID(agentID),
		"agreement_body_digest": Digest32(obligation.AgreementBodyDigest), "obligation_instance_id": Digest32(obligation.ObligationInstanceID),
		"adapter_profile_digest": Digest32(adapterProfileDigest), "payer_id": ID(obligation.PayerAgentID),
		"payee_id": ID(obligation.PayeeAgentID), "system_id": ID(systemID), "asset_digest": Digest32(assetDigest),
		"amount_digest": Digest32(amountDigest), "destination_digest": Digest32(destinationDigest)}
	actionID, _, err := DeriveStableActionID("settlement.external", fields)
	if err != nil {
		return AgreementPaymentRequest{}, err
	}
	request := AgreementPaymentRequest{SchemaVersion: 2, OwnerID: ownerID, AgentID: agentID,
		AgreementBodyDigest: obligation.AgreementBodyDigest, AgreementObligationID: obligation.AgreementObligationID,
		ObligationInstanceID: obligation.ObligationInstanceID, PayerAgentID: obligation.PayerAgentID, PayeeAgentID: obligation.PayeeAgentID,
		NetworkID: networkID, Amount: requested, Destination: append([]byte(nil), destination...),
		SettlementAdapterURI: obligation.SettlementAdapterURI, SemanticActionKind: "settlement.external",
		AdapterProfileDigest: adapterProfileDigest, ExternalSystemID: systemID, StableActionID: actionID,
		ExpiresAtUnix: obligation.ExpiresAtUnix}
	if request.ExpiresAtUnix == 0 {
		return AgreementPaymentRequest{}, errors.New("external payment requires an exact expiry")
	}
	return request, nil
}

func AgreementPaymentRequestDigest(request AgreementPaymentRequest) (string, error) {
	if err := ValidateAgreementPaymentRequest(request); err != nil {
		return "", err
	}
	return codec.Digest("tos.agreement-payment-request.v1", request)
}

func ValidateAgreementPaymentRequest(request AgreementPaymentRequest) error {
	if (request.SchemaVersion != 1 && request.SchemaVersion != 2) || !boundedIdentifier(request.OwnerID, 256) || !boundedIdentifier(request.AgentID, 256) ||
		!canonicalDigestPattern.MatchString(request.AgreementBodyDigest) || !boundedIdentifier(request.AgreementObligationID, 128) ||
		!canonicalDigestPattern.MatchString(request.ObligationInstanceID) || !boundedIdentifier(request.PayerAgentID, 256) ||
		!boundedIdentifier(request.PayeeAgentID, 256) || !boundedIdentifier(request.NetworkID, 128) || validateAgreementAmount(request.Amount) != nil ||
		request.Amount.AmountAtomic == "" || len(request.Destination) == 0 || len(request.Destination) > 64<<10 ||
		!boundedIdentifier(request.SettlementAdapterURI, 256) || !canonicalDigestPattern.MatchString(request.StableActionID) || request.ExpiresAtUnix == 0 {
		return errors.New("Agreement payment request is invalid")
	}
	if request.SchemaVersion == 1 && (request.SemanticActionKind != "" || request.AdapterProfileDigest != "" || request.ExternalSystemID != "") ||
		request.SchemaVersion == 2 && (request.SemanticActionKind != "settlement.external" ||
			!canonicalDigestPattern.MatchString(request.AdapterProfileDigest) || !boundedIdentifier(request.ExternalSystemID, 256)) {
		return errors.New("Agreement payment action profile is invalid")
	}
	assetDigest, _ := codec.Digest("tos.agreement-payment-asset.v1", struct {
		Namespace  string `json:"namespace"`
		Identifier string `json:"identifier"`
		Unit       string `json:"unit"`
	}{request.Amount.AssetNamespace, request.Amount.AssetIdentifier, request.Amount.Unit})
	destinationDigest, _ := codec.Digest("tos.agreement-payment-destination.v1", struct {
		NetworkID   string `json:"network_id"`
		AdapterURI  string `json:"adapter_uri"`
		Destination []byte `json:"destination"`
	}{request.NetworkID, request.SettlementAdapterURI, request.Destination})
	fields := map[string]SemanticValue{"owner_id": ID(request.OwnerID), "agent_id": ID(request.AgentID),
		"agreement_body_digest": Digest32(request.AgreementBodyDigest), "obligation_instance_id": Digest32(request.ObligationInstanceID),
		"payer_id": ID(request.PayerAgentID), "payee_id": ID(request.PayeeAgentID), "asset_digest": Digest32(assetDigest),
		"destination_digest": Digest32(destinationDigest)}
	kind := "payment.direct"
	if request.SchemaVersion == 1 {
		fields["network_id"] = ID(request.NetworkID)
		fields["amount_atomic"] = ID(request.Amount.AmountAtomic)
	} else {
		kind = request.SemanticActionKind
		amountDigest, _ := codec.Digest("tos.agreement-payment-amount.v1", request.Amount)
		fields["adapter_profile_digest"] = Digest32(request.AdapterProfileDigest)
		fields["system_id"] = ID(request.ExternalSystemID)
		fields["amount_digest"] = Digest32(amountDigest)
	}
	want, _, err := DeriveStableActionID(kind, fields)
	if err != nil || want != request.StableActionID {
		return errors.New("Agreement payment semantic identity mismatch")
	}
	return nil
}

// PaymentAuthorizationMaterial returns the exact request and semantic fields
// independently re-derived by Action Authority and custody.
func PaymentAuthorizationMaterial(request AgreementPaymentRequest) ([]byte, map[string]SemanticValue, error) {
	if err := ValidateAgreementPaymentRequest(request); err != nil {
		return nil, nil, err
	}
	assetDigest, _ := codec.Digest("tos.agreement-payment-asset.v1", struct {
		Namespace  string `json:"namespace"`
		Identifier string `json:"identifier"`
		Unit       string `json:"unit"`
	}{request.Amount.AssetNamespace, request.Amount.AssetIdentifier, request.Amount.Unit})
	destinationDigest, _ := codec.Digest("tos.agreement-payment-destination.v1", struct {
		NetworkID   string `json:"network_id"`
		AdapterURI  string `json:"adapter_uri"`
		Destination []byte `json:"destination"`
	}{request.NetworkID, request.SettlementAdapterURI, request.Destination})
	fields := map[string]SemanticValue{"owner_id": ID(request.OwnerID), "agent_id": ID(request.AgentID),
		"agreement_body_digest": Digest32(request.AgreementBodyDigest), "obligation_instance_id": Digest32(request.ObligationInstanceID),
		"payer_id": ID(request.PayerAgentID), "payee_id": ID(request.PayeeAgentID),
		"asset_digest": Digest32(assetDigest), "destination_digest": Digest32(destinationDigest)}
	if request.SchemaVersion == 1 {
		fields["network_id"] = ID(request.NetworkID)
		fields["amount_atomic"] = ID(request.Amount.AmountAtomic)
	} else {
		amountDigest, _ := codec.Digest("tos.agreement-payment-amount.v1", request.Amount)
		fields["adapter_profile_digest"] = Digest32(request.AdapterProfileDigest)
		fields["system_id"] = ID(request.ExternalSystemID)
		fields["amount_digest"] = Digest32(amountDigest)
	}
	canonical, err := codec.Marshal(request)
	return canonical, fields, err
}

func paymentComponentDigests(networkID, adapterURI string, destination []byte,
	amount AgreementAmount) (string, string, string, error) {
	assetDigest, err := codec.Digest("tos.agreement-payment-asset.v1", struct {
		Namespace  string `json:"namespace"`
		Identifier string `json:"identifier"`
		Unit       string `json:"unit"`
	}{amount.AssetNamespace, amount.AssetIdentifier, amount.Unit})
	if err != nil {
		return "", "", "", err
	}
	amountDigest, err := codec.Digest("tos.agreement-payment-amount.v1", amount)
	if err != nil {
		return "", "", "", err
	}
	destinationDigest, err := codec.Digest("tos.agreement-payment-destination.v1", struct {
		NetworkID   string `json:"network_id"`
		AdapterURI  string `json:"adapter_uri"`
		Destination []byte `json:"destination"`
	}{networkID, adapterURI, destination})
	return assetDigest, amountDigest, destinationDigest, err
}

func VerifyAgreementPaymentEvidence(request AgreementPaymentRequest, evidence AgreementPaymentEvidence,
	verifier PaymentEvidenceVerifier, now time.Time) error {
	if err := ValidateAgreementPaymentRequest(request); err != nil || verifier == nil || !now.UTC().Before(time.Unix(int64(request.ExpiresAtUnix), 0).UTC()) {
		return errors.New("Agreement payment verification context is invalid or expired")
	}
	digest, err := AgreementPaymentRequestDigest(request)
	if err != nil || evidence.PaymentRequestDigest != digest || evidence.StableActionID != request.StableActionID ||
		!boundedIdentifier(evidence.ExactTransferReference, 1024) || !boundedIdentifier(evidence.AdapterEvidenceProfile, 256) ||
		evidence.ResolvedState != "finalized" || evidence.ResolvedAtUnix == 0 || evidence.ResolvedAtUnix > uint64(now.Unix()) ||
		!boundedIdentifier(evidence.FinalityReference, 1024) || len(evidence.Evidence) == 0 || len(evidence.Evidence) > 1<<20 {
		return errors.New("Agreement payment evidence is invalid or unrelated")
	}
	return verifier.VerifyPaymentEvidence(request, evidence, now)
}
