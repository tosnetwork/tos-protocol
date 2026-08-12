// Package quotecommitment owns the versioned canonical Verified Quote value.
package quotecommitment

import (
	"errors"
	"fmt"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"google.golang.org/protobuf/reflect/protoreflect"
)

const (
	Version          = "atos_verified_quote_commitment_v1"
	Canonicalization = "rfc8949_core_deterministic_cbor"
	Domain           = "tos.atos.verified-quote-commitment.v1"
)

type reference struct {
	Network   string `json:"network"`
	Reference string `json:"reference"`
}
type money struct {
	Amount string `json:"amount"`
	Asset  string `json:"asset"`
}
type Value struct {
	Version                      string    `json:"version"`
	Canonicalization             string    `json:"canonicalization"`
	NetworkID                    string    `json:"network_id"`
	Domain                       string    `json:"domain"`
	QuoteID                      string    `json:"quote_id"`
	PrincipalID                  string    `json:"principal_id"`
	RequesterAgentID             string    `json:"requester_agent_id"`
	ProviderID                   string    `json:"provider_id"`
	CapabilityID                 string    `json:"capability_id"`
	CapabilityVersion            string    `json:"capability_version"`
	ManifestDigest               string    `json:"manifest_digest"`
	OwnershipRef                 reference `json:"ownership_ref"`
	TrustMode                    string    `json:"trust_mode"`
	ProofProfile                 string    `json:"proof_profile"`
	Subtotal                     money     `json:"subtotal"`
	Fees                         money     `json:"fees"`
	TotalMax                     money     `json:"total_max"`
	AssetDecimals                uint32    `json:"asset_decimals"`
	TermsDigest                  string    `json:"terms_digest"`
	DisputePolicyDigest          string    `json:"dispute_policy_digest"`
	AcceptanceDeadlineUnixMillis int64     `json:"acceptance_deadline_unix_millis"`
	ExpiresUnixMillis            int64     `json:"expires_unix_millis"`
	ExecutionDeadlineUnixMillis  int64     `json:"execution_deadline_unix_millis"`
	SettlementBackend            string    `json:"settlement_backend"`
	SettlementAsset              string    `json:"settlement_asset"`
	UnderlyingServiceQuoteRef    string    `json:"underlying_service_quote_ref"`
	SignerAuthorizationID        string    `json:"signer_authorization_id"`
	SignerAuthorizationRef       reference `json:"signer_authorization_ref"`
}

func textDigest(v *atostosv1.Digest) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%s:%x", v.Algorithm, v.Value)
}
func ref(v *atostosv1.NetworkReference) reference {
	if v == nil {
		return reference{}
	}
	return reference{Network: v.Network, Reference: v.Reference}
}
func cash(v *atostosv1.Money) money {
	if v == nil {
		return money{}
	}
	return money{Amount: v.Amount, Asset: v.Currency}
}

func CanonicalValue(v *atostosv1.QuoteCommitmentInput) (Value, error) {
	if v == nil {
		return Value{}, errors.New("quote commitment is required")
	}
	if err := RejectUnknown(v); err != nil {
		return Value{}, err
	}
	return Value{Version: v.Version, Canonicalization: v.Canonicalization, NetworkID: v.NetworkId, Domain: v.Domain, QuoteID: v.QuoteId, PrincipalID: v.PrincipalId, RequesterAgentID: v.RequesterAgentId, ProviderID: v.ProviderId, CapabilityID: v.CapabilityId, CapabilityVersion: v.CapabilityVersion, ManifestDigest: textDigest(v.ManifestDigest), OwnershipRef: ref(v.OwnershipRef), TrustMode: v.TrustMode.String(), ProofProfile: v.ProofProfile.String(), Subtotal: cash(v.Subtotal), Fees: cash(v.Fees), TotalMax: cash(v.TotalMax), AssetDecimals: v.AssetDecimals, TermsDigest: textDigest(v.TermsDigest), DisputePolicyDigest: textDigest(v.DisputePolicyDigest), AcceptanceDeadlineUnixMillis: v.AcceptanceDeadlineUnixMillis, ExpiresUnixMillis: v.ExpiresUnixMillis, ExecutionDeadlineUnixMillis: v.ExecutionDeadlineUnixMillis, SettlementBackend: v.SettlementBackend, SettlementAsset: v.SettlementAsset, UnderlyingServiceQuoteRef: v.UnderlyingServiceQuoteRef, SignerAuthorizationID: v.SignerAuthorizationId, SignerAuthorizationRef: ref(v.SignerAuthorizationRef)}, nil
}
func Bytes(v *atostosv1.QuoteCommitmentInput) ([]byte, error) {
	value, err := CanonicalValue(v)
	if err != nil {
		return nil, err
	}
	return codec.Marshal(value)
}
func Parse(data []byte) (Value, error) {
	var value Value
	if err := codec.Unmarshal(data, &value); err != nil {
		return Value{}, err
	}
	return value, nil
}
func Digest(v *atostosv1.QuoteCommitmentInput) (string, error) {
	value, err := CanonicalValue(v)
	if err != nil {
		return "", err
	}
	return codec.Digest(Domain, value)
}

func RejectUnknown(message protoreflect.ProtoMessage) error {
	if message == nil {
		return errors.New("message is required")
	}
	return reject(message.ProtoReflect())
}
func reject(m protoreflect.Message) error {
	if len(m.GetUnknown()) != 0 {
		return errors.New("protobuf unknown fields are forbidden")
	}
	var found error
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}
		if fd.IsList() {
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				if err := reject(list.Get(i).Message()); err != nil {
					found = err
					return false
				}
			}
		} else if fd.IsMap() {
			if fd.MapValue().Kind() == protoreflect.MessageKind {
				mp := v.Map()
				mp.Range(func(_ protoreflect.MapKey, mv protoreflect.Value) bool {
					if err := reject(mv.Message()); err != nil {
						found = err
						return false
					}
					return true
				})
			}
		} else if m.Has(fd) {
			found = reject(v.Message())
		}
		return found == nil
	})
	return found
}
