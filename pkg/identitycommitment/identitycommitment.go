// Package identitycommitment owns the canonical, privacy-safe identity and
// principal-binding tuples used for TOS-backed read-only recovery.
package identitycommitment

import (
	"errors"
	"strings"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

const (
	IdentityDomain = "tos.atos.agent-identity.v2"
	BindingDomain  = "tos.atos.principal-binding.v2"
)

type IdentityValue struct {
	AgentID      string   `json:"agent_id"`
	CanonicalURI string   `json:"canonical_uri"`
	Controllers  []string `json:"controllers"`
	Assurance    string   `json:"assurance"`
}

type BindingValue struct {
	PrincipalID string `json:"principal_id"`
	AgentID     string `json:"agent_id"`
}

func IdentityDigest(identity *atostosv1.AgentIdentity) (string, error) {
	if identity == nil || strings.TrimSpace(identity.AgentId) == "" || strings.TrimSpace(identity.CanonicalUri) == "" || strings.TrimSpace(identity.Assurance) == "" || len(identity.Controllers) == 0 {
		return "", errors.New("complete agent identity tuple is required")
	}
	controllers := append([]string(nil), identity.Controllers...)
	for _, controller := range controllers {
		if strings.TrimSpace(controller) == "" {
			return "", errors.New("complete agent identity controllers are required")
		}
	}
	return codec.Digest(IdentityDomain, IdentityValue{AgentID: identity.AgentId, CanonicalURI: identity.CanonicalUri, Controllers: controllers, Assurance: identity.Assurance})
}

func BindingDigest(principalID, agentID string) (string, error) {
	if strings.TrimSpace(principalID) == "" || strings.TrimSpace(agentID) == "" {
		return "", errors.New("complete principal binding tuple is required")
	}
	return codec.Digest(BindingDomain, BindingValue{PrincipalID: principalID, AgentID: agentID})
}
