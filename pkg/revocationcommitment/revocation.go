// Package revocationcommitment defines canonical, deterministic current-state
// revocation identities. Their digests are derivable from the historical fact
// being checked, allowing a fresh replica to perform read-only tuple recovery.
package revocationcommitment

import (
	"errors"
	"strings"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
)

const (
	SignerDomain  = "tos.atos.execution-signer-revocation.v2"
	BindingDomain = "tos.atos.principal-binding-revocation.v2"
)

type SignerValue struct {
	AuthorizationID string `json:"authorization_id"`
}

type BindingValue struct {
	PrincipalID   string `json:"principal_id"`
	AgentID       string `json:"agent_id"`
	BindingDigest string `json:"binding_digest"`
}

func SignerDigest(authorizationID string) (string, error) {
	if strings.TrimSpace(authorizationID) == "" {
		return "", errors.New("authorization_id is required")
	}
	return codec.Digest(SignerDomain, SignerValue{AuthorizationID: authorizationID})
}

func BindingDigest(principalID, agentID, bindingDigest string) (string, error) {
	if strings.TrimSpace(principalID) == "" || strings.TrimSpace(agentID) == "" || strings.TrimSpace(bindingDigest) == "" {
		return "", errors.New("complete principal binding revocation tuple is required")
	}
	return codec.Digest(BindingDomain, BindingValue{PrincipalID: principalID, AgentID: agentID, BindingDigest: bindingDigest})
}
