package atosrpc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) economicPartiesTx(
	tx *bolt.Tx,
	principalID, providerID string,
) (creator, agent string, err error) {
	if tx == nil || s == nil || s.economy == nil {
		return "", "", errors.New("economic driver is unavailable")
	}
	boundAgent := tx.Bucket(bucketPrincipalBindings).Get([]byte(principalID))
	if boundAgent == nil {
		return "", "", failedPrecondition("PRINCIPAL_NOT_BOUND", "principal has no TOS identity binding")
	}
	principalIdentity := new(atostosv1.AgentIdentity)
	found, err := s.store.getProto(tx, bucketIdentities, string(boundAgent), principalIdentity)
	if err != nil {
		return "", "", err
	}
	if !found {
		return "", "", failedPrecondition("PRINCIPAL_NOT_BOUND", "principal TOS identity is unavailable")
	}
	providerIdentity := new(atostosv1.AgentIdentity)
	found, err = s.store.getProto(tx, bucketIdentities, providerID, providerIdentity)
	if err != nil {
		return "", "", err
	}
	if !found {
		return "", "", failedPrecondition("PROVIDER_IDENTITY_UNAVAILABLE", "provider TOS identity is unavailable")
	}
	creator, err = verifiedTOSController(principalIdentity, s.authority.Network())
	if err != nil {
		return "", "", failedPrecondition("PRINCIPAL_NOT_BOUND", err.Error())
	}
	agent, err = verifiedTOSController(providerIdentity, s.authority.Network())
	if err != nil {
		return "", "", failedPrecondition("PROVIDER_IDENTITY_UNAVAILABLE", err.Error())
	}
	return creator, agent, nil
}

func verifiedTOSController(identity *atostosv1.AgentIdentity, network string) (string, error) {
	if identity == nil || strings.TrimSpace(identity.Assurance) == "" ||
		strings.EqualFold(strings.TrimSpace(identity.Assurance), "self_asserted") ||
		identity.IdentityRef == nil || identity.IdentityRef.Network != network ||
		strings.TrimSpace(identity.IdentityRef.Reference) == "" ||
		strings.HasPrefix(identity.IdentityRef.Reference, "atosrpc:self-asserted:") {
		return "", errors.New("TOS identity is not independently anchored")
	}
	return uniqueTOSController(identity)
}

func uniqueTOSController(identity *atostosv1.AgentIdentity) (string, error) {
	if identity == nil {
		return "", errors.New("TOS identity is missing")
	}
	unique := make(map[string]struct{})
	for _, controller := range identity.Controllers {
		canonical, err := toschain.CanonicalAddress(strings.TrimSpace(controller))
		if err == nil {
			unique[canonical] = struct{}{}
		}
	}
	if len(unique) != 1 {
		return "", errors.New("TOS identity must contain exactly one canonical account controller")
	}
	for controller := range unique {
		return controller, nil
	}
	return "", errors.New("TOS identity controller is unavailable")
}

func digestString(value *atostosv1.Digest) (string, error) {
	if err := validateDigest(value); err != nil {
		return "", err
	}
	return "sha256:" + fmt.Sprintf("%x", value.Value), nil
}

func economicContractAddress(reference *NetworkReference) (string, error) {
	if reference == nil || strings.TrimSpace(reference.Reference) == "" {
		return "", errors.New("economic escrow reference is missing")
	}
	return toschain.ParseTaskEscrowReference(reference.Reference)
}

func economicNetworkReference(network, reference string) *NetworkReference {
	if strings.TrimSpace(reference) == "" {
		return nil
	}
	return &NetworkReference{Network: network, Reference: reference}
}

func economicRPCError(err error, operation string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return unavailable("ECONOMIC_DRIVER_UNAVAILABLE", operation+" did not reach finalized TOS state")
	}
	return failedPrecondition("ECONOMIC_TRANSITION_FAILED", operation+": "+err.Error())
}

func (s *Server) acceptEconomicEscrow(
	ctx context.Context,
	escrowID, providerID string,
) error {
	if s == nil || s.economy == nil {
		return failedPrecondition("TRUST_MODE_UNAVAILABLE", "contract economic driver is unavailable")
	}
	var escrow atostosv1.Escrow
	var agent string
	err := s.store.view(func(tx *bolt.Tx) error {
		found, err := s.store.getProto(tx, bucketEscrows, escrowID, &escrow)
		if err != nil {
			return err
		}
		if !found || escrow.ProviderId != providerID || escrow.TrustMode != TrustModeVerified {
			return failedPrecondition("ESCROW_MISMATCH", "Verified escrow does not match provider")
		}
		identity := new(atostosv1.AgentIdentity)
		found, err = s.store.getProto(tx, bucketIdentities, providerID, identity)
		if err != nil {
			return err
		}
		if !found {
			return failedPrecondition("PROVIDER_IDENTITY_UNAVAILABLE", "provider TOS identity is unavailable")
		}
		agent, err = verifiedTOSController(identity, s.authority.Network())
		return err
	})
	if err != nil {
		return err
	}
	contractAddress, err := economicContractAddress(escrow.EscrowRef)
	if err != nil {
		return failedPrecondition("ESCROW_MISMATCH", err.Error())
	}
	_, err = s.economy.AcceptEscrow(ctx, economic.AcceptEscrowRequest{
		EscrowID: escrow.EscrowId, ContractAddress: contractAddress,
		ExpectedAgent: agent,
	})
	return economicRPCError(err, "accept TOS Task Escrow")
}
