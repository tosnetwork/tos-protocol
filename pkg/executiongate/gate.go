// Package executiongate verifies finalized Native commercial authority and
// atomically binds one paid escrow to one exact provider execution intent.
package executiongate

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	nativev1 "github.com/tosnetwork/tos-service-protocol/gen/tos/service/v1"
	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tos-service-protocol/pkg/toschain"
	"google.golang.org/protobuf/proto"
)

type EscrowResolver interface {
	ResolveFinalized(context.Context, string) (*toschain.FinalizedEscrowV1, bool, error)
}

type NativeResolver interface {
	ResolveFinalizedState(context.Context, string, string) (*nativev1.NativeStateV1, bool, time.Time, error)
}

type Config struct {
	Directory                    string
	EscrowResolver               EscrowResolver
	NativeResolver               NativeResolver
	Network                      *nativev1.NetworkDomain
	RegistryCodeHash             string
	ProviderAgentID              string
	ProviderAddress              string
	ManifestDigest               string
	TransportDigest              string
	ExecutionSignerAuthorization string
	Timeout                      time.Duration
	Now                          func() time.Time
}

type Gate struct {
	store         *store
	escrow        EscrowResolver
	native        NativeResolver
	network       *nativev1.NetworkDomain
	registryHash  string
	providerAgent string
	provider      string
	manifest      string
	transport     string
	signerAuth    string
	timeout       time.Duration
	now           func() time.Time
}

// Request is the transport-independent execution identity. The same funded
// Quote and escrow may be claimed by exactly one complete request.
type Request struct {
	EscrowAddress   string `json:"escrow_address"`
	QuoteCommitment string `json:"quote_commitment"`
	ExecutionID     string `json:"execution_id"`
	InputDigest     string `json:"input_digest"`
	SourceDigest    string `json:"source_digest"`
}

// Evidence records the finalized chain authority used when admitting work.
type Evidence struct {
	NetworkID                     string `json:"network_id"`
	ProviderAgentID               string `json:"provider_agent_id"`
	ProviderAddress               string `json:"provider_address"`
	CapabilityID                  string `json:"capability_id"`
	CapabilityVersion             string `json:"capability_version"`
	ManifestDigest                string `json:"manifest_digest"`
	QuoteCommitment               string `json:"quote_commitment"`
	EscrowAddress                 string `json:"escrow_address"`
	EscrowCodeHash                string `json:"escrow_code_hash"`
	RegistryCodeHash              string `json:"registry_code_hash"`
	EscrowTransactionHash         string `json:"escrow_transaction_hash"`
	AgentTransactionHash          string `json:"agent_transaction_hash"`
	CapabilityTransactionHash     string `json:"capability_transaction_hash"`
	EscrowFinalizedCheckpoint     uint64 `json:"escrow_finalized_checkpoint"`
	AgentFinalizedCheckpoint      uint64 `json:"agent_finalized_checkpoint"`
	CapabilityFinalizedCheckpoint uint64 `json:"capability_finalized_checkpoint"`
}

func New(c Config) (*Gate, error) {
	if c.EscrowResolver == nil || c.NativeResolver == nil || c.Network == nil ||
		c.Network.NetworkId == "" || !cellDigest(c.RegistryCodeHash) ||
		!agentID(c.ProviderAgentID) || !rawAddress(c.ProviderAddress) ||
		!shaDigest(c.ManifestDigest) || !shaDigest(c.TransportDigest) ||
		!shaDigest(c.ExecutionSignerAuthorization) {
		return nil, errors.New("invalid execution gate configuration")
	}
	if c.Timeout == 0 {
		c.Timeout = 30 * time.Second
	}
	if c.Timeout < time.Second || c.Timeout > 5*time.Minute {
		return nil, errors.New("invalid execution gate timeout")
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	s, err := newStore(c.Directory)
	if err != nil {
		return nil, err
	}
	return &Gate{
		store: s, escrow: c.EscrowResolver, native: c.NativeResolver,
		network: proto.Clone(c.Network).(*nativev1.NetworkDomain), registryHash: c.RegistryCodeHash,
		providerAgent: c.ProviderAgentID, provider: c.ProviderAddress, manifest: c.ManifestDigest,
		transport: c.TransportDigest, signerAuth: c.ExecutionSignerAuthorization,
		timeout: c.Timeout, now: c.Now,
	}, nil
}

func (g *Gate) ClaimExecution(ctx context.Context, r Request) (Evidence, error) {
	if g == nil || ctx == nil || !rawAddress(r.EscrowAddress) ||
		!cellDigest(r.QuoteCommitment) || !shaDigest(r.ExecutionID) ||
		!shaDigest(r.InputDigest) || !shaDigest(r.SourceDigest) {
		return Evidence{}, errors.New("invalid execution claim")
	}
	call, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()

	escrow, found, err := g.escrow.ResolveFinalized(call, r.EscrowAddress)
	if err != nil {
		return Evidence{}, err
	}
	now := g.now()
	if now.Unix() < 0 || !found || escrow == nil || escrow.State == nil ||
		!validReference(escrow.Reference, "") || escrow.State.Status != nativecore.EscrowStatusFunded ||
		escrow.State.QuoteCommitment != r.QuoteCommitment || escrow.State.ProviderAddress != g.provider ||
		escrow.State.RefundAvailableAt <= uint64(now.Unix()) {
		return Evidence{}, errors.New("escrow is not an executable finalized purchase")
	}

	quote, err := nativecore.DecodeAcceptedQuoteV1(escrow.State.AcceptedQuote, g.network)
	if err != nil {
		return Evidence{}, err
	}
	p := quote.Proposal
	if p.ProviderAgentId != g.providerAgent || p.ManifestDigest != g.manifest ||
		p.TransportBindingDigest != g.transport || quote.ExecutionSignerAuthorization != g.signerAuth ||
		p.MaximumPrice == nil || p.MaximumPrice.AtomicAmount != escrow.State.FundedAtomicAmount {
		return Evidence{}, errors.New("Accepted Quote does not match provider execution policy")
	}

	agentState, err := g.resolveNative(call, g.providerAgent, now)
	if err != nil {
		return Evidence{}, err
	}
	agent := agentState.GetAgent()
	if agent == nil || agent.AgentId != g.providerAgent || agent.Tombstoned {
		return Evidence{}, errors.New("provider Agent is absent or tombstoned")
	}

	capabilityState, err := g.resolveNative(call, p.CapabilityId, now)
	if err != nil {
		return Evidence{}, err
	}
	capability := capabilityState.GetCapability()
	if capability == nil || capability.CapabilityId != p.CapabilityId ||
		capability.OwnerAgentId != g.providerAgent || capability.Tombstoned {
		return Evidence{}, errors.New("Capability no longer authorizes provider execution")
	}
	active := false
	for _, v := range capability.Versions {
		if v != nil && v.Version == p.CapabilityVersion && v.ManifestDigest == g.manifest && !v.Revoked {
			active = true
		}
	}
	if !active {
		return Evidence{}, errors.New("Capability version is absent or revoked")
	}

	e := Evidence{
		NetworkID: g.network.NetworkId, ProviderAgentID: g.providerAgent, ProviderAddress: g.provider,
		CapabilityID: p.CapabilityId, CapabilityVersion: p.CapabilityVersion, ManifestDigest: g.manifest,
		QuoteCommitment: r.QuoteCommitment, EscrowAddress: r.EscrowAddress,
		EscrowCodeHash: escrow.Reference.ContractCodeHash, RegistryCodeHash: g.registryHash,
		EscrowTransactionHash:         escrow.Reference.TransactionHash,
		AgentTransactionHash:          agentState.Reference.TransactionHash,
		CapabilityTransactionHash:     capabilityState.Reference.TransactionHash,
		EscrowFinalizedCheckpoint:     escrow.Reference.FinalizedCheckpoint,
		AgentFinalizedCheckpoint:      agentState.Reference.FinalizedCheckpoint,
		CapabilityFinalizedCheckpoint: capabilityState.Reference.FinalizedCheckpoint,
	}
	if err := g.store.claim(r, e); err != nil {
		return Evidence{}, err
	}
	return e, nil
}

func (g *Gate) resolveNative(ctx context.Context, objectID string, now time.Time) (*nativev1.NativeStateV1, error) {
	state, found, finalizedAt, err := g.native.ResolveFinalizedState(ctx, objectID, "")
	if err != nil {
		return nil, err
	}
	if !found || state == nil || finalizedAt.IsZero() || finalizedAt.After(now.Add(time.Minute)) ||
		!validReference(state.Reference, g.registryHash) ||
		!cellDigest(state.TvmStateHash) || !proto.Equal(state.Network, g.network) {
		return nil, errors.New("object is not valid finalized Native state")
	}
	return state, nil
}

func validReference(r *nativev1.ChainReference, expectedCodeHash string) bool {
	return r != nil && r.FinalizedCheckpoint > 0 && cellDigest(r.ContractCodeHash) &&
		(expectedCodeHash == "" || r.ContractCodeHash == expectedCodeHash) && shaDigest(r.TransactionHash)
}

func validDigest(v, prefix string) bool {
	if len(v) != len(prefix)+64 || !strings.HasPrefix(v, prefix) || v != strings.ToLower(v) {
		return false
	}
	b, err := hex.DecodeString(v[len(prefix):])
	return err == nil && !bytes.Equal(b, make([]byte, 32))
}

func shaDigest(v string) bool  { return validDigest(v, "sha256:") }
func cellDigest(v string) bool { return validDigest(v, "tvm-cell-sha256:") }
func agentID(v string) bool {
	return len(v) == 70 && strings.HasPrefix(v, "agent_") && validDigest("sha256:"+v[6:], "sha256:")
}
func rawAddress(v string) bool {
	wc, id, ok := strings.Cut(v, ":")
	return ok && wc == "0" && len(id) == 64 && validDigest("sha256:"+id, "sha256:")
}
