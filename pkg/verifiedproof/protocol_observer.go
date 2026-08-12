package verifiedproof

import (
	"context"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/gen/atos/tos/v1/atostosv1connect"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/poscommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
)

// ProtocolObserver uses only the public, read-only tos-protocol RPC surface.
// Each RPC performs live authority/TaskEscrow observation; this observer has
// no ATOS database or publisher/mutation dependency.
type ProtocolObserver struct {
	token      string
	identity   atostosv1connect.IdentityServiceClient
	capability atostosv1connect.CapabilityServiceClient
	trust      atostosv1connect.TrustServiceClient
	settlement atostosv1connect.SettlementServiceClient
	proof      atostosv1connect.ProofServiceClient
}

func NewProtocolObserver(baseURL, token string) (*ProtocolObserver, error) {
	if strings.TrimSpace(baseURL) == "" || strings.TrimSpace(token) == "" {
		return nil, errors.New("protocol observer URL and token are required")
	}
	c := &http.Client{Timeout: 25 * time.Second}
	return &ProtocolObserver{token: token, identity: atostosv1connect.NewIdentityServiceClient(c, baseURL), capability: atostosv1connect.NewCapabilityServiceClient(c, baseURL), trust: atostosv1connect.NewTrustServiceClient(c, baseURL), settlement: atostosv1connect.NewSettlementServiceClient(c, baseURL), proof: atostosv1connect.NewProofServiceClient(c, baseURL)}, nil
}
func (o *ProtocolObserver) decorate(r connect.AnyRequest) {
	r.Header().Set("Authorization", "Bearer "+o.token)
}
func observerContext() *atostosv1.RequestContext {
	return &atostosv1.RequestContext{RequestId: "portable-proof-" + time.Now().UTC().Format("20060102150405.000000000"), CallerId: "independent-verifier", DeadlineUnixMillis: time.Now().Add(20 * time.Second).UnixMilli()}
}
func protoRef(r Reference) *atostosv1.NetworkReference {
	return &atostosv1.NetworkReference{Network: r.Network, Reference: r.Reference, Finalized: true, FinalizedCheckpoint: r.FinalizedCheckpoint}
}
func protoDigestText(s string) *atostosv1.Digest {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	b, e := hex.DecodeString(parts[1])
	if e != nil {
		return nil
	}
	return &atostosv1.Digest{Algorithm: parts[0], Value: b}
}
func observation(r EvidenceRequest, ref *atostosv1.NetworkReference) (EvidenceObservation, error) {
	if ref == nil || !ref.Finalized || ref.FinalizedCheckpoint == 0 || ref.Network != r.Reference.Network || ref.Reference != r.Reference.Reference {
		return EvidenceObservation{}, errors.New("live evidence reference mismatch")
	}
	return EvidenceObservation{Found: true, Network: ref.Network, Kind: r.Kind, ObjectID: r.ObjectID, Digest: r.Digest, Reference: ref.Reference, Finalized: true, FinalizedCheckpoint: ref.FinalizedCheckpoint}, nil
}

func (o *ProtocolObserver) Observe(ctx context.Context, r EvidenceRequest) (EvidenceObservation, error) {
	if o == nil || r.Package == nil {
		return EvidenceObservation{}, errors.New("complete proof package is required")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	p := r.Package
	switch r.Kind {
	case "identity":
		req := connect.NewRequest(&atostosv1.ResolvePrincipalBindingRequest{Context: observerContext(), PrincipalId: r.ObjectID})
		o.decorate(req)
		resp, e := o.identity.ResolvePrincipalBinding(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Bound {
			return EvidenceObservation{}, nil
		}
		return observation(r, resp.Msg.BindingRef)
	case "capability-ownership":
		req := connect.NewRequest(&atostosv1.VerifyCapabilityOwnershipRequest{Context: observerContext(), CapabilityId: p.Capability.CapabilityID, ProviderId: p.ProviderID, Version: p.Capability.CapabilityVersion, ExpectedManifestDigest: protoDigestText(p.Capability.ManifestDigest)})
		o.decorate(req)
		resp, e := o.capability.VerifyCapabilityOwnership(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Verified {
			return EvidenceObservation{}, nil
		}
		return observation(r, resp.Msg.OwnershipRef)
	case "verified-quote":
		q, e := quotecommitment.Proto(p.Quote.CanonicalCBOR)
		if e != nil {
			return EvidenceObservation{}, e
		}
		q.OwnershipRef = protoRef(p.Capability.OwnershipRef)
		if p.SignerAuthorization != nil {
			q.SignerAuthorizationRef = protoRef(p.SignerAuthorization.AuthorizationRef)
		}
		req := connect.NewRequest(&atostosv1.GetQuoteCommitmentRequest{Context: observerContext(), QuoteId: p.Quote.QuoteID, ExpectedQuote: q, ExpectedCommitmentRef: protoRef(p.Quote.CommitmentRef)})
		o.decorate(req)
		resp, e := o.trust.GetQuoteCommitment(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Found || resp.Msg.Quote == nil {
			return EvidenceObservation{}, nil
		}
		return observation(r, resp.Msg.Quote.CommitmentRef)
	case "task-escrow-reservation", "task-escrow", "provider_settlement", "requester_release", "dispute_resolution":
		t, e := escrowcommitment.Proto(p.Escrow.CanonicalCBOR)
		if e != nil {
			return EvidenceObservation{}, e
		}
		t.QuoteCommitmentRef = protoRef(p.Quote.CommitmentRef)
		t.OwnershipRef = protoRef(p.Capability.OwnershipRef)
		if p.SignerAuthorization != nil {
			t.SignerAuthorizationRef = protoRef(p.SignerAuthorization.AuthorizationRef)
		}
		req := connect.NewRequest(&atostosv1.GetEscrowRequest{Context: observerContext(), EscrowId: p.Escrow.EscrowID, QuoteId: p.Quote.QuoteID, ExpectedTerms: t, ExpectedEscrowRef: protoRef(p.Escrow.ContractRef), ExpectedReservationDigest: p.Escrow.ReservationDigest})
		if p.Outcome.Kind == "requester_release" {
			req.Msg.ExpectedReleaseDigest = p.Outcome.ReleaseDigest
			req.Msg.ExpectedReleaseReasonCode = p.Outcome.ReasonCode
			if r.Kind == "requester_release" {
				req.Msg.ExpectedTerminalRef = protoRef(p.Outcome.OutcomeRef)
			}
		}
		if p.Outcome.Kind == "dispute_resolution" {
			req.Msg.ExpectedDisputeDigest = p.Outcome.DisputeDigest
			req.Msg.ExpectedDisputeRef = protoRef(p.Outcome.DisputeRef)
			req.Msg.ExpectedDisputePayout = &atostosv1.NetworkAmount{Asset: p.Quote.SettlementAsset, AtomicAmount: p.Outcome.ChargedAtomic}
			if r.Kind == "dispute_resolution" {
				req.Msg.ExpectedTerminalRef = protoRef(p.Outcome.OutcomeRef)
			}
		}
		o.decorate(req)
		resp, e := o.settlement.GetEscrow(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Found || resp.Msg.Escrow == nil {
			return EvidenceObservation{}, nil
		}
		if r.Kind == "task-escrow-reservation" || r.Kind == "task-escrow" {
			return observation(r, resp.Msg.Escrow.EscrowRef)
		}
		return observation(r, resp.Msg.Escrow.TerminalRef)
	case "verified-receipt":
		env, e := receiptcommitment.Proto(p.Receipt.CanonicalCBOR)
		if e != nil {
			return EvidenceObservation{}, e
		}
		req := connect.NewRequest(&atostosv1.ResolveExecutionReceiptRequest{Context: observerContext(), Receipt: env, ExpectedReceiptRef: protoRef(p.Receipt.ReceiptRef)})
		o.decorate(req)
		resp, e := o.proof.ResolveExecutionReceipt(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Found {
			return EvidenceObservation{}, nil
		}
		return observation(r, resp.Msg.ReceiptRef)
	case "proof-of-service":
		v, e := poscommitment.Proto(p.ProofOfService.CanonicalCBOR)
		if e != nil {
			return EvidenceObservation{}, e
		}
		req := connect.NewRequest(&atostosv1.ResolveProofOfServiceEvidenceRequest{Context: observerContext(), Evidence: v, ExpectedEvidenceRef: protoRef(p.ProofOfService.EvidenceRef)})
		o.decorate(req)
		resp, e := o.proof.ResolveProofOfServiceEvidence(ctx, req)
		if e != nil {
			return EvidenceObservation{}, e
		}
		if !resp.Msg.Found {
			return EvidenceObservation{}, nil
		}
		return observation(r, resp.Msg.EvidenceRef)
	case "execution-signer":
		return observation(r, protoRef(p.SignerAuthorization.AuthorizationRef))
	default:
		return EvidenceObservation{}, errors.New("unsupported evidence kind")
	}
}

func (o *ProtocolObserver) ResolveSigner(ctx context.Context, p Package) (SignerObservation, error) {
	if p.SignerAuthorization == nil {
		return SignerObservation{}, errors.New("signer authorization required")
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	req := connect.NewRequest(&atostosv1.ResolveExecutionSignerAuthorizationRequest{Context: observerContext(), ProviderId: p.ProviderID, CapabilityId: p.Capability.CapabilityID, CapabilityVersion: p.Capability.CapabilityVersion, ExecutionSignerId: p.SignerAuthorization.ExecutionSignerID, AtUnixMillis: p.Receipt.CompletedUnixNanos / 1e6})
	o.decorate(req)
	resp, e := o.trust.ResolveExecutionSignerAuthorization(ctx, req)
	if e != nil {
		return SignerObservation{}, e
	}
	a := resp.Msg.Authorization
	if !resp.Msg.Authorized || a == nil || a.Value == nil || a.AuthorizationRef == nil {
		return SignerObservation{}, nil
	}
	v := a.Value
	return SignerObservation{Found: true, Revoked: a.Revoked, Network: a.AuthorizationRef.Network, AuthorizationID: v.AuthorizationId, ProviderID: v.ProviderId, CapabilityID: v.CapabilityId, CapabilityVersion: v.CapabilityVersion, SignerID: v.ExecutionSignerId, Reference: a.AuthorizationRef.Reference, SignatureAlgorithm: v.SignatureAlgorithm, PublicKey: append([]byte(nil), v.SignerPublicKey...), ValidFromUnixNanos: v.ValidFromUnixMillis * 1e6, ValidUntilUnixNanos: v.ValidUntilUnixMillis * 1e6, FinalizedCheckpoint: a.AuthorizationRef.FinalizedCheckpoint}, nil
}
