package atosrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/codec"
	bolt "go.etcd.io/bbolt"
)

const (
	managedFinancialAnchorVersion = "atos_managed_financial_anchor_v1"
	managedFinancialCanonical     = "rfc8949_core_deterministic_cbor"
	managedFinancialAnchorDomain  = "tos.atos.managed-financial-anchor.v1"
)

var boundedFinancialText = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,511}$`)

// managedFinancialAnchorCanonical is deliberately independent of protobuf
// field numbers and transport context. Its JSON model is the normative CBOR
// value frozen by atos-spec.
type managedFinancialAnchorCanonical struct {
	Version            string `json:"version"`
	AnchorID           string `json:"anchor_id,omitempty"`
	BatchID            string `json:"batch_id"`
	BatchSequence      uint64 `json:"batch_sequence"`
	FirstSequence      uint64 `json:"first_sequence"`
	LastSequence       uint64 `json:"last_sequence"`
	CommitmentCount    uint32 `json:"commitment_count"`
	PreviousAnchorID   string `json:"previous_anchor_id"`
	PreviousMerkleRoot string `json:"previous_merkle_root"`
	MerkleRoot         string `json:"merkle_root"`
	ManifestDigest     string `json:"manifest_digest"`
	SignatureDigest    string `json:"signature_digest"`
	SigningKeyID       string `json:"signing_key_id"`
	Canonicalization   string `json:"canonicalization"`
	GatewayID          string `json:"gateway_id"`
	NetworkID          string `json:"network_id"`
}

func digestText(value *atostosv1.Digest) string {
	if value == nil {
		return ""
	}
	return value.Algorithm + ":" + hex.EncodeToString(value.Value)
}

func financialAnchorCanonical(value *atostosv1.ManagedFinancialAnchorInput, includeID bool) managedFinancialAnchorCanonical {
	canonical := managedFinancialAnchorCanonical{
		Version: value.Version, BatchID: value.BatchId,
		BatchSequence: value.BatchSequence, FirstSequence: value.FirstSequence,
		LastSequence: value.LastSequence, CommitmentCount: value.CommitmentCount,
		PreviousAnchorID:   value.PreviousAnchorId,
		PreviousMerkleRoot: digestText(value.PreviousMerkleRoot),
		MerkleRoot:         digestText(value.MerkleRoot),
		ManifestDigest:     digestText(value.ManifestDigest),
		SignatureDigest:    digestText(value.SignatureDigest),
		SigningKeyID:       value.SigningKeyId, Canonicalization: value.Canonicalization,
		GatewayID: value.GatewayId, NetworkID: value.NetworkId,
	}
	if includeID {
		canonical.AnchorID = value.AnchorId
	}
	return canonical
}

func managedFinancialAnchorID(value *atostosv1.ManagedFinancialAnchorInput) (string, error) {
	canonical := financialAnchorCanonical(value, false)
	encoded, err := codec.Marshal(canonical)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return "fanchor_" + hex.EncodeToString(hash[:]), nil
}

func managedFinancialPayloadDigest(value *atostosv1.ManagedFinancialAnchorInput) (string, error) {
	return codec.Digest(managedFinancialAnchorDomain, financialAnchorCanonical(value, true))
}

func parseSHA256Digest(name string, value *atostosv1.Digest) error {
	if value == nil || value.Algorithm != "sha256" || len(value.Value) != sha256.Size {
		return invalid("INVALID_ARGUMENT", name+" must be a SHA-256 digest")
	}
	return nil
}

func validateManagedFinancialAnchor(value *atostosv1.ManagedFinancialAnchorInput, network string) (string, error) {
	if value == nil {
		return "", invalid("INVALID_ARGUMENT", "managed financial anchor is required")
	}
	if value.Version != managedFinancialAnchorVersion || value.Canonicalization != managedFinancialCanonical {
		return "", invalid("INVALID_ARGUMENT", "unsupported managed financial anchor version or canonicalization")
	}
	for name, field := range map[string]string{
		"anchor_id": value.AnchorId, "batch_id": value.BatchId,
		"signing_key_id": value.SigningKeyId, "gateway_id": value.GatewayId,
		"network_id": value.NetworkId,
	} {
		if !boundedFinancialText.MatchString(field) {
			return "", invalid("INVALID_ARGUMENT", name+" is invalid")
		}
	}
	if value.NetworkId != network {
		return "", invalid("NETWORK_MISMATCH", "managed financial anchor network does not match the configured authority")
	}
	if value.BatchSequence == 0 || value.FirstSequence == 0 ||
		value.LastSequence < value.FirstSequence || value.CommitmentCount == 0 ||
		uint64(value.CommitmentCount) != value.LastSequence-value.FirstSequence+1 {
		return "", invalid("INVALID_ARGUMENT", "managed financial anchor sequence range is invalid")
	}
	if value.BatchSequence == 1 {
		if value.PreviousAnchorId != "" {
			return "", invalid("INVALID_ARGUMENT", "genesis managed financial anchor cannot name a previous anchor")
		}
	} else if !boundedFinancialText.MatchString(value.PreviousAnchorId) {
		return "", invalid("INVALID_ARGUMENT", "previous_anchor_id is required after genesis")
	}
	for name, digest := range map[string]*atostosv1.Digest{
		"previous_merkle_root": value.PreviousMerkleRoot,
		"merkle_root":          value.MerkleRoot, "manifest_digest": value.ManifestDigest,
		"signature_digest": value.SignatureDigest,
	} {
		if err := parseSHA256Digest(name, digest); err != nil {
			return "", err
		}
	}
	expectedID, err := managedFinancialAnchorID(value)
	if err != nil {
		return "", invalid("INVALID_ARGUMENT", "managed financial anchor cannot be canonicalized")
	}
	if value.AnchorId != expectedID {
		return "", invalid("ANCHOR_ID_MISMATCH", "managed financial anchor ID does not match its canonical content")
	}
	payloadDigest, err := managedFinancialPayloadDigest(value)
	if err != nil {
		return "", invalid("INVALID_ARGUMENT", "managed financial anchor cannot be canonicalized")
	}
	return payloadDigest, nil
}

func digestProtoValue(text string) *atostosv1.Digest {
	raw, err := hex.DecodeString(strings.TrimPrefix(text, "sha256:"))
	if err != nil {
		return nil
	}
	return &atostosv1.Digest{Algorithm: "sha256", Value: raw}
}

func (s *Server) PublishManagedFinancialAnchor(
	ctx context.Context,
	req *connect.Request[atostosv1.PublishManagedFinancialAnchorRequest],
) (*connect.Response[atostosv1.PublishManagedFinancialAnchorResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Anchor == nil {
		return nil, invalid("INVALID_ARGUMENT", "managed financial anchor is required")
	}
	value := req.Msg.Anchor
	if req.Msg.Context == nil || req.Msg.Context.IdempotencyKey != value.AnchorId ||
		req.Msg.Context.CallerId != value.GatewayId {
		return nil, invalid("INVALID_ARGUMENT", "anchor identity must bind caller and idempotency context")
	}
	payloadDigest, err := validateManagedFinancialAnchor(value, s.authority.Network())
	if err != nil {
		return nil, err
	}
	response := new(atostosv1.PublishManagedFinancialAnchorResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err = s.atomicMutation("PublishManagedFinancialAnchor", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		existing := new(atostosv1.PublishManagedFinancialAnchorResponse)
		found, getErr := s.store.getProto(tx, bucketFinancialAnchors, value.AnchorId, existing)
		if getErr != nil {
			return getErr
		}
		if found {
			if existing.PayloadDigest == nil || digestText(existing.PayloadDigest) != payloadDigest {
				return conflict("IDEMPOTENCY_CONFLICT", "anchor ID is already bound to different content")
			}
			*response = *cloneMessage(existing)
			return nil
		}
		ref, commitErr := s.authority.Commit(ctx, "managed-financial-ledger-root", value.AnchorId, payloadDigest)
		if commitErr != nil {
			return unavailable("NETWORK_UNAVAILABLE", "managed financial anchor publication is unavailable")
		}
		response.Anchor = cloneMessage(value)
		response.PayloadDigest = digestProtoValue(payloadDigest)
		response.AnchorRef = cloneMessage(&ref)
		response.Finalized = ref.Finalized
		response.FinalizedCheckpoint = ref.FinalizedCheckpoint
		if putErr := s.store.putProto(tx, bucketFinancialAnchors, value.AnchorId, response); putErr != nil {
			return putErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ResolveManagedFinancialAnchor(
	ctx context.Context,
	req *connect.Request[atostosv1.ResolveManagedFinancialAnchorRequest],
) (*connect.Response[atostosv1.ResolveManagedFinancialAnchorResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if !boundedFinancialText.MatchString(req.Msg.AnchorId) ||
		req.Msg.NetworkId != s.authority.Network() {
		return nil, invalid("NETWORK_MISMATCH", "anchor identity or network is invalid")
	}
	response := new(atostosv1.ResolveManagedFinancialAnchorResponse)
	err := s.store.view(func(tx *bolt.Tx) error {
		stored := new(atostosv1.PublishManagedFinancialAnchorResponse)
		found, err := s.store.getProto(tx, bucketFinancialAnchors, req.Msg.AnchorId, stored)
		if err != nil || !found {
			return err
		}
		response.Anchor = cloneMessage(stored.Anchor)
		response.PayloadDigest = cloneMessage(stored.PayloadDigest)
		response.AnchorRef = cloneMessage(stored.AnchorRef)
		response.Finalized = stored.Finalized
		response.FinalizedCheckpoint = stored.FinalizedCheckpoint
		response.Found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	if response.Found && response.Finalized {
		resolver, ok := s.authority.(CommitmentResolver)
		if !ok || response.Anchor == nil || response.AnchorRef == nil || response.PayloadDigest == nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "finalized managed financial anchor requires a live network resolver")
		}
		live, resolveErr := resolver.ResolveCommitment(ctx, "managed-financial-ledger-root", response.Anchor.AnchorId, digestText(response.PayloadDigest), response.AnchorRef)
		if resolveErr != nil || live == nil || !live.Finalized || live.Network != req.Msg.NetworkId || live.Reference != response.AnchorRef.Reference || live.FinalizedCheckpoint < response.FinalizedCheckpoint {
			return nil, unavailable("NETWORK_UNAVAILABLE", "managed financial anchor finality could not be re-observed")
		}
		response.AnchorRef = cloneMessage(live)
		response.FinalizedCheckpoint = live.FinalizedCheckpoint
	}
	return connect.NewResponse(response), nil
}
