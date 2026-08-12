package atosrpc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/aipow"
	"github.com/tosnetwork/tos-protocol/pkg/poscommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

func (s *Server) putProofTx(tx *bolt.Tx, ref *NetworkReference, proofType string, value proto.Message) error {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
	if err != nil {
		return err
	}
	digest := bytesDigest("ATOS-TOS-PROOF-BYTES-V1", encoded)
	if ref == nil {
		return errors.New("nil network reference")
	}
	key := ref.Reference
	if key == "" {
		key = digest
	}
	return s.store.putJSON(tx, bucketProofs, key, storedProof{
		ProofType: proofType, Bytes: encoded, Digest: digest,
		Network: ref.Network, Reference: ref.Reference,
	})
}

func receiptSigningBytes(receipt *atostosv1.ExecutionReceiptEnvelope) ([]byte, error) {
	clone := cloneMessage(receipt)
	clone.Signature = nil
	return receiptcommitment.SigningBytes(clone)
}

func (s *Server) signReceipt(receipt *atostosv1.ExecutionReceiptEnvelope) error {
	receipt.SignatureAlgorithm = "ed25519"
	bytesToSign, err := receiptSigningBytes(receipt)
	if err != nil {
		return err
	}
	receipt.Signature = ed25519.Sign(s.privateKey, bytesToSign)
	return nil
}

func (s *Server) verifyReceiptTx(tx *bolt.Tx, receipt *atostosv1.ExecutionReceiptEnvelope, expectedQuoteID, expectedJobID string, requiredProfile atostosv1.ProofProfile) (bool, string, *NetworkReference, error) {
	if receipt == nil {
		return false, "MISSING_RECEIPT", nil, nil
	}
	for _, value := range []string{
		receipt.ReceiptId, receipt.QuoteId, receipt.EscrowId, receipt.JobId,
		receipt.PrincipalId, receipt.ProviderId, receipt.CapabilityId,
		receipt.CapabilityVersion, receipt.ExecutionSignerId,
		receipt.SignerAuthorizationId,
	} {
		if strings.TrimSpace(value) == "" {
			return false, "MISSING_BINDING", nil, nil
		}
	}
	if expectedQuoteID != "" && receipt.QuoteId != expectedQuoteID {
		return false, "QUOTE_MISMATCH", nil, nil
	}
	if expectedJobID != "" && receipt.JobId != expectedJobID {
		return false, "JOB_MISMATCH", nil, nil
	}
	if requiredProfile != atostosv1.ProofProfile_PROOF_PROFILE_UNSPECIFIED && receipt.ProofProfile != requiredProfile {
		return false, "PROOF_PROFILE_MISMATCH", nil, nil
	}
	if err := validateModeProfile(receipt.TrustMode, receipt.ProofProfile); err != nil {
		return false, "TRUST_MODE_MISMATCH", nil, nil
	}
	if !s.supportsMode(receipt.TrustMode) {
		return false, "TRUST_MODE_UNAVAILABLE", nil, nil
	}
	// A malformed AIPoW attribution is rejected, never repaired (an absent
	// one is valid -- the field is optional).
	if err := aipow.Validate(receipt.Aipow); err != nil {
		return false, "AIPOW_ATTRIBUTION_INVALID", nil, nil
	}
	quote := new(atostosv1.QuoteCommitment)
	found, err := s.store.getProto(tx, bucketQuoteCommitments, receipt.QuoteId, quote)
	if err != nil {
		return false, "", nil, err
	}
	if !found || quote.Value == nil {
		return false, "QUOTE_NOT_COMMITTED", nil, nil
	}
	if quote.Value.PrincipalId != receipt.PrincipalId || quote.Value.ProviderId != receipt.ProviderId ||
		quote.Value.CapabilityId != receipt.CapabilityId || quote.Value.CapabilityVersion != receipt.CapabilityVersion ||
		quote.Value.TrustMode != receipt.TrustMode || quote.Value.ProofProfile != receipt.ProofProfile ||
		quote.Value.TotalMax == nil || receipt.ClientCharge == nil ||
		quote.Value.TotalMax.Amount != receipt.ClientCharge.Amount ||
		quote.Value.TotalMax.Currency != receipt.ClientCharge.Currency {
		return false, "QUOTE_BINDING_MISMATCH", nil, nil
	}
	escrow := new(atostosv1.Escrow)
	found, err = s.store.getProto(tx, bucketEscrows, receipt.EscrowId, escrow)
	if err != nil {
		return false, "", nil, err
	}
	if !found || escrow.QuoteId != receipt.QuoteId || escrow.PrincipalId != receipt.PrincipalId ||
		escrow.ProviderId != receipt.ProviderId || escrow.CapabilityId != receipt.CapabilityId ||
		escrow.TrustMode != receipt.TrustMode || escrow.ProofProfile != receipt.ProofProfile ||
		escrow.Reserved == nil || receipt.NetworkCharge == nil ||
		escrow.Reserved.Asset != receipt.NetworkCharge.Asset ||
		escrow.Reserved.AtomicAmount != receipt.NetworkCharge.AtomicAmount {
		return false, "ESCROW_BINDING_MISMATCH", nil, nil
	}
	authorization := new(atostosv1.ExecutionSignerAuthorization)
	key := signerKey(receipt.ProviderId, receipt.CapabilityId, receipt.CapabilityVersion, receipt.ExecutionSignerId)
	found, err = s.store.getProto(tx, bucketSignerAuths, key, authorization)
	if err != nil {
		return false, "", nil, err
	}
	if !found || authorization.Value == nil || authorization.Revoked {
		return false, "SIGNER_NOT_AUTHORIZED", nil, nil
	}
	value := authorization.Value
	if value.AuthorizationId != receipt.SignerAuthorizationId ||
		receipt.CompletedUnixMillis < value.ValidFromUnixMillis ||
		receipt.CompletedUnixMillis >= value.ValidUntilUnixMillis ||
		strings.ToLower(value.SignatureAlgorithm) != "ed25519" ||
		len(value.SignerPublicKey) != ed25519.PublicKeySize ||
		strings.ToLower(receipt.SignatureAlgorithm) != "ed25519" {
		return false, "SIGNER_AUTHORIZATION_MISMATCH", nil, nil
	}
	bytesToVerify, err := receiptSigningBytes(receipt)
	if err != nil {
		return false, "", nil, err
	}
	if !ed25519.Verify(ed25519.PublicKey(value.SignerPublicKey), bytesToVerify, receipt.Signature) {
		return false, "SIGNATURE_INVALID", nil, nil
	}
	if err := validateDigest(receipt.InputCommitment); err != nil {
		return false, "INPUT_COMMITMENT_INVALID", nil, nil
	}
	if err := validateDigest(receipt.OutputCommitment); err != nil {
		return false, "OUTPUT_COMMITMENT_INVALID", nil, nil
	}
	if err := validateDigest(receipt.UsageCommitment); err != nil {
		return false, "USAGE_COMMITMENT_INVALID", nil, nil
	}
	digest, err := receiptcommitment.Digest(receipt)
	if err != nil {
		return false, "", nil, err
	}
	ref, err := s.authority.Commit(context.Background(), "verified-receipt", receipt.ReceiptId, digest)
	if err != nil {
		return false, "NETWORK_UNAVAILABLE", nil, nil
	}
	return true, "", &ref, nil
}

func (s *Server) CommitExecutionReceipt(
	ctx context.Context,
	req *connect.Request[atostosv1.CommitExecutionReceiptRequest],
) (*connect.Response[atostosv1.CommitExecutionReceiptResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Receipt == nil {
		return nil, invalid("INVALID_ARGUMENT", "execution receipt is required")
	}
	if err := requiredIdentifier("receipt_id", req.Msg.Receipt.ReceiptId); err != nil {
		return nil, err
	}
	if err := validateModeProfile(req.Msg.Receipt.TrustMode, req.Msg.Receipt.ProofProfile); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(req.Msg.Receipt.TrustMode); err != nil {
		return nil, err
	}
	response := new(atostosv1.CommitExecutionReceiptResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("CommitExecutionReceipt", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		existing := new(atostosv1.CommittedExecutionReceipt)
		found, err := s.store.getProto(tx, bucketReceipts, req.Msg.Receipt.ReceiptId, existing)
		if err != nil {
			return err
		}
		if found {
			existingDigest, _ := protoDigest("ATOS-TOS-EXECUTION-RECEIPT-V1", existing.Receipt)
			requestedDigest, _ := protoDigest("ATOS-TOS-EXECUTION-RECEIPT-V1", req.Msg.Receipt)
			if existingDigest != requestedDigest {
				return conflict("RECEIPT_MISMATCH", "receipt ID is already committed to different evidence")
			}
			response.Receipt = existing
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-EXECUTION-RECEIPT-V1", req.Msg.Receipt)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "execution-receipt", req.Msg.Receipt.ReceiptId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "execution receipt authority is unavailable")
		}
		committed := &atostosv1.CommittedExecutionReceipt{
			Receipt: cloneMessage(req.Msg.Receipt), ReceiptRef: &ref,
			VerificationStatus:  atostosv1.VerificationStatus_VERIFICATION_STATUS_PENDING,
			CommittedUnixMillis: s.now().UnixMilli(),
		}
		if err := s.store.putProto(tx, bucketReceipts, req.Msg.Receipt.ReceiptId, committed); err != nil {
			return err
		}
		if err := tx.Bucket(bucketReceiptByJob).Put([]byte(req.Msg.Receipt.JobId), []byte(req.Msg.Receipt.ReceiptId)); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "execution_receipt", req.Msg.Receipt); err != nil {
			return err
		}
		response.Receipt = committed
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) VerifyExecutionReceipt(
	_ context.Context,
	req *connect.Request[atostosv1.VerifyExecutionReceiptRequest],
) (*connect.Response[atostosv1.VerifyExecutionReceiptResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Receipt == nil {
		return nil, invalid("INVALID_ARGUMENT", "execution receipt is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	response := &atostosv1.VerifyExecutionReceiptResponse{
		Status: atostosv1.VerificationStatus_VERIFICATION_STATUS_FAILED,
	}
	err := s.store.update(func(tx *bolt.Tx) error {
		verified, reason, proofRef, err := s.verifyReceiptTx(tx, req.Msg.Receipt, req.Msg.ExpectedQuoteId, req.Msg.ExpectedJobId, req.Msg.RequiredProfile)
		if err != nil {
			return err
		}
		response.Verified = verified
		response.ReasonCode = reason
		if verified {
			response.Status = atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED
			response.ProofRef = proofRef
		}
		committed := new(atostosv1.CommittedExecutionReceipt)
		found, err := s.store.getProto(tx, bucketReceipts, req.Msg.Receipt.ReceiptId, committed)
		if err != nil {
			return err
		}
		if found {
			committed.VerificationStatus = response.Status
			if response.ProofRef != nil {
				committed.ReceiptRef = cloneMessage(response.ProofRef)
			}
			if err := s.store.putProto(tx, bucketReceipts, req.Msg.Receipt.ReceiptId, committed); err != nil {
				return err
			}
		}
		if verified && proofRef != nil {
			return s.putProofTx(tx, proofRef, "verified_execution_receipt", req.Msg.Receipt)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ResolveExecutionReceipt(ctx context.Context, req *connect.Request[atostosv1.ResolveExecutionReceiptRequest]) (*connect.Response[atostosv1.ResolveExecutionReceiptResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Receipt == nil {
		return nil, invalid("INVALID_ARGUMENT", "execution receipt is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	digestText, err := receiptcommitment.Digest(req.Msg.Receipt)
	if err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	resolver, ok := s.authority.(CommitmentResolver)
	if !ok {
		return nil, unavailable("NETWORK_UNAVAILABLE", "authority does not support read-only receipt resolution")
	}
	known := req.Msg.ExpectedReceiptRef
	live, err := resolver.ResolveCommitment(ctx, "verified-receipt", req.Msg.Receipt.ReceiptId, digestText, known)
	if err != nil {
		if errors.Is(err, ErrCommitmentNotFound) {
			return connect.NewResponse(&atostosv1.ResolveExecutionReceiptResponse{}), nil
		}
		return nil, unavailable("NETWORK_UNAVAILABLE", "receipt authority is unavailable")
	}
	if live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != s.authority.Network() {
		return nil, unavailable("NETWORK_UNAVAILABLE", "receipt authority returned non-final or mismatched evidence")
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(digestText, "sha256:"))
	return connect.NewResponse(&atostosv1.ResolveExecutionReceiptResponse{Found: true, ReceiptDigest: &atostosv1.Digest{Algorithm: "sha256", Value: raw}, ReceiptRef: live}), nil
}

func (s *Server) CommitProofOfServiceEvidence(
	ctx context.Context,
	req *connect.Request[atostosv1.CommitProofOfServiceEvidenceRequest],
) (*connect.Response[atostosv1.CommitProofOfServiceEvidenceResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Evidence == nil {
		return nil, invalid("INVALID_ARGUMENT", "proof-of-service evidence is required")
	}
	value := req.Msg.Evidence
	for name, field := range map[string]string{
		"evidence_id": value.EvidenceId, "receipt_id": value.ReceiptId,
		"provider_id": value.ProviderId, "capability_id": value.CapabilityId,
		"capability_version": value.CapabilityVersion,
	} {
		if err := requiredIdentifier(name, field); err != nil {
			return nil, err
		}
	}
	if err := validateDigest(value.EvidenceDigest); err != nil {
		return nil, err
	}
	response := new(atostosv1.CommitProofOfServiceEvidenceResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("CommitProofOfServiceEvidence", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		receipt := new(atostosv1.CommittedExecutionReceipt)
		found, err := s.store.getProto(tx, bucketReceipts, value.ReceiptId, receipt)
		if err != nil {
			return err
		}
		if !found || receipt.Receipt == nil || receipt.VerificationStatus != atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED {
			return failedPrecondition("PROOF_REQUIREMENTS_UNSATISFIED", "verified receipt is required before Proof-of-Service evidence")
		}
		if receipt.Receipt.ProviderId != value.ProviderId || receipt.Receipt.CapabilityId != value.CapabilityId ||
			receipt.Receipt.CapabilityVersion != value.CapabilityVersion {
			return failedPrecondition("RECEIPT_MISMATCH", "evidence does not match receipt binding")
		}
		existing := new(atostosv1.ProofOfServiceEvidence)
		exists, err := s.store.getProto(tx, bucketEvidence, value.EvidenceId, existing)
		if err != nil {
			return err
		}
		if exists {
			response.Evidence = existing
			return nil
		}
		digest, err := poscommitment.Digest(value)
		if err != nil {
			return err
		}
		ref, err := s.authority.Commit(ctx, "proof-of-service", value.EvidenceId, digest)
		if err != nil {
			return unavailable("NETWORK_UNAVAILABLE", "Proof-of-Service authority is unavailable")
		}
		evidence := &atostosv1.ProofOfServiceEvidence{
			Value: cloneMessage(value), EvidenceRef: &ref,
			CommittedUnixMillis: s.now().UnixMilli(),
		}
		if err := s.store.putProto(tx, bucketEvidence, value.EvidenceId, evidence); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "proof_of_service", value); err != nil {
			return err
		}
		response.Evidence = evidence
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

// ResolveProofOfServiceEvidence performs live, read-only tuple resolution. A
// local projection miss is never treated as canonical absence.
func (s *Server) ResolveProofOfServiceEvidence(ctx context.Context, req *connect.Request[atostosv1.ResolveProofOfServiceEvidenceRequest]) (*connect.Response[atostosv1.ResolveProofOfServiceEvidenceResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Evidence == nil {
		return nil, invalid("INVALID_ARGUMENT", "proof-of-service evidence is required")
	}
	v := req.Msg.Evidence
	if err := requiredIdentifier("evidence_id", v.EvidenceId); err != nil {
		return nil, err
	}
	digest, err := poscommitment.Digest(v)
	if err != nil {
		return nil, err
	}
	var expected *atostosv1.NetworkReference
	if req.Msg.ExpectedEvidenceRef != nil && req.Msg.ExpectedEvidenceRef.Reference != "" {
		expected = req.Msg.ExpectedEvidenceRef
	}
	resolver, ok := s.authority.(CommitmentResolver)
	if !ok {
		return nil, unavailable("NETWORK_UNAVAILABLE", "Proof-of-Service resolver is unavailable")
	}
	live, err := resolver.ResolveCommitment(ctx, "proof-of-service", v.EvidenceId, digest, expected)
	if err != nil {
		if errors.Is(err, ErrCommitmentNotFound) {
			return connect.NewResponse(&atostosv1.ResolveProofOfServiceEvidenceResponse{}), nil
		}
		return nil, unavailable("NETWORK_UNAVAILABLE", "Proof-of-Service authority is unavailable")
	}
	if live == nil || !live.Finalized || live.FinalizedCheckpoint == 0 || live.Network != s.authority.Network() {
		return nil, unavailable("NETWORK_UNAVAILABLE", "Proof-of-Service authority returned non-final evidence")
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(digest, "sha256:"))
	return connect.NewResponse(&atostosv1.ResolveProofOfServiceEvidenceResponse{Found: true, EvidenceDigest: &atostosv1.Digest{Algorithm: "sha256", Value: raw}, EvidenceRef: live}), nil
}

func (s *Server) ReadProofOfService(
	_ context.Context,
	req *connect.Request[atostosv1.ReadProofOfServiceRequest],
) (*connect.Response[atostosv1.ReadProofOfServiceResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	limit := uint32(100)
	if req.Msg.Page != nil && req.Msg.Page.PageSize > 0 {
		limit = req.Msg.Page.PageSize
	}
	if limit > 1000 {
		return nil, invalid("INVALID_ARGUMENT", "page_size exceeds limit")
	}
	response := &atostosv1.ReadProofOfServiceResponse{Page: &atostosv1.PageResponse{}}
	err := s.store.view(func(tx *bolt.Tx) error {
		cursor := tx.Bucket(bucketEvidence).Cursor()
		var key, value []byte
		if req.Msg.Page != nil && req.Msg.Page.PageToken != "" {
			key, value = cursor.Seek([]byte(req.Msg.Page.PageToken))
			if key != nil && string(key) == req.Msg.Page.PageToken {
				key, value = cursor.Next()
			}
		} else {
			key, value = cursor.First()
		}
		for ; key != nil && uint32(len(response.Evidence)) < limit; key, value = cursor.Next() {
			_ = value
			evidence := new(atostosv1.ProofOfServiceEvidence)
			found, err := s.store.getProto(tx, bucketEvidence, string(key), evidence)
			if err != nil {
				return err
			}
			if !found || evidence.Value == nil {
				continue
			}
			if req.Msg.ProviderId != "" && evidence.Value.ProviderId != req.Msg.ProviderId {
				continue
			}
			if req.Msg.CapabilityId != "" && evidence.Value.CapabilityId != req.Msg.CapabilityId {
				continue
			}
			response.Evidence = append(response.Evidence, evidence)
			response.Page.NextPageToken = string(key)
		}
		if key == nil {
			response.Page.NextPageToken = ""
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ReadReputation(
	_ context.Context,
	req *connect.Request[atostosv1.ReadReputationRequest],
) (*connect.Response[atostosv1.ReadReputationResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if err := requiredIdentifier("provider_id", req.Msg.ProviderId); err != nil {
		return nil, err
	}
	response := new(atostosv1.ReadReputationResponse)
	err := s.store.view(func(tx *bolt.Tx) error {
		var total, verified, successes, disputed, settled uint64
		var latencies []uint64
		cursor := tx.Bucket(bucketEvidence).Cursor()
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			evidence := new(atostosv1.ProofOfServiceEvidence)
			found, err := s.store.getProto(tx, bucketEvidence, string(key), evidence)
			if err != nil {
				return err
			}
			if !found || evidence.Value == nil || evidence.Value.ProviderId != req.Msg.ProviderId {
				continue
			}
			if req.Msg.CapabilityId != "" && evidence.Value.CapabilityId != req.Msg.CapabilityId {
				continue
			}
			total++
			verified++
			if evidence.Value.Result == atostosv1.ExecutionResult_EXECUTION_RESULT_SUCCESS {
				successes++
			}
			if evidence.Value.Disputed {
				disputed++
			}
			if evidence.Value.SettlementVolume != nil && evidence.Value.SettlementVolume.AtomicAmount != "" {
				settled++
			}
			latencies = append(latencies, evidence.Value.LatencyMillis)
		}
		if total == 0 {
			return nil
		}
		sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
		score := float64(successes) / float64(total)
		if disputed > 0 {
			score *= 1 - (0.5 * float64(disputed) / float64(total))
		}
		summary := &atostosv1.ReputationSummary{
			ProviderId: req.Msg.ProviderId, CapabilityId: req.Msg.CapabilityId,
			Score: score, VerifiedExecutions: verified, SuccessfulExecutions: successes,
			DisputedExecutions: disputed, SettledExecutions: settled,
			P50LatencyMillis: percentile(latencies, 0.50), P95LatencyMillis: percentile(latencies, 0.95),
			UpdatedUnixMillis: s.now().UnixMilli(),
		}
		// ReputationSummary is a derived gateway/indexer projection, not a
		// consensus-critical fact. A read must not publish a chain transaction.
		// Portable evidence remains available through Proof-of-Service records.
		response.Reputation = summary
		response.Found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func percentile(sorted []uint64, p float64) uint64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(float64(len(sorted)-1) * p)
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func (s *Server) ReadProof(
	_ context.Context,
	req *connect.Request[atostosv1.ReadProofRequest],
) (*connect.Response[atostosv1.ReadProofResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.Msg.ProofRef) == "" {
		return nil, invalid("INVALID_ARGUMENT", "proof_ref is required")
	}
	response := &atostosv1.ReadProofResponse{ProofRef: req.Msg.ProofRef}
	err := s.store.view(func(tx *bolt.Tx) error {
		var proof storedProof
		found, err := s.store.getJSON(tx, bucketProofs, req.Msg.ProofRef, &proof)
		if err != nil {
			return err
		}
		if !found {
			return nil
		}
		response.ProofType = proof.ProofType
		response.ProofBytes = append([]byte(nil), proof.Bytes...)
		rawDigest := strings.TrimPrefix(proof.Digest, "sha256:")
		decoded, _ := hex.DecodeString(rawDigest)
		response.ProofDigest = &atostosv1.Digest{Algorithm: "sha256", Value: decoded}
		response.NetworkRef = &atostosv1.NetworkReference{Network: proof.Network, Reference: proof.Reference}
		response.Found = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func canonicalReceiptDigest(receipt []byte) *atostosv1.Digest {
	sum := sha256.Sum256(receipt)
	return &atostosv1.Digest{Algorithm: "sha256", Value: sum[:]}
}

func equalDigests(left, right *atostosv1.Digest) bool {
	return left != nil && right != nil && left.Algorithm == right.Algorithm && bytes.Equal(left.Value, right.Value)
}
