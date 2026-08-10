package atosrpc

import (
	"context"
	"math/big"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) CreateEscrow(
	ctx context.Context,
	req *connect.Request[atostosv1.CreateEscrowRequest],
) (*connect.Response[atostosv1.CreateEscrowResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	for name, value := range map[string]string{
		"quote_id": req.Msg.QuoteId, "principal_id": req.Msg.PrincipalId,
		"provider_id": req.Msg.ProviderId, "capability_id": req.Msg.CapabilityId,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	if err := validateModeProfile(req.Msg.TrustMode, req.Msg.ProofProfile); err != nil {
		return nil, err
	}
	if err := s.ensureSupported(req.Msg.TrustMode); err != nil {
		return nil, err
	}
	if req.Msg.Reserve == nil || strings.TrimSpace(req.Msg.Reserve.Asset) == "" {
		return nil, invalid("INVALID_ARGUMENT", "reserve asset and amount are required")
	}
	reserveAmount, err := parseAtomic(req.Msg.Reserve.AtomicAmount)
	if err != nil || !reserveAmount.IsUint64() {
		return nil, invalid("INVALID_ARGUMENT", "reserve atomic_amount is invalid or outside uint64")
	}
	if req.Msg.TrustMode == TrustModeVerified && req.Msg.Reserve.Asset != "TOS" {
		return nil, invalid("INVALID_ARGUMENT", "Verified Task Escrow requires native TOS")
	}
	if req.Msg.ExpiresUnixMillis <= s.now().UnixMilli() {
		return nil, invalid("INVALID_ARGUMENT", "escrow expiry must be in the future")
	}
	response := new(atostosv1.CreateEscrowResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err = s.atomicMutation("CreateEscrow", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		quote := new(atostosv1.QuoteCommitment)
		found, err := s.store.getProto(tx, bucketQuoteCommitments, req.Msg.QuoteId, quote)
		if err != nil {
			return err
		}
		if !found || quote.Value == nil {
			return failedPrecondition("QUOTE_MISMATCH", "quote commitment is not available")
		}
		value := quote.Value
		if value.PrincipalId != req.Msg.PrincipalId || value.ProviderId != req.Msg.ProviderId ||
			value.CapabilityId != req.Msg.CapabilityId || value.TrustMode != req.Msg.TrustMode ||
			value.ProofProfile != req.Msg.ProofProfile {
			return failedPrecondition("QUOTE_MISMATCH", "escrow request does not match quote commitment")
		}
		if existingID := tx.Bucket(bucketEscrowByQuote).Get([]byte(req.Msg.QuoteId)); existingID != nil {
			existing := new(atostosv1.Escrow)
			found, err := s.store.getProto(tx, bucketEscrows, string(existingID), existing)
			if err != nil {
				return err
			}
			if found {
				response.Escrow = existing
				return nil
			}
		}
		digest, err := protoDigest("ATOS-TOS-ESCROW-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		escrowID := shortID("esc-", digest)
		var ref NetworkReference
		switch req.Msg.TrustMode {
		case TrustModeManaged:
			ref, err = s.authority.Commit(ctx, "escrow", escrowID, digest)
			if err != nil {
				return unavailable("NETWORK_UNAVAILABLE", "escrow authority is unavailable")
			}
		case TrustModeVerified:
			creator, agent, partyErr := s.economicPartiesTx(
				tx, req.Msg.PrincipalId, req.Msg.ProviderId,
			)
			if partyErr != nil {
				return partyErr
			}
			policyHash, policyErr := protoDigest("ATOS-TOS-TASK-ESCROW-POLICY-V1", value)
			if policyErr != nil {
				return policyErr
			}
			permissionHash := bytesDigest(
				"ATOS-TOS-TASK-ESCROW-PERMISSION-V1",
				[]byte(strings.Join([]string{
					"principal_id", req.Msg.PrincipalId,
					"provider_id", req.Msg.ProviderId,
					"capability_id", req.Msg.CapabilityId,
					"quote_id", req.Msg.QuoteId,
				}, "\x00")),
			)
			result, economicErr := s.economy.ReserveEscrow(ctx, economic.ReserveEscrowRequest{
				EscrowID: escrowID, Creator: creator, Agent: agent,
				BudgetNanoTOS: reserveAmount.Uint64(),
				DeadlineUnix:  uint64(req.Msg.ExpiresUnixMillis / 1000),
				PolicyHash:    policyHash, PermissionHash: permissionHash,
			})
			if economicErr != nil {
				return economicRPCError(economicErr, "reserve TOS Task Escrow")
			}
			ref = NetworkReference{
				Network: s.economy.Network(), Reference: result.ContractReference,
			}
		default:
			return failedPrecondition("TRUST_MODE_UNAVAILABLE", "economic escrow mode is unavailable")
		}
		escrow := &atostosv1.Escrow{
			EscrowId: escrowID, QuoteId: req.Msg.QuoteId,
			PrincipalId: req.Msg.PrincipalId, ProviderId: req.Msg.ProviderId,
			CapabilityId: req.Msg.CapabilityId, TrustMode: req.Msg.TrustMode,
			ProofProfile: req.Msg.ProofProfile, Reserved: cloneMessage(req.Msg.Reserve),
			State:             atostosv1.EscrowState_ESCROW_STATE_RESERVED,
			CreatedUnixMillis: s.now().UnixMilli(), ExpiresUnixMillis: req.Msg.ExpiresUnixMillis,
			EscrowRef: &ref, FundingModel: req.Msg.FundingModel,
		}
		if err := s.store.putProto(tx, bucketEscrows, escrowID, escrow); err != nil {
			return err
		}
		if err := tx.Bucket(bucketEscrowByQuote).Put([]byte(req.Msg.QuoteId), []byte(escrowID)); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "escrow", escrow); err != nil {
			return err
		}
		response.Escrow = escrow
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) GetEscrow(
	_ context.Context,
	req *connect.Request[atostosv1.GetEscrowRequest],
) (*connect.Response[atostosv1.GetEscrowResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if req.Msg.EscrowId == "" && req.Msg.QuoteId == "" {
		return nil, invalid("INVALID_ARGUMENT", "escrow_id or quote_id is required")
	}
	response := new(atostosv1.GetEscrowResponse)
	err := s.store.view(func(tx *bolt.Tx) error {
		escrowID := req.Msg.EscrowId
		if escrowID == "" {
			encoded := tx.Bucket(bucketEscrowByQuote).Get([]byte(req.Msg.QuoteId))
			if encoded == nil {
				return nil
			}
			escrowID = string(encoded)
		}
		escrow := new(atostosv1.Escrow)
		found, err := s.store.getProto(tx, bucketEscrows, escrowID, escrow)
		if err != nil {
			return err
		}
		if found {
			response.Escrow, response.Found = escrow, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) ReleaseEscrow(
	ctx context.Context,
	req *connect.Request[atostosv1.ReleaseEscrowRequest],
) (*connect.Response[atostosv1.ReleaseEscrowResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := requiredIdentifier("escrow_id", req.Msg.EscrowId); err != nil {
		return nil, err
	}
	response := new(atostosv1.ReleaseEscrowResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err := s.atomicMutation("ReleaseEscrow", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		escrow := new(atostosv1.Escrow)
		found, err := s.store.getProto(tx, bucketEscrows, req.Msg.EscrowId, escrow)
		if err != nil {
			return err
		}
		if !found {
			return notFound("NOT_FOUND", "escrow not found")
		}
		if req.Msg.QuoteId != "" && escrow.QuoteId != req.Msg.QuoteId {
			return failedPrecondition("QUOTE_MISMATCH", "escrow quote mismatch")
		}
		if escrow.State == atostosv1.EscrowState_ESCROW_STATE_SETTLED {
			return failedPrecondition("SETTLEMENT_FAILED", "settled escrow cannot be released")
		}
		if escrow.State == atostosv1.EscrowState_ESCROW_STATE_RELEASED {
			response.Escrow = escrow
			response.ReleaseRef = cloneMessage(escrow.EscrowRef)
			response.Released = true
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-ESCROW-RELEASE-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		var ref NetworkReference
		switch escrow.TrustMode {
		case TrustModeManaged:
			ref, err = s.authority.Commit(ctx, "escrow-release", escrow.EscrowId, digest)
			if err != nil {
				return unavailable("NETWORK_UNAVAILABLE", "escrow release authority is unavailable")
			}
		case TrustModeVerified:
			contractAddress, addressErr := economicContractAddress(escrow.EscrowRef)
			if addressErr != nil {
				return failedPrecondition("ESCROW_MISMATCH", addressErr.Error())
			}
			reserved, parseErr := parseAtomic(escrow.Reserved.AtomicAmount)
			if parseErr != nil || !reserved.IsUint64() {
				return failedPrecondition("ESCROW_MISMATCH", "escrow reserve is outside uint64")
			}
			result, economicErr := s.economy.ReleaseEscrow(ctx, economic.ReleaseEscrowRequest{
				EscrowID: escrow.EscrowId, ContractAddress: contractAddress,
				BudgetNanoTOS: reserved.Uint64(), ReasonCode: req.Msg.ReasonCode,
			})
			if economicErr != nil {
				return economicRPCError(economicErr, "release TOS Task Escrow")
			}
			if result.TransitionReference == "" {
				return failedPrecondition("ECONOMIC_TRANSITION_FAILED", "released Task Escrow has no finalized transition reference")
			}
			ref = NetworkReference{Network: s.economy.Network(), Reference: result.TransitionReference}
		default:
			return failedPrecondition("TRUST_MODE_UNAVAILABLE", "economic escrow mode is unavailable")
		}
		escrow.State = atostosv1.EscrowState_ESCROW_STATE_RELEASED
		if err := s.store.putProto(tx, bucketEscrows, escrow.EscrowId, escrow); err != nil {
			return err
		}
		response.Escrow = escrow
		response.ReleaseRef = &ref
		response.Released = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) SettleJob(
	ctx context.Context,
	req *connect.Request[atostosv1.SettleJobRequest],
) (*connect.Response[atostosv1.SettleJobResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.RequestedCharge == nil {
		return nil, invalid("INVALID_ARGUMENT", "settlement charge is required")
	}
	for name, value := range map[string]string{
		"escrow_id": req.Msg.EscrowId, "quote_id": req.Msg.QuoteId,
		"job_id": req.Msg.JobId, "receipt_id": req.Msg.ReceiptId,
	} {
		if err := requiredIdentifier(name, value); err != nil {
			return nil, err
		}
	}
	charge, err := parseAtomic(req.Msg.RequestedCharge.AtomicAmount)
	if err != nil || !charge.IsUint64() || strings.TrimSpace(req.Msg.RequestedCharge.Asset) == "" {
		return nil, invalid("INVALID_ARGUMENT", "requested charge is invalid or outside uint64")
	}
	response := new(atostosv1.SettleJobResponse)
	s.mutationMu.Lock()
	defer s.mutationMu.Unlock()
	err = s.atomicMutation("SettleJob", req.Msg.Context, req.Msg, response, func(tx *bolt.Tx) error {
		escrow := new(atostosv1.Escrow)
		found, err := s.store.getProto(tx, bucketEscrows, req.Msg.EscrowId, escrow)
		if err != nil {
			return err
		}
		if !found {
			return notFound("NOT_FOUND", "escrow not found")
		}
		if escrow.QuoteId != req.Msg.QuoteId || escrow.State != atostosv1.EscrowState_ESCROW_STATE_RESERVED {
			return failedPrecondition("SETTLEMENT_FAILED", "escrow is not reservable for this settlement")
		}
		if escrow.Reserved == nil || escrow.Reserved.Asset != req.Msg.RequestedCharge.Asset {
			return failedPrecondition("SETTLEMENT_FAILED", "settlement asset does not match escrow")
		}
		reserved, err := parseAtomic(escrow.Reserved.AtomicAmount)
		if err != nil || charge.Cmp(reserved) > 0 {
			return failedPrecondition("SETTLEMENT_FAILED", "charge exceeds escrow reserve")
		}
		receipt := new(atostosv1.CommittedExecutionReceipt)
		found, err = s.store.getProto(tx, bucketReceipts, req.Msg.ReceiptId, receipt)
		if err != nil {
			return err
		}
		if !found || receipt.Receipt == nil || receipt.VerificationStatus != atostosv1.VerificationStatus_VERIFICATION_STATUS_VERIFIED {
			return failedPrecondition("SETTLEMENT_FAILED", "a verified execution receipt is required")
		}
		if receipt.Receipt.JobId != req.Msg.JobId || receipt.Receipt.QuoteId != req.Msg.QuoteId || receipt.Receipt.EscrowId != req.Msg.EscrowId {
			return failedPrecondition("SETTLEMENT_FAILED", "receipt binding does not match settlement")
		}
		if existingID := tx.Bucket(bucketSettlementByJob).Get([]byte(req.Msg.JobId)); existingID != nil {
			existing := new(atostosv1.Settlement)
			found, err := s.store.getProto(tx, bucketSettlements, string(existingID), existing)
			if err != nil {
				return err
			}
			if found {
				response.Settlement = existing
				response.Escrow = escrow
				return nil
			}
		}
		refund := new(big.Int).Sub(new(big.Int).Set(reserved), charge)
		digest, err := protoDigest("ATOS-TOS-SETTLEMENT-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		settlementID := shortID("set-", digest)
		var ref NetworkReference
		switch escrow.TrustMode {
		case TrustModeManaged:
			ref, err = s.authority.Commit(ctx, "settlement", settlementID, digest)
			if err != nil {
				return unavailable("NETWORK_UNAVAILABLE", "settlement authority is unavailable")
			}
		case TrustModeVerified:
			contractAddress, addressErr := economicContractAddress(escrow.EscrowRef)
			if addressErr != nil {
				return failedPrecondition("ESCROW_MISMATCH", addressErr.Error())
			}
			resultHash, hashErr := digestString(receipt.Receipt.OutputCommitment)
			if hashErr != nil {
				return failedPrecondition("RECEIPT_INVALID", "receipt output commitment is invalid")
			}
			evidenceHash, evidenceErr := protoDigest("ATOS-TOS-TASK-EVIDENCE-V1", receipt.Receipt)
			if evidenceErr != nil {
				return evidenceErr
			}
			result, economicErr := s.economy.SettleProvider(ctx, economic.SettleProviderRequest{
				EscrowID: escrow.EscrowId, ContractAddress: contractAddress,
				BudgetNanoTOS: reserved.Uint64(),
				ResultHash:    resultHash, EvidenceHash: evidenceHash,
				PayoutNanoTOS: charge.Uint64(),
			})
			if economicErr != nil {
				return economicRPCError(economicErr, "settle TOS Task Escrow")
			}
			if result.TransitionReference == "" || result.AgentPaidNanoTOS != charge.Uint64() {
				return failedPrecondition("SETTLEMENT_FAILED", "Task Escrow payout is not finalized")
			}
			ref = NetworkReference{Network: s.economy.Network(), Reference: result.TransitionReference}
		default:
			return failedPrecondition("TRUST_MODE_UNAVAILABLE", "economic settlement mode is unavailable")
		}
		settlement := &atostosv1.Settlement{
			SettlementId: settlementID, EscrowId: req.Msg.EscrowId,
			QuoteId: req.Msg.QuoteId, JobId: req.Msg.JobId, ReceiptId: req.Msg.ReceiptId,
			Charged:       cloneMessage(req.Msg.RequestedCharge),
			Refunded:      &atostosv1.NetworkAmount{Asset: escrow.Reserved.Asset, AtomicAmount: refund.String()},
			State:         atostosv1.SettlementState_SETTLEMENT_STATE_SETTLED,
			SettlementRef: &ref, SettledUnixMillis: s.now().UnixMilli(),
		}
		escrow.State = atostosv1.EscrowState_ESCROW_STATE_SETTLED
		if err := s.store.putProto(tx, bucketSettlements, settlementID, settlement); err != nil {
			return err
		}
		if err := s.store.putProto(tx, bucketEscrows, escrow.EscrowId, escrow); err != nil {
			return err
		}
		if err := tx.Bucket(bucketSettlementByJob).Put([]byte(req.Msg.JobId), []byte(settlementID)); err != nil {
			return err
		}
		if err := tx.Bucket(bucketSettlementByRcpt).Put([]byte(req.Msg.ReceiptId), []byte(settlementID)); err != nil {
			return err
		}
		if err := s.putProofTx(tx, &ref, "settlement", settlement); err != nil {
			return err
		}
		response.Settlement = settlement
		response.Escrow = escrow
		response.Created = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func (s *Server) GetSettlement(
	_ context.Context,
	req *connect.Request[atostosv1.GetSettlementRequest],
) (*connect.Response[atostosv1.GetSettlementResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := validateReadContext(req.Msg.Context, s.now()); err != nil {
		return nil, err
	}
	if req.Msg.SettlementId == "" && req.Msg.JobId == "" && req.Msg.ReceiptId == "" {
		return nil, invalid("INVALID_ARGUMENT", "settlement_id, job_id, or receipt_id is required")
	}
	response := new(atostosv1.GetSettlementResponse)
	err := s.store.view(func(tx *bolt.Tx) error {
		settlementID := req.Msg.SettlementId
		if settlementID == "" && req.Msg.JobId != "" {
			settlementID = string(tx.Bucket(bucketSettlementByJob).Get([]byte(req.Msg.JobId)))
		}
		if settlementID == "" && req.Msg.ReceiptId != "" {
			settlementID = string(tx.Bucket(bucketSettlementByRcpt).Get([]byte(req.Msg.ReceiptId)))
		}
		if settlementID == "" {
			return nil
		}
		settlement := new(atostosv1.Settlement)
		found, err := s.store.getProto(tx, bucketSettlements, settlementID, settlement)
		if err != nil {
			return err
		}
		if found {
			response.Settlement, response.Found = settlement, true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(response), nil
}

func settlementTerminal(state atostosv1.SettlementState) bool {
	return state == atostosv1.SettlementState_SETTLEMENT_STATE_SETTLED ||
		state == atostosv1.SettlementState_SETTLEMENT_STATE_RELEASED ||
		state == atostosv1.SettlementState_SETTLEMENT_STATE_FAILED
}

func escrowExpired(escrow *atostosv1.Escrow, now time.Time) bool {
	return escrow != nil && escrow.ExpiresUnixMillis > 0 && !now.Before(time.UnixMilli(escrow.ExpiresUnixMillis))
}
