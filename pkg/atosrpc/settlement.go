package atosrpc

import (
	"context"
	"math/big"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	bolt "go.etcd.io/bbolt"
)

func (s *Server) CreateEscrow(
	ctx context.Context,
	req *connect.Request[atostosv1.CreateEscrowRequest],
) (*connect.Response[atostosv1.CreateEscrowResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
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
	var verifiedTerms *atostosv1.VerifiedEscrowTerms
	var reservationDigest string
	if req.Msg.TrustMode == TrustModeVerified {
		verifiedTerms = req.Msg.VerifiedTerms
		if _, _, _, err := s.validateVerifiedEscrowTerms(ctx, verifiedTerms); err != nil {
			return nil, err
		}
		if verifiedTerms.QuoteId != req.Msg.QuoteId || verifiedTerms.PrincipalId != req.Msg.PrincipalId ||
			verifiedTerms.ProviderId != req.Msg.ProviderId || verifiedTerms.CapabilityId != req.Msg.CapabilityId ||
			verifiedTerms.TrustMode != req.Msg.TrustMode || verifiedTerms.ProofProfile != req.Msg.ProofProfile ||
			verifiedTerms.FundingModel != req.Msg.FundingModel || verifiedTerms.EscrowDeadlineUnixMillis != req.Msg.ExpiresUnixMillis ||
			verifiedTerms.Reserve == nil || verifiedTerms.Reserve.Asset != req.Msg.Reserve.Asset || verifiedTerms.Reserve.AtomicAmount != req.Msg.Reserve.AtomicAmount {
			return nil, failedPrecondition("QUOTE_MISMATCH", "legacy escrow fields do not match verified terms")
		}
		reservationDigest, err = escrowcommitment.Digest(verifiedTerms)
		if err != nil {
			return nil, invalid("INVALID_ARGUMENT", "verified escrow terms cannot be canonicalized")
		}
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
		if (!found || quote.Value == nil) && req.Msg.TrustMode != TrustModeVerified {
			return failedPrecondition("QUOTE_MISMATCH", "quote commitment is not available")
		}
		value := quote.Value
		if req.Msg.TrustMode == TrustModeVerified {
			value, _ = verifiedQuoteFromEscrowTerms(verifiedTerms)
		}
		if value.PrincipalId != req.Msg.PrincipalId || value.ProviderId != req.Msg.ProviderId ||
			value.CapabilityId != req.Msg.CapabilityId || value.TrustMode != req.Msg.TrustMode ||
			value.ProofProfile != req.Msg.ProofProfile {
			return failedPrecondition("QUOTE_MISMATCH", "escrow request does not match quote commitment")
		}
		if existingID := tx.Bucket(bucketEscrowByQuote).Get([]byte(req.Msg.QuoteId)); existingID != nil && req.Msg.TrustMode != TrustModeVerified {
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
		if req.Msg.TrustMode == TrustModeVerified {
			escrowID = verifiedTerms.EscrowId
		}
		var ref NetworkReference
		var economicResult economic.Result
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
			permissionHash := reservationDigest
			reserveRequest := economic.ReserveEscrowRequest{
				EscrowID: escrowID, Creator: creator, Agent: agent,
				BudgetNanoTOS: reserveAmount.Uint64(),
				DeadlineUnix:  uint64(req.Msg.ExpiresUnixMillis / 1000),
				PolicyHash:    policyHash, PermissionHash: permissionHash,
			}
			result, recovered, economicErr := s.economy.ResolveEscrow(ctx, reserveRequest)
			if economicErr == nil && recovered && result.State.Status != chain.TaskEscrowStatusOpen {
				return failedPrecondition("ESCROW_MISMATCH", "released or terminal TaskEscrow cannot be revived")
			}
			if economicErr == nil && !recovered {
				result, economicErr = s.economy.ReserveEscrow(ctx, reserveRequest)
			}
			if economicErr != nil {
				return economicRPCError(economicErr, "reserve TOS Task Escrow")
			}
			if result.State.ObservedMasterSeqno == 0 || strings.TrimSpace(result.State.CodeHash) == "" || result.TransitionReference == "" {
				return failedPrecondition("ECONOMIC_TRANSITION_FAILED", "TaskEscrow reservation is not independently finalized")
			}
			ref = NetworkReference{
				Network: s.economy.Network(), Reference: result.ContractReference,
			}
			economicResult = result
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
		if verifiedTerms != nil {
			escrow.JobId = verifiedTerms.JobId
			escrow.CapabilityVersion = verifiedTerms.CapabilityVersion
			escrow.QuoteCommitmentDigest = verifiedTerms.QuoteCommitmentDigest
			escrow.QuoteCommitmentRef = cloneMessage(verifiedTerms.QuoteCommitmentRef)
			escrow.ReservationDigest = reservationDigest
			escrow.Finalized = true
			// ReserveEscrow returns only after independent quorum observation.
			escrow.FinalizedCheckpoint = economicResult.State.ObservedMasterSeqno
			escrow.ContractCodeHash = economicResult.State.CodeHash
			escrow.ReservationActionId = economicResult.ActionID
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
	ctx context.Context,
	req *connect.Request[atostosv1.GetEscrowRequest],
) (*connect.Response[atostosv1.GetEscrowResponse], error) {
	if req == nil || req.Msg == nil {
		return nil, invalid("INVALID_ARGUMENT", "request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
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
	if req.Msg.ExpectedTerms != nil {
		terms := req.Msg.ExpectedTerms
		expectedQuote, _, _, validationErr := s.validateVerifiedEscrowTerms(ctx, terms)
		if validationErr != nil {
			return nil, validationErr
		}
		if req.Msg.EscrowId != "" && req.Msg.EscrowId != terms.EscrowId {
			return nil, conflict("ESCROW_MISMATCH", "expected escrow identity mismatch")
		}
		if req.Msg.QuoteId != "" && req.Msg.QuoteId != terms.QuoteId {
			return nil, conflict("QUOTE_MISMATCH", "expected Quote identity mismatch")
		}
		reservationDigest, digestErr := escrowcommitment.Digest(terms)
		if digestErr != nil || (req.Msg.ExpectedReservationDigest != "" && req.Msg.ExpectedReservationDigest != reservationDigest) {
			return nil, conflict("ESCROW_MISMATCH", "reservation digest mismatch")
		}
		var creator, agent string
		partyErr := s.store.view(func(tx *bolt.Tx) error {
			var err error
			creator, agent, err = s.economicPartiesTx(tx, terms.PrincipalId, terms.ProviderId)
			return err
		})
		if partyErr != nil {
			return nil, partyErr
		}
		reserve, parseErr := parseAtomic(terms.Reserve.AtomicAmount)
		if parseErr != nil || !reserve.IsUint64() {
			return nil, invalid("INVALID_ARGUMENT", "invalid reserve")
		}
		policyHash, policyErr := protoDigest("ATOS-TOS-TASK-ESCROW-POLICY-V1", expectedQuote)
		if policyErr != nil {
			return nil, policyErr
		}
		resolved, found, resolveErr := s.economy.ResolveEscrow(ctx, economic.ReserveEscrowRequest{EscrowID: terms.EscrowId, Creator: creator, Agent: agent, BudgetNanoTOS: reserve.Uint64(), DeadlineUnix: uint64(terms.EscrowDeadlineUnixMillis / 1000), PolicyHash: policyHash, PermissionHash: reservationDigest})
		if resolveErr != nil {
			return nil, economicRPCError(resolveErr, "resolve TOS Task Escrow")
		}
		if !found {
			return connect.NewResponse(&atostosv1.GetEscrowResponse{}), nil
		}
		if req.Msg.ExpectedEscrowRef != nil && (req.Msg.ExpectedEscrowRef.Network != s.economy.Network() || req.Msg.ExpectedEscrowRef.Reference != resolved.ContractReference || req.Msg.ExpectedEscrowRef.FinalizedCheckpoint > resolved.State.ObservedMasterSeqno) {
			return nil, conflict("ESCROW_MISMATCH", "canonical escrow reference mismatch")
		}
		if response.Found && response.Escrow.FinalizedCheckpoint > resolved.State.ObservedMasterSeqno {
			return nil, unavailable("NETWORK_UNAVAILABLE", "TaskEscrow checkpoint regressed")
		}
		state := atostosv1.EscrowState_ESCROW_STATE_UNSPECIFIED
		switch resolved.State.Status {
		case chain.TaskEscrowStatusOpen, chain.TaskEscrowStatusAccepted:
			state = atostosv1.EscrowState_ESCROW_STATE_RESERVED
		case chain.TaskEscrowStatusCancelled, chain.TaskEscrowStatusExpired, chain.TaskEscrowStatusRejected:
			state = atostosv1.EscrowState_ESCROW_STATE_RELEASED
		case chain.TaskEscrowStatusSettled:
			state = atostosv1.EscrowState_ESCROW_STATE_SETTLED
		case chain.TaskEscrowStatusDisputed:
			state = atostosv1.EscrowState_ESCROW_STATE_DISPUTED
		default:
			return nil, failedPrecondition("ESCROW_MISMATCH", "canonical TaskEscrow state is not legal for this lifecycle")
		}
		response.Escrow = &atostosv1.Escrow{EscrowId: terms.EscrowId, QuoteId: terms.QuoteId, JobId: terms.JobId, PrincipalId: terms.PrincipalId, ProviderId: terms.ProviderId, CapabilityId: terms.CapabilityId, CapabilityVersion: terms.CapabilityVersion, TrustMode: terms.TrustMode, ProofProfile: terms.ProofProfile, Reserved: cloneMessage(terms.Reserve), State: state, ExpiresUnixMillis: terms.EscrowDeadlineUnixMillis, EscrowRef: &NetworkReference{Network: s.economy.Network(), Reference: resolved.ContractReference, Finalized: true, FinalizedCheckpoint: resolved.State.ObservedMasterSeqno}, FundingModel: terms.FundingModel, QuoteCommitmentDigest: terms.QuoteCommitmentDigest, QuoteCommitmentRef: cloneMessage(terms.QuoteCommitmentRef), ReservationDigest: reservationDigest, ReservationActionId: resolved.ActionID, ContractCodeHash: resolved.State.CodeHash, Finalized: true, FinalizedCheckpoint: resolved.State.ObservedMasterSeqno}
		response.Found = true
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
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	if err := requiredIdentifier("escrow_id", req.Msg.EscrowId); err != nil {
		return nil, err
	}
	var canonicalEscrow *atostosv1.Escrow
	if req.Msg.ExpectedTerms != nil {
		lookup, lookupErr := s.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{Context: req.Msg.Context, EscrowId: req.Msg.EscrowId, QuoteId: req.Msg.QuoteId, ExpectedTerms: req.Msg.ExpectedTerms, ExpectedEscrowRef: req.Msg.ExpectedEscrowRef, ExpectedReservationDigest: req.Msg.ExpectedReservationDigest}))
		if lookupErr != nil {
			return nil, lookupErr
		}
		if lookup.Msg == nil || !lookup.Msg.Found || lookup.Msg.Escrow == nil {
			return nil, unavailable("NETWORK_UNAVAILABLE", "canonical TaskEscrow reservation is not recoverable")
		}
		canonicalEscrow = lookup.Msg.Escrow
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
		if !found && canonicalEscrow != nil {
			escrow = cloneMessage(canonicalEscrow)
			found = true
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
		if escrow.State == atostosv1.EscrowState_ESCROW_STATE_RELEASED && escrow.TrustMode != TrustModeVerified {
			response.Escrow = escrow
			response.ReleaseRef = cloneMessage(escrow.ReleaseRef)
			response.Released = true
			return nil
		}
		digest, err := protoDigest("ATOS-TOS-ESCROW-RELEASE-V1", withoutTransportContext(req.Msg))
		if err != nil {
			return err
		}
		var ref NetworkReference
		var economicResult economic.Result
		switch escrow.TrustMode {
		case TrustModeManaged:
			ref, err = s.authority.Commit(ctx, "escrow-release", escrow.EscrowId, digest)
			if err != nil {
				return unavailable("NETWORK_UNAVAILABLE", "escrow release authority is unavailable")
			}
		case TrustModeVerified:
			if req.Msg.ExpectedTerms == nil || escrow.ReservationDigest != req.Msg.ExpectedReservationDigest && req.Msg.ExpectedReservationDigest != "" {
				return failedPrecondition("ESCROW_MISMATCH", "verified release requires the original reservation tuple")
			}
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
			ref.Finalized = true
			ref.FinalizedCheckpoint = result.State.ObservedMasterSeqno
			economicResult = result
		default:
			return failedPrecondition("TRUST_MODE_UNAVAILABLE", "economic escrow mode is unavailable")
		}
		escrow.State = atostosv1.EscrowState_ESCROW_STATE_RELEASED
		if escrow.TrustMode == TrustModeVerified {
			escrow.ReleaseRef = cloneMessage(&ref)
			escrow.ReleaseReasonCode = req.Msg.ReasonCode
			escrow.ReleaseActionId = economicResult.ActionID
			escrow.Finalized = true
			escrow.FinalizedCheckpoint = economicResult.State.ObservedMasterSeqno
			escrow.ContractCodeHash = economicResult.State.CodeHash
			releaseDigest, digestErr := protoDigest("tos.atos.verified-task-escrow-release.v1", withoutTransportContext(req.Msg))
			if digestErr != nil {
				return digestErr
			}
			escrow.ReleaseDigest = releaseDigest
		}
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
