package atosrpc

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"time"

	"connectrpc.com/connect"
	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/disputecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/economic"
	"github.com/tosnetwork/tos-protocol/pkg/escrowcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/quotecommitment"
	"github.com/tosnetwork/tos-protocol/pkg/receiptcommitment"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
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
		if existingID := tx.Bucket(bucketEscrowByQuote).Get([]byte(req.Msg.QuoteId)); existingID != nil {
			if req.Msg.TrustMode == TrustModeVerified && string(existingID) != verifiedTerms.EscrowId {
				return failedPrecondition("IDEMPOTENCY_CONFLICT", "verified Quote already funded another Job/TaskEscrow")
			}
			if req.Msg.TrustMode == TrustModeVerified {
				// Continue through live canonical resolution; a local record is not
				// sufficient evidence for a usable Verified escrow.
			} else {
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
			// The fixed dispute policy is the contract policy that the
			// key-custody publisher can allowlist. The unique reservation tuple
			// is already bound by permissionHash below.
			policyHash, policyErr := digestString(verifiedTerms.DisputePolicyDigest)
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
	var projectedResolutionDigest, projectedDisputeOutcome string
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
			projectedResolutionDigest, projectedDisputeOutcome = escrow.DisputeResolutionDigest, escrow.DisputeOutcome
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if req.Msg.ExpectedTerms != nil {
		terms := req.Msg.ExpectedTerms
		_, _, _, validationErr := s.validateVerifiedEscrowTerms(ctx, terms)
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
			if req.Msg.ExpectedCreatorAddress == "" || req.Msg.ExpectedAgentAddress == "" {
				return nil, partyErr
			}
			creator, partyErr = toschain.CanonicalAddress(req.Msg.ExpectedCreatorAddress)
			if partyErr == nil {
				agent, partyErr = toschain.CanonicalAddress(req.Msg.ExpectedAgentAddress)
			}
			if partyErr != nil {
				return nil, conflict("ESCROW_MISMATCH", "expected economic identity controller is invalid")
			}
		} else if req.Msg.ExpectedCreatorAddress != "" || req.Msg.ExpectedAgentAddress != "" {
			expectedCreator, creatorErr := toschain.CanonicalAddress(req.Msg.ExpectedCreatorAddress)
			expectedAgent, agentErr := toschain.CanonicalAddress(req.Msg.ExpectedAgentAddress)
			if creatorErr != nil || agentErr != nil || expectedCreator != creator || expectedAgent != agent {
				return nil, conflict("ESCROW_MISMATCH", "expected economic identity controller mismatch")
			}
		}
		reserve, parseErr := parseAtomic(terms.Reserve.AtomicAmount)
		if parseErr != nil || !reserve.IsUint64() {
			return nil, invalid("INVALID_ARGUMENT", "invalid reserve")
		}
		policyHash, policyErr := digestString(terms.DisputePolicyDigest)
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
		case chain.TaskEscrowStatusOpen, chain.TaskEscrowStatusAccepted, chain.TaskEscrowStatusResultSubmitted:
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
		if state == atostosv1.EscrowState_ESCROW_STATE_RELEASED || state == atostosv1.EscrowState_ESCROW_STATE_SETTLED {
			if state == atostosv1.EscrowState_ESCROW_STATE_RELEASED {
				if digestErr := validateDigest(digestMessageFromString(req.Msg.ExpectedReleaseDigest)); digestErr != nil || strings.TrimSpace(req.Msg.ExpectedReleaseReasonCode) == "" {
					return nil, failedPrecondition("ESCROW_MISMATCH", "expected release tuple is required for terminal recovery")
				}
				resolver, ok := s.economy.(economic.ReleaseResolver)
				if !ok {
					return nil, unavailable("NETWORK_UNAVAILABLE", "read-only TaskEscrow release resolver unavailable")
				}
				terminal, terminalErr := resolver.ResolveRelease(ctx, economic.RefundPrincipalRequest{
					EscrowID: terms.EscrowId, ContractAddress: resolved.State.ContractAddress,
					BudgetNanoTOS: reserve.Uint64(), ReleaseDigest: req.Msg.ExpectedReleaseDigest,
				})
				if terminalErr != nil || terminal.TransitionReference == "" || terminal.State.ObservedMasterSeqno == 0 {
					return nil, unavailable("NETWORK_UNAVAILABLE", "canonical release transition unavailable")
				}
				if expected := req.Msg.ExpectedTerminalRef; expected != nil &&
					(expected.Network != s.economy.Network() || expected.Reference != terminal.TransitionReference ||
						expected.FinalizedCheckpoint > terminal.State.ObservedMasterSeqno) {
					return nil, conflict("ESCROW_MISMATCH", "canonical release reference mismatch")
				}
				resolved.TransitionReference = terminal.TransitionReference
				resolved.State = terminal.State
				response.Escrow.ReleaseDigest = req.Msg.ExpectedReleaseDigest
				response.Escrow.ReleaseReasonCode = req.Msg.ExpectedReleaseReasonCode
				response.Escrow.ReleaseActionId = terminal.ActionID
				response.Escrow.ReleaseRef = &NetworkReference{Network: s.economy.Network(), Reference: terminal.TransitionReference, Finalized: true, FinalizedCheckpoint: terminal.State.ObservedMasterSeqno}
				response.Escrow.FinalizedCheckpoint = terminal.State.ObservedMasterSeqno
			} else if state == atostosv1.EscrowState_ESCROW_STATE_SETTLED {
				// ResolveEscrow's transition is the reservation/deploy observation.
				// A terminal reference is exposed only after the exact settlement
				// projection can reconstruct and independently observe its action.
				resolved.TransitionReference = ""
				if req.Msg.ExpectedDisputeDigest != "" {
					if req.Msg.ExpectedDisputeResolution == nil {
						return nil, failedPrecondition("DISPUTE_MISMATCH", "complete canonical dispute resolution is required")
					}
					resolutionDigest, resolutionErr := disputecommitment.ResolutionDigest(req.Msg.ExpectedDisputeResolution)
					if resolutionErr != nil || resolutionDigest != req.Msg.ExpectedDisputeResolutionDigest || req.Msg.ExpectedDisputeResolution.DisputeDigest != req.Msg.ExpectedDisputeDigest || req.Msg.ExpectedDisputeResolution.Outcome != req.Msg.ExpectedDisputeOutcome {
						return nil, conflict("DISPUTE_MISMATCH", "canonical dispute resolution projection mismatch")
					}
					resolverAuthority, ok := s.authority.(CommitmentResolver)
					if !ok || req.Msg.ExpectedDisputeResolutionRef == nil {
						return nil, unavailable("NETWORK_UNAVAILABLE", "dispute resolution commitment resolver unavailable")
					}
					liveResolution, liveResolutionErr := resolverAuthority.ResolveCommitment(ctx, "dispute-resolution", req.Msg.ExpectedDisputeResolution.DisputeId, resolutionDigest, req.Msg.ExpectedDisputeResolutionRef)
					if liveResolutionErr != nil || liveResolution == nil || !liveResolution.Finalized || liveResolution.FinalizedCheckpoint == 0 {
						return nil, unavailable("NETWORK_UNAVAILABLE", "dispute resolution commitment unavailable")
					}
					if projectedResolutionDigest != "" && (projectedResolutionDigest != resolutionDigest || projectedDisputeOutcome != req.Msg.ExpectedDisputeOutcome) {
						return nil, conflict("DISPUTE_MISMATCH", "local dispute resolution projection mismatch")
					}
					payout, payoutErr := parseAtomic(req.Msg.ExpectedDisputePayout.GetAtomicAmount())
					resolver, ok := s.economy.(economic.DisputeResolver)
					if payoutErr != nil || !payout.IsUint64() || !ok {
						return nil, failedPrecondition("DISPUTE_MISMATCH", "exact dispute payout and resolver are required")
					}
					terminal, terminalErr := resolver.ResolveDisputeOutcome(ctx, economic.ResolveDisputeRequest{EscrowID: terms.EscrowId, ContractAddress: resolved.State.ContractAddress, BudgetNanoTOS: reserve.Uint64(), PayoutNanoTOS: payout.Uint64()})
					if terminalErr != nil || terminal.State.DisputeHash != req.Msg.ExpectedDisputeDigest || terminal.TransitionReference == "" || terminal.State.ObservedMasterSeqno == 0 {
						return nil, unavailable("NETWORK_UNAVAILABLE", "canonical dispute resolution unavailable")
					}
					if expected := req.Msg.ExpectedTerminalRef; expected != nil && (expected.Network != s.economy.Network() || expected.Reference != terminal.TransitionReference || expected.FinalizedCheckpoint > terminal.State.ObservedMasterSeqno) {
						return nil, conflict("DISPUTE_MISMATCH", "canonical dispute resolution reference mismatch")
					}
					resolved.TransitionReference, resolved.State = terminal.TransitionReference, terminal.State
					response.Escrow.DisputeDigest = req.Msg.ExpectedDisputeDigest
					response.Escrow.DisputeRef = cloneMessage(req.Msg.ExpectedDisputeRef)
					response.Escrow.DisputeResolutionDigest = resolutionDigest
					response.Escrow.DisputeResolutionRef = liveResolution
					response.Escrow.DisputeOutcome = req.Msg.ExpectedDisputeOutcome
					response.Escrow.FinalizedCheckpoint = terminal.State.ObservedMasterSeqno
				} else {
					resolver, ok := s.economy.(economic.SettlementResolver)
					if !ok {
						return nil, unavailable("NETWORK_UNAVAILABLE", "read-only TaskEscrow settlement resolver unavailable")
					}
					var settlement *atostosv1.Settlement
					var receipt *atostosv1.CommittedExecutionReceipt
					loadErr := s.store.view(func(tx *bolt.Tx) error {
						id := tx.Bucket(bucketSettlementByJob).Get([]byte(terms.JobId))
						if id == nil {
							return errors.New("settlement projection unavailable")
						}
						settlement = new(atostosv1.Settlement)
						found, err := s.store.getProto(tx, bucketSettlements, string(id), settlement)
						if err != nil || !found {
							return errors.New("settlement projection unavailable")
						}
						receipt = new(atostosv1.CommittedExecutionReceipt)
						found, err = s.store.getProto(tx, bucketReceipts, settlement.ReceiptId, receipt)
						if err != nil || !found || receipt.Receipt == nil {
							return errors.New("settlement receipt unavailable")
						}
						return nil
					})
					if loadErr != nil {
						if req.Msg.ExpectedTerminalRef == nil {
							response.Found = true
							return connect.NewResponse(response), nil
						}
						if req.Msg.ExpectedReceipt == nil || req.Msg.ExpectedReceiptRef == nil || req.Msg.ExpectedSettlementCharge == nil {
							return nil, unavailable("NETWORK_UNAVAILABLE", "complete expected settlement tuple is required for projection-free recovery")
						}
						resolvedReceipt, receiptErr := s.resolveExpectedReceipt(ctx, req.Msg.Context, req.Msg.ExpectedReceipt, req.Msg.ExpectedReceiptRef)
						if receiptErr != nil || resolvedReceipt.JobId != terms.JobId || resolvedReceipt.QuoteId != terms.QuoteId || resolvedReceipt.EscrowId != terms.EscrowId {
							return nil, conflict("SETTLEMENT_FAILED", "canonical settlement receipt mismatch")
						}
						settlement = &atostosv1.Settlement{ReceiptId: resolvedReceipt.ReceiptId, Charged: cloneMessage(req.Msg.ExpectedSettlementCharge), SettlementRef: cloneMessage(req.Msg.ExpectedTerminalRef)}
						receipt = &atostosv1.CommittedExecutionReceipt{Receipt: cloneMessage(resolvedReceipt), ReceiptRef: cloneMessage(req.Msg.ExpectedReceiptRef)}
					}
					if settlement.SettlementRef == nil || settlement.Charged == nil {
						return nil, unavailable("NETWORK_UNAVAILABLE", "canonical settlement projection is malformed")
					}
					resultHash, hashErr := digestString(receipt.Receipt.OutputCommitment)
					if hashErr != nil {
						return nil, hashErr
					}
					evidenceHash, evidenceErr := protoDigest("ATOS-TOS-TASK-EVIDENCE-V1", receipt.Receipt)
					if evidenceErr != nil {
						return nil, evidenceErr
					}
					charge, chargeErr := parseAtomic(settlement.Charged.AtomicAmount)
					if chargeErr != nil || !charge.IsUint64() {
						return nil, failedPrecondition("SETTLEMENT_FAILED", "stored settlement charge is invalid")
					}
					terminal, terminalErr := resolver.ResolveSettlement(ctx, economic.SettleProviderRequest{EscrowID: terms.EscrowId, ContractAddress: resolved.State.ContractAddress, BudgetNanoTOS: reserve.Uint64(), ResultHash: resultHash, EvidenceHash: evidenceHash, PayoutNanoTOS: charge.Uint64()})
					if terminalErr != nil || terminal.TransitionReference != settlement.SettlementRef.Reference || terminal.State.ObservedMasterSeqno == 0 {
						return nil, unavailable("NETWORK_UNAVAILABLE", "canonical settlement transition unavailable")
					}
					resolved.TransitionReference = terminal.TransitionReference
					resolved.State = terminal.State
					response.Escrow.FinalizedCheckpoint = terminal.State.ObservedMasterSeqno
				}
			}
			if strings.TrimSpace(resolved.TransitionReference) == "" {
				response.Found = true
				return connect.NewResponse(response), nil
			}
			response.Escrow.TerminalRef = &NetworkReference{Network: s.economy.Network(), Reference: resolved.TransitionReference, Finalized: true, FinalizedCheckpoint: resolved.State.ObservedMasterSeqno}
		}
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
	if strings.TrimSpace(req.Msg.ReasonCode) == "" || len(req.Msg.ReasonCode) > 128 {
		return nil, invalid("INVALID_ARGUMENT", "release reason_code is required")
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
			releaseDigest, digestErr := escrowcommitment.ReleaseDigest(
				escrow.ReservationDigest, escrow.EscrowId, escrow.JobId, escrow.QuoteId, req.Msg.ReasonCode,
			)
			if digestErr != nil {
				return failedPrecondition("ESCROW_MISMATCH", digestErr.Error())
			}
			result, economicErr := s.economy.ReleaseEscrow(ctx, economic.ReleaseEscrowRequest{
				EscrowID: escrow.EscrowId, ContractAddress: contractAddress,
				BudgetNanoTOS: reserved.Uint64(), ReasonCode: req.Msg.ReasonCode,
				ReleaseDigest: releaseDigest,
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
			releaseDigest, digestErr := escrowcommitment.ReleaseDigest(escrow.ReservationDigest, escrow.EscrowId, escrow.JobId, escrow.QuoteId, req.Msg.ReasonCode)
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

func (s *Server) resolveExpectedReceipt(ctx context.Context, requestContext *atostosv1.RequestContext, receipt *atostosv1.ExecutionReceiptEnvelope, expected *NetworkReference) (*atostosv1.ExecutionReceiptEnvelope, error) {
	if receipt == nil || expected == nil {
		return nil, failedPrecondition("RECEIPT_INVALID", "exact finalized Receipt evidence is required")
	}
	resolved, err := s.ResolveExecutionReceipt(ctx, connect.NewRequest(&atostosv1.ResolveExecutionReceiptRequest{Context: requestContext, Receipt: receipt, ExpectedReceiptRef: expected}))
	if err != nil {
		return nil, err
	}
	if resolved.Msg == nil || !resolved.Msg.Found || resolved.Msg.ReceiptRef == nil || resolved.Msg.ReceiptRef.Network != s.economy.Network() || resolved.Msg.ReceiptRef.Reference != expected.Reference || !resolved.Msg.ReceiptRef.Finalized || resolved.Msg.ReceiptRef.FinalizedCheckpoint == 0 || resolved.Msg.ReceiptRef.FinalizedCheckpoint < expected.FinalizedCheckpoint {
		return nil, failedPrecondition("RECEIPT_INVALID", "canonical Receipt commitment unavailable or regressed")
	}
	return receipt, nil
}

func (s *Server) PrepareVerifiedResult(ctx context.Context, req *connect.Request[atostosv1.PrepareVerifiedResultRequest]) (*connect.Response[atostosv1.PrepareVerifiedResultResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.ExpectedTerms == nil {
		return nil, invalid("INVALID_ARGUMENT", "verified result request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	if req.Msg.Context == nil || req.Msg.Context.CallerId != req.Msg.ExpectedTerms.PrincipalId {
		return nil, permissionDenied("PERMISSION_DENIED", "requester context does not match Verified escrow")
	}
	lookup, err := s.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{Context: req.Msg.Context, EscrowId: req.Msg.EscrowId, QuoteId: req.Msg.QuoteId, ExpectedTerms: req.Msg.ExpectedTerms, ExpectedEscrowRef: req.Msg.ExpectedEscrowRef, ExpectedReservationDigest: req.Msg.ExpectedReservationDigest}))
	if err != nil || !lookup.Msg.Found || lookup.Msg.Escrow == nil {
		if err != nil {
			return nil, err
		}
		return nil, notFound("NOT_FOUND", "verified escrow not found")
	}
	escrow := lookup.Msg.Escrow
	if escrow.JobId != req.Msg.JobId || escrow.State != atostosv1.EscrowState_ESCROW_STATE_RESERVED {
		return nil, failedPrecondition("ESCROW_MISMATCH", "verified escrow is not result-ready")
	}
	receipt, err := s.resolveExpectedReceipt(ctx, req.Msg.Context, req.Msg.ExpectedReceipt, req.Msg.ExpectedReceiptRef)
	if err != nil {
		return nil, err
	}
	if receipt.ReceiptId != req.Msg.ReceiptId || receipt.JobId != req.Msg.JobId || receipt.QuoteId != req.Msg.QuoteId || receipt.EscrowId != req.Msg.EscrowId {
		return nil, failedPrecondition("RECEIPT_INVALID", "verified Receipt tuple mismatch")
	}
	contract, err := economicContractAddress(escrow.EscrowRef)
	if err != nil {
		return nil, failedPrecondition("ESCROW_MISMATCH", err.Error())
	}
	resultHash, err := digestString(receipt.OutputCommitment)
	if err != nil {
		return nil, failedPrecondition("RECEIPT_INVALID", "Receipt result digest invalid")
	}
	evidenceHash, err := protoDigest("ATOS-TOS-TASK-EVIDENCE-V1", receipt)
	if err != nil {
		return nil, err
	}
	accepted, err := s.economy.AcceptEscrow(ctx, economic.AcceptEscrowRequest{EscrowID: escrow.EscrowId, ContractAddress: contract, ExpectedAgent: ""})
	if err != nil {
		return nil, economicRPCError(err, "accept TOS TaskEscrow")
	}
	_ = accepted
	committed, err := s.economy.CommitResult(ctx, economic.CommitResultRequest{EscrowID: escrow.EscrowId, ContractAddress: contract, ResultHash: resultHash, EvidenceHash: evidenceHash})
	if err != nil {
		return nil, economicRPCError(err, "commit TOS TaskEscrow result")
	}
	if committed.State.Status != chain.TaskEscrowStatusResultSubmitted || committed.State.ReviewDeadlineUnix == 0 || committed.State.ObservedMasterSeqno == 0 || committed.TransitionReference == "" {
		return nil, failedPrecondition("ECONOMIC_TRANSITION_FAILED", "TaskEscrow result is not finalized")
	}
	escrow.ResultRef = &NetworkReference{Network: s.economy.Network(), Reference: committed.TransitionReference, Finalized: true, FinalizedCheckpoint: committed.State.ObservedMasterSeqno}
	escrow.ResultDigest = resultHash
	escrow.ResultEvidenceDigest = evidenceHash
	escrow.ReviewDeadlineUnixMillis = int64(committed.State.ReviewDeadlineUnix) * 1000
	escrow.FinalizedCheckpoint = committed.State.ObservedMasterSeqno
	if err = s.store.update(func(tx *bolt.Tx) error { return s.store.putProto(tx, bucketEscrows, escrow.EscrowId, escrow) }); err != nil {
		return nil, err
	}
	return connect.NewResponse(&atostosv1.PrepareVerifiedResultResponse{Escrow: escrow, Prepared: true}), nil
}

func (s *Server) OpenVerifiedDispute(ctx context.Context, req *connect.Request[atostosv1.OpenVerifiedDisputeRequest]) (*connect.Response[atostosv1.OpenVerifiedDisputeResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Dispute == nil || req.Msg.ExpectedTerms == nil {
		return nil, invalid("INVALID_ARGUMENT", "verified dispute request is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	digest, err := disputecommitment.OpenDigest(req.Msg.Dispute)
	if err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	d := req.Msg.Dispute
	if req.Msg.Context == nil || req.Msg.Context.CallerId != d.PrincipalId {
		return nil, permissionDenied("PERMISSION_DENIED", "only the canonical requester may open this dispute")
	}
	if d.Version != "atos_verified_dispute_open_v1" || d.NetworkId != s.economy.Network() || d.GatewayDomain != s.config.TrustDomain || d.EscrowId != req.Msg.ExpectedTerms.EscrowId || d.JobId != req.Msg.ExpectedTerms.JobId || d.QuoteId != req.Msg.ExpectedTerms.QuoteId || d.PrincipalId != req.Msg.ExpectedTerms.PrincipalId || d.ProviderId != req.Msg.ExpectedTerms.ProviderId || d.CapabilityId != req.Msg.ExpectedTerms.CapabilityId || d.CapabilityVersion != req.Msg.ExpectedTerms.CapabilityVersion || d.QuoteCommitmentDigest != req.Msg.ExpectedTerms.QuoteCommitmentDigest || d.ReservationDigest != req.Msg.ExpectedReservationDigest {
		return nil, conflict("DISPUTE_MISMATCH", "verified dispute tuple mismatch")
	}
	lookup, err := s.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{Context: req.Msg.Context, EscrowId: d.EscrowId, QuoteId: d.QuoteId, ExpectedTerms: req.Msg.ExpectedTerms, ExpectedEscrowRef: req.Msg.ExpectedEscrowRef, ExpectedReservationDigest: req.Msg.ExpectedReservationDigest}))
	if err != nil {
		return nil, err
	}
	if !lookup.Msg.Found || lookup.Msg.Escrow == nil {
		return nil, failedPrecondition("DISPUTE_NOT_ELIGIBLE", "canonical escrow unavailable")
	}
	escrow := lookup.Msg.Escrow
	if req.Msg.ExpectedResultRef == nil || strings.TrimSpace(req.Msg.ExpectedResultHash) == "" || strings.TrimSpace(req.Msg.ExpectedEvidenceHash) == "" {
		return nil, failedPrecondition("DISPUTE_NOT_ELIGIBLE", "exact result tuple is required")
	}
	contract, err := economicContractAddress(escrow.EscrowRef)
	if err != nil {
		return nil, failedPrecondition("ESCROW_MISMATCH", err.Error())
	}
	resolver, ok := s.economy.(economic.DisputeResolver)
	if !ok {
		return nil, unavailable("NETWORK_UNAVAILABLE", "read-only result resolver unavailable")
	}
	canonicalResult, err := resolver.ResolveResult(ctx, economic.CommitResultRequest{EscrowID: d.EscrowId, ContractAddress: contract, ResultHash: req.Msg.ExpectedResultHash, EvidenceHash: req.Msg.ExpectedEvidenceHash})
	if err != nil || canonicalResult.State.ObservedMasterSeqno == 0 || canonicalResult.TransitionReference == "" || canonicalResult.State.ReviewDeadlineUnix == 0 {
		return nil, unavailable("NETWORK_UNAVAILABLE", "canonical result transition unavailable")
	}
	if req.Msg.ExpectedResultRef.Network != s.economy.Network() || req.Msg.ExpectedResultRef.Reference != canonicalResult.TransitionReference || req.Msg.ExpectedResultRef.FinalizedCheckpoint > canonicalResult.State.ObservedMasterSeqno {
		return nil, conflict("DISPUTE_MISMATCH", "canonical result reference mismatch")
	}
	if canonicalResult.State.Status == chain.TaskEscrowStatusResultSubmitted && (s.now().Unix() > int64(canonicalResult.State.ReviewDeadlineUnix) || d.OpenedUnixMillis > int64(canonicalResult.State.ReviewDeadlineUnix)*1000 || d.OpenedUnixMillis > s.now().Add(time.Minute).UnixMilli()) {
		return nil, failedPrecondition("DISPUTE_NOT_ELIGIBLE", "canonical result review window expired")
	}
	escrow.ResultRef = &NetworkReference{Network: s.economy.Network(), Reference: canonicalResult.TransitionReference, Finalized: true, FinalizedCheckpoint: canonicalResult.State.ObservedMasterSeqno}
	escrow.ReviewDeadlineUnixMillis = int64(canonicalResult.State.ReviewDeadlineUnix) * 1000
	receipt, err := s.resolveExpectedReceipt(ctx, req.Msg.Context, req.Msg.ExpectedReceipt, req.Msg.ExpectedReceiptRef)
	if err != nil {
		return nil, failedPrecondition("RECEIPT_INVALID", err.Error())
	}
	receiptDigest, err := receiptcommitment.Digest(receipt)
	expectedResultHash, resultHashErr := digestString(receipt.OutputCommitment)
	expectedEvidenceHash, evidenceHashErr := protoDigest("ATOS-TOS-TASK-EVIDENCE-V1", receipt)
	policyMatches := d.DisputePolicyDigest != nil && req.Msg.ExpectedTerms.DisputePolicyDigest != nil && strings.EqualFold(d.DisputePolicyDigest.Algorithm, req.Msg.ExpectedTerms.DisputePolicyDigest.Algorithm) && bytes.Equal(d.DisputePolicyDigest.Value, req.Msg.ExpectedTerms.DisputePolicyDigest.Value)
	if err != nil || resultHashErr != nil || evidenceHashErr != nil || receiptDigest != d.ReceiptDigest || receipt.JobId != d.JobId || receipt.QuoteId != d.QuoteId || receipt.EscrowId != d.EscrowId || receipt.PrincipalId != d.PrincipalId || receipt.ProviderId != d.ProviderId || receipt.CapabilityId != d.CapabilityId || receipt.CapabilityVersion != d.CapabilityVersion || d.OpenedUnixMillis < receipt.CompletedUnixMillis || !policyMatches || req.Msg.ExpectedResultHash != expectedResultHash || req.Msg.ExpectedEvidenceHash != expectedEvidenceHash {
		return nil, conflict("DISPUTE_MISMATCH", "Receipt commitment mismatch")
	}
	result, err := s.economy.OpenDispute(ctx, economic.OpenDisputeRequest{EscrowID: d.EscrowId, ContractAddress: contract, DisputeHash: digest})
	if err != nil {
		return nil, economicRPCError(err, "open TOS TaskEscrow dispute")
	}
	if result.State.Status != chain.TaskEscrowStatusDisputed || result.State.DisputeHash != digest || result.State.ObservedMasterSeqno == 0 || result.TransitionReference == "" {
		return nil, failedPrecondition("ECONOMIC_TRANSITION_FAILED", "TaskEscrow dispute is not finalized")
	}
	ref := &NetworkReference{Network: s.economy.Network(), Reference: result.TransitionReference, Finalized: true, FinalizedCheckpoint: result.State.ObservedMasterSeqno}
	escrow.State = atostosv1.EscrowState_ESCROW_STATE_DISPUTED
	escrow.DisputeDigest = digest
	escrow.DisputeRef = ref
	escrow.FinalizedCheckpoint = result.State.ObservedMasterSeqno
	if err = s.store.update(func(tx *bolt.Tx) error { return s.store.putProto(tx, bucketEscrows, escrow.EscrowId, escrow) }); err != nil {
		return nil, err
	}
	return connect.NewResponse(&atostosv1.OpenVerifiedDisputeResponse{Escrow: escrow, DisputeDigest: digest, DisputeRef: ref, Opened: true}), nil
}

func (s *Server) ResolveVerifiedDispute(ctx context.Context, req *connect.Request[atostosv1.ResolveVerifiedDisputeRequest]) (*connect.Response[atostosv1.ResolveVerifiedDisputeResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.Resolution == nil || req.Msg.ExpectedTerms == nil {
		return nil, invalid("INVALID_ARGUMENT", "verified dispute resolution is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	r := req.Msg.Resolution
	if req.Msg.Context == nil || req.Msg.Context.CallerId != r.ReviewerPrincipalId {
		return nil, permissionDenied("PERMISSION_DENIED", "reviewer context mismatch")
	}
	digest, err := disputecommitment.ResolutionDigest(r)
	if err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
	}
	if r.Version != "atos_verified_dispute_resolution_v1" || r.ReviewerPrincipalId == req.Msg.ExpectedTerms.PrincipalId || r.ReviewerPrincipalId == req.Msg.ExpectedTerms.ProviderId {
		return nil, permissionDenied("PERMISSION_DENIED", "a dispute party cannot resolve the dispute")
	}
	lookup, err := s.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{Context: req.Msg.Context, EscrowId: r.EscrowId, QuoteId: r.QuoteId, ExpectedTerms: req.Msg.ExpectedTerms, ExpectedEscrowRef: req.Msg.ExpectedEscrowRef, ExpectedReservationDigest: req.Msg.ExpectedReservationDigest, ExpectedDisputeDigest: r.DisputeDigest, ExpectedDisputeRef: req.Msg.ExpectedDisputeRef, ExpectedDisputePayout: r.ProviderPayout}))
	if err != nil {
		return nil, err
	}
	if !lookup.Msg.Found || lookup.Msg.Escrow == nil {
		return nil, notFound("NOT_FOUND", "verified escrow not found")
	}
	escrow := lookup.Msg.Escrow
	if (escrow.State != atostosv1.EscrowState_ESCROW_STATE_DISPUTED && escrow.State != atostosv1.EscrowState_ESCROW_STATE_SETTLED) || r.DisputeId == "" || r.JobId != escrow.JobId || r.QuoteId != escrow.QuoteId || r.ReceiptId == "" || r.NetworkId != s.economy.Network() || r.GatewayDomain != s.config.TrustDomain {
		return nil, conflict("DISPUTE_MISMATCH", "canonical disputed escrow mismatch")
	}
	if req.Msg.ExpectedDisputeRef == nil || r.DisputeDigest == "" {
		return nil, conflict("DISPUTE_MISMATCH", "exact dispute tuple is required")
	}
	contract, e := economicContractAddress(escrow.EscrowRef)
	if e != nil {
		return nil, failedPrecondition("ESCROW_MISMATCH", e.Error())
	}
	resolver, ok := s.economy.(economic.DisputeResolver)
	if !ok {
		return nil, unavailable("NETWORK_UNAVAILABLE", "read-only dispute resolver unavailable")
	}
	canonicalDispute := economic.Result{State: chain.TaskEscrowState{ObservedMasterSeqno: escrow.FinalizedCheckpoint}, TransitionReference: req.Msg.ExpectedDisputeRef.Reference}
	if escrow.State == atostosv1.EscrowState_ESCROW_STATE_DISPUTED {
		canonicalDispute, e = resolver.ResolveDisputeOpen(ctx, economic.OpenDisputeRequest{EscrowID: escrow.EscrowId, ContractAddress: contract, DisputeHash: r.DisputeDigest})
		if e != nil || canonicalDispute.State.ObservedMasterSeqno == 0 || canonicalDispute.TransitionReference == "" {
			return nil, unavailable("NETWORK_UNAVAILABLE", "canonical dispute transition unavailable")
		}
		if req.Msg.ExpectedDisputeRef.Network != s.economy.Network() || req.Msg.ExpectedDisputeRef.Reference != canonicalDispute.TransitionReference || req.Msg.ExpectedDisputeRef.FinalizedCheckpoint > canonicalDispute.State.ObservedMasterSeqno {
			return nil, conflict("DISPUTE_MISMATCH", "dispute reference mismatch")
		}
	}
	escrow.DisputeDigest = r.DisputeDigest
	escrow.DisputeRef = &NetworkReference{Network: s.economy.Network(), Reference: canonicalDispute.TransitionReference, Finalized: true, FinalizedCheckpoint: canonicalDispute.State.ObservedMasterSeqno}
	reserved, e := parseAtomic(r.Reserved.GetAtomicAmount())
	if e != nil || !reserved.IsUint64() {
		return nil, invalid("INVALID_ARGUMENT", "invalid dispute reserve")
	}
	if r.Reserved.Asset != req.Msg.ExpectedTerms.Reserve.Asset || r.Reserved.AtomicAmount != req.Msg.ExpectedTerms.Reserve.AtomicAmount || r.ProviderPayout.GetAsset() != r.Reserved.Asset || r.RequesterRefund.GetAsset() != r.Reserved.Asset {
		return nil, conflict("DISPUTE_MISMATCH", "dispute reserve or asset differs from the frozen escrow")
	}
	payout, e := parseAtomic(r.ProviderPayout.GetAtomicAmount())
	if e != nil || !payout.IsUint64() {
		return nil, invalid("INVALID_ARGUMENT", "invalid dispute payout")
	}
	refund, e := parseAtomic(r.RequesterRefund.GetAtomicAmount())
	if e != nil || !refund.IsUint64() || new(big.Int).Add(payout, refund).Cmp(reserved) != 0 {
		return nil, invalid("INVALID_ARGUMENT", "dispute money does not conserve reserve")
	}
	if (r.Outcome == "principal" && payout.Sign() != 0) || (r.Outcome != "principal" && r.Outcome != "provider" && r.Outcome != "rejected") {
		return nil, invalid("INVALID_ARGUMENT", "invalid dispute outcome allocation")
	}
	cr, receiptErr := s.resolveExpectedReceipt(ctx, req.Msg.Context, req.Msg.ExpectedReceipt, req.Msg.ExpectedReceiptRef)
	if receiptErr != nil {
		return nil, failedPrecondition("RECEIPT_INVALID", receiptErr.Error())
	}
	if cr.JobId != r.JobId || cr.QuoteId != r.QuoteId || cr.EscrowId != r.EscrowId || cr.PrincipalId != req.Msg.ExpectedTerms.PrincipalId || cr.ProviderId != req.Msg.ExpectedTerms.ProviderId || cr.CapabilityId != req.Msg.ExpectedTerms.CapabilityId || cr.CapabilityVersion != req.Msg.ExpectedTerms.CapabilityVersion || cr.NetworkCharge == nil || cr.NetworkCharge.Asset != r.Reserved.Asset {
		return nil, conflict("DISPUTE_MISMATCH", "committed Receipt differs from dispute resolution")
	}
	charge, chargeErr := parseAtomic(cr.NetworkCharge.AtomicAmount)
	if chargeErr != nil || !charge.IsUint64() || (r.Outcome != "principal" && charge.Cmp(payout) != 0) {
		return nil, conflict("DISPUTE_MISMATCH", "provider resolution payout differs from verified Receipt charge")
	}
	result, e := s.economy.ResolveDispute(ctx, economic.ResolveDisputeRequest{EscrowID: escrow.EscrowId, ContractAddress: contract, BudgetNanoTOS: reserved.Uint64(), PayoutNanoTOS: payout.Uint64()})
	if e != nil {
		return nil, economicRPCError(e, "resolve TOS TaskEscrow dispute")
	}
	if result.State.Status != chain.TaskEscrowStatusSettled || result.State.DisputeHash != r.DisputeDigest || result.State.ObservedMasterSeqno == 0 || result.TransitionReference == "" || result.AgentPaidNanoTOS != payout.Uint64() || result.CreatorPaidNanoTOS < refund.Uint64() {
		return nil, failedPrecondition("ECONOMIC_TRANSITION_FAILED", "TaskEscrow dispute resolution is not finalized")
	}
	ref := &NetworkReference{Network: s.economy.Network(), Reference: result.TransitionReference, Finalized: true, FinalizedCheckpoint: result.State.ObservedMasterSeqno}
	resolutionRef, resolutionCommitErr := s.authority.Commit(ctx, "dispute-resolution", r.DisputeId, digest)
	if resolutionCommitErr != nil || !resolutionRef.Finalized || resolutionRef.FinalizedCheckpoint == 0 {
		return nil, unavailable("NETWORK_UNAVAILABLE", "dispute resolution commitment unavailable")
	}
	settlement := &atostosv1.Settlement{SettlementId: "dispute-settlement:" + r.DisputeId, EscrowId: r.EscrowId, QuoteId: r.QuoteId, JobId: r.JobId, ReceiptId: r.ReceiptId, Charged: cloneMessage(r.ProviderPayout), Refunded: cloneMessage(r.RequesterRefund), State: atostosv1.SettlementState_SETTLEMENT_STATE_SETTLED, SettlementRef: ref, SettledUnixMillis: s.now().UnixMilli()}
	escrow.State = atostosv1.EscrowState_ESCROW_STATE_SETTLED
	escrow.TerminalRef = ref
	escrow.DisputeResolutionDigest = digest
	escrow.DisputeResolutionRef = &resolutionRef
	escrow.DisputeOutcome = r.Outcome
	escrow.FinalizedCheckpoint = result.State.ObservedMasterSeqno
	if e = s.store.update(func(tx *bolt.Tx) error {
		if e := s.store.putProto(tx, bucketEscrows, escrow.EscrowId, escrow); e != nil {
			return e
		}
		return s.store.putProto(tx, bucketSettlements, settlement.SettlementId, settlement)
	}); e != nil {
		return nil, e
	}
	return connect.NewResponse(&atostosv1.ResolveVerifiedDisputeResponse{Escrow: escrow, Settlement: settlement, ResolutionDigest: digest, ResolutionRef: &resolutionRef, Resolved: true}), nil
}

func (s *Server) SettleJob(
	ctx context.Context,
	req *connect.Request[atostosv1.SettleJobRequest],
) (*connect.Response[atostosv1.SettleJobResponse], error) {
	if req == nil || req.Msg == nil || req.Msg.RequestedCharge == nil {
		return nil, invalid("INVALID_ARGUMENT", "settlement charge is required")
	}
	if err := quotecommitment.RejectUnknown(req.Msg); err != nil {
		return nil, invalid("INVALID_ARGUMENT", err.Error())
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
	var canonicalEscrow *atostosv1.Escrow
	if req.Msg.ExpectedTerms != nil || req.Msg.ExpectedEscrowRef != nil || req.Msg.ExpectedReservationDigest != "" {
		if req.Msg.ExpectedTerms == nil || req.Msg.ExpectedEscrowRef == nil || req.Msg.ExpectedReservationDigest == "" {
			return nil, invalid("INVALID_ARGUMENT", "complete expected Verified reservation binding is required")
		}
		resolved, resolveErr := s.GetEscrow(ctx, connect.NewRequest(&atostosv1.GetEscrowRequest{
			Context: req.Msg.Context, EscrowId: req.Msg.EscrowId, QuoteId: req.Msg.QuoteId,
			ExpectedTerms: req.Msg.ExpectedTerms, ExpectedEscrowRef: req.Msg.ExpectedEscrowRef,
			ExpectedReservationDigest: req.Msg.ExpectedReservationDigest,
		}))
		if resolveErr != nil {
			return nil, resolveErr
		}
		if resolved.Msg == nil || !resolved.Msg.Found || resolved.Msg.Escrow == nil ||
			(resolved.Msg.Escrow.State != atostosv1.EscrowState_ESCROW_STATE_RESERVED &&
				resolved.Msg.Escrow.State != atostosv1.EscrowState_ESCROW_STATE_SETTLED) {
			return nil, failedPrecondition("ESCROW_MISMATCH", "canonical Verified TaskEscrow is not reservable or settled")
		}
		canonicalEscrow = resolved.Msg.Escrow
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
		if escrow.TrustMode == TrustModeVerified {
			if canonicalEscrow == nil || !sameVerifiedEscrowBinding(escrow, canonicalEscrow) {
				return failedPrecondition("ESCROW_MISMATCH", "local escrow projection does not match canonical reservation")
			}
			escrow = cloneMessage(canonicalEscrow)
		}
		if existingID := tx.Bucket(bucketSettlementByJob).Get([]byte(req.Msg.JobId)); existingID != nil {
			existing := new(atostosv1.Settlement)
			found, err := s.store.getProto(tx, bucketSettlements, string(existingID), existing)
			if err != nil {
				return err
			}
			if found {
				if existing.EscrowId != req.Msg.EscrowId || existing.QuoteId != req.Msg.QuoteId ||
					existing.JobId != req.Msg.JobId || existing.ReceiptId != req.Msg.ReceiptId ||
					!sameAtomic(existing.Charged, req.Msg.RequestedCharge) ||
					escrow.State != atostosv1.EscrowState_ESCROW_STATE_SETTLED {
					return conflict("IDEMPOTENCY_CONFLICT", "existing settlement semantics differ")
				}
				if escrow.TrustMode == TrustModeVerified && existing.SettlementRef != nil &&
					escrow.FinalizedCheckpoint > existing.SettlementRef.FinalizedCheckpoint {
					existing.SettlementRef.Finalized = true
					existing.SettlementRef.FinalizedCheckpoint = escrow.FinalizedCheckpoint
				}
				response.Settlement = existing
				response.Escrow = escrow
				return nil
			}
		}
		verifiedRecoverable := escrow.TrustMode == TrustModeVerified &&
			(escrow.State == atostosv1.EscrowState_ESCROW_STATE_RESERVED || escrow.State == atostosv1.EscrowState_ESCROW_STATE_SETTLED)
		if escrow.QuoteId != req.Msg.QuoteId ||
			(escrow.TrustMode == TrustModeVerified && escrow.JobId != req.Msg.JobId) ||
			(!verifiedRecoverable && escrow.State != atostosv1.EscrowState_ESCROW_STATE_RESERVED) {
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
			if result.TransitionReference == "" || result.AgentPaidNanoTOS != charge.Uint64() ||
				result.CreatorPaidNanoTOS < refund.Uint64() || result.State.Network != s.economy.Network() ||
				result.State.Status != chain.TaskEscrowStatusSettled || result.State.ObservedMasterSeqno == 0 ||
				strings.TrimSpace(result.State.CodeHash) == "" || result.State.ContractAddress != contractAddress ||
				result.State.BudgetNanoTOS != 0 || result.State.BalanceNanoTOS != 0 {
				return failedPrecondition("SETTLEMENT_FAILED", "Task Escrow payout is not finalized")
			}
			ref = NetworkReference{
				Network: s.economy.Network(), Reference: result.TransitionReference,
				Finalized: true, FinalizedCheckpoint: result.State.ObservedMasterSeqno,
			}
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
		escrow.TerminalRef = cloneMessage(&ref)
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

func sameVerifiedEscrowBinding(local, canonical *atostosv1.Escrow) bool {
	return local != nil && canonical != nil &&
		local.EscrowId == canonical.EscrowId && local.QuoteId == canonical.QuoteId && local.JobId == canonical.JobId &&
		local.PrincipalId == canonical.PrincipalId && local.ProviderId == canonical.ProviderId &&
		local.CapabilityId == canonical.CapabilityId && local.CapabilityVersion == canonical.CapabilityVersion &&
		local.TrustMode == canonical.TrustMode && local.ProofProfile == canonical.ProofProfile &&
		sameAtomic(local.Reserved, canonical.Reserved) && local.FundingModel == canonical.FundingModel &&
		local.QuoteCommitmentDigest == canonical.QuoteCommitmentDigest &&
		sameReference(local.QuoteCommitmentRef, canonical.QuoteCommitmentRef) &&
		local.ReservationDigest == canonical.ReservationDigest &&
		local.EscrowRef != nil && canonical.EscrowRef != nil &&
		local.EscrowRef.Network == canonical.EscrowRef.Network && local.EscrowRef.Reference == canonical.EscrowRef.Reference &&
		local.ContractCodeHash == canonical.ContractCodeHash && local.Finalized && canonical.Finalized &&
		local.FinalizedCheckpoint <= canonical.FinalizedCheckpoint
}

func sameAtomic(left, right *atostosv1.NetworkAmount) bool {
	return left != nil && right != nil && left.Asset == right.Asset && left.AtomicAmount == right.AtomicAmount
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
