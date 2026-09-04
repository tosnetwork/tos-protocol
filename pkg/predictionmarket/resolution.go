package predictionmarket

import (
	"bytes"
	"errors"

	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

type PredictionNormalContextV1 struct {
	MarketID            Hash32
	RulesHash           Hash32
	NormalRoundNonce    Hash32
	NormalRoundOpenedAt uint64
	ResolveNotBefore    uint64
	OracleVoteDeadline  uint64
}

type PredictionChallengeReviewV1 struct {
	ProposedStatementHash Hash32
	ProposedOutcome       Outcome
	ProposedEvidenceRoot  Hash32
	ChallengerAddress     string
	CounterOutcome        Outcome
	CounterEvidenceRoot   Hash32
}

type PredictionReviewBaseContextV1 struct {
	MarketID            Hash32
	RulesHash           Hash32
	Reason              ReviewReason
	ReviewStartedAt     uint64
	ReviewVoteNotBefore uint64
	AppealDeadline      uint64
	Challenge           *PredictionChallengeReviewV1
}

type PredictionReviewVoteContextV1 struct {
	ReviewBaseContextHash Hash32
	ReviewRoundNonce      Hash32
	ReviewRoundOpenedAt   uint64
}

type PredictionResolutionStatementV1 struct {
	GlobalID           int32
	MarketAddress      string
	MarketID           Hash32
	RulesHash          Hash32
	RoundPolicyHash    Hash32
	RoundContextHash   Hash32
	Round              Round
	Outcome            Outcome
	EvidenceRoot       Hash32
	StatementCreatedAt uint64
	StatementExpiry    uint64
}

func BuildPredictionNormalContextCell(value PredictionNormalContextV1) (*cell.Cell, error) {
	if value.MarketID.IsZero() || value.RulesHash.IsZero() || value.NormalRoundNonce.IsZero() ||
		value.NormalRoundOpenedAt == 0 || value.ResolveNotBefore == 0 || value.OracleVoteDeadline == 0 ||
		value.NormalRoundOpenedAt > value.OracleVoteDeadline || value.ResolveNotBefore > value.OracleVoteDeadline {
		return nil, errors.New("invalid normal-round context")
	}
	binding := cell.BeginCell().MustStoreSlice(value.MarketID[:], 256).MustStoreSlice(value.RulesHash[:], 256).
		MustStoreSlice(value.NormalRoundNonce[:], 256).EndCell()
	return cell.BeginCell().MustStoreUInt(normalContextMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(normalContextDomain[:], 256).MustStoreUInt(value.NormalRoundOpenedAt, 64).
		MustStoreUInt(value.ResolveNotBefore, 64).MustStoreUInt(value.OracleVoteDeadline, 64).
		MustStoreRef(binding).EndCell(), nil
}

func DecodePredictionNormalContextV1(root *cell.Cell) (*PredictionNormalContextV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, 2, 1); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid normal-round context")
	}
	if err := loadMagicAndDomain(s, normalContextMagic, normalContextDomain, "normal-round context"); err != nil {
		return nil, err
	}
	opened, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid normal-round opening time")
	}
	resolve, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid resolution observation time")
	}
	deadline, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid normal-round deadline")
	}
	bindingCell, err := s.LoadRefCell()
	if err != nil || finish(s, "normal-round context") != nil {
		return nil, errors.New("invalid normal-round context shape")
	}
	binding, err := bindingCell.BeginParse()
	if err != nil {
		return nil, errors.New("invalid normal-round binding")
	}
	market, err := loadHash(binding, "normal-round market id")
	if err != nil {
		return nil, err
	}
	rules, err := loadHash(binding, "normal-round rules hash")
	if err != nil {
		return nil, err
	}
	nonce, err := loadHash(binding, "normal-round nonce")
	if err != nil || finish(binding, "normal-round binding") != nil {
		return nil, errors.New("invalid normal-round binding shape")
	}
	result := &PredictionNormalContextV1{MarketID: market, RulesHash: rules, NormalRoundNonce: nonce,
		NormalRoundOpenedAt: opened, ResolveNotBefore: resolve, OracleVoteDeadline: deadline}
	rebuilt, err := BuildPredictionNormalContextCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("normal-round context is not canonical")
	}
	return result, nil
}

func BuildPredictionReviewBaseContextCell(value PredictionReviewBaseContextV1) (*cell.Cell, error) {
	if value.MarketID.IsZero() || value.RulesHash.IsZero() || !value.Reason.valid() || value.ReviewStartedAt == 0 ||
		value.ReviewVoteNotBefore < value.ReviewStartedAt || value.AppealDeadline <= value.ReviewVoteNotBefore {
		return nil, errors.New("invalid review base context")
	}
	if value.Reason == ReviewNormalTimeout && value.Challenge != nil {
		return nil, errors.New("normal-timeout review cannot contain challenge provenance")
	}
	if value.Reason == ReviewChallenge && value.Challenge == nil {
		return nil, errors.New("challenge review requires complete provenance")
	}
	identity := cell.BeginCell().MustStoreSlice(value.MarketID[:], 256).MustStoreSlice(value.RulesHash[:], 256).EndCell()
	root := cell.BeginCell().MustStoreUInt(reviewBaseMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(reviewBaseDomain[:], 256).MustStoreUInt(uint64(value.Reason), 8).
		MustStoreUInt(value.ReviewStartedAt, 64).MustStoreUInt(value.ReviewVoteNotBefore, 64).
		MustStoreUInt(value.AppealDeadline, 64).MustStoreRef(identity)
	if value.Challenge != nil {
		challenge := value.Challenge
		challenger, err := parseCanonicalAddress(challenge.ChallengerAddress)
		if err != nil || challenge.ProposedStatementHash.IsZero() || challenge.ProposedEvidenceRoot.IsZero() ||
			challenge.CounterEvidenceRoot.IsZero() || !challenge.ProposedOutcome.valid() || !challenge.CounterOutcome.valid() ||
			challenge.CounterOutcome == challenge.ProposedOutcome {
			return nil, errors.New("invalid challenge review provenance")
		}
		proposal := cell.BeginCell().MustStoreSlice(challenge.ProposedStatementHash[:], 256).
			MustStoreUInt(uint64(challenge.ProposedOutcome), 8).MustStoreSlice(challenge.ProposedEvidenceRoot[:], 256).EndCell()
		counter := cell.BeginCell().MustStoreAddr(challenger).MustStoreUInt(uint64(challenge.CounterOutcome), 8).
			MustStoreSlice(challenge.CounterEvidenceRoot[:], 256).EndCell()
		root.MustStoreRef(proposal).MustStoreRef(counter)
	}
	return root.EndCell(), nil
}

func DecodePredictionReviewBaseContextV1(root *cell.Cell) (*PredictionReviewBaseContextV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, 4, 1); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid review base context")
	}
	if err := loadMagicAndDomain(s, reviewBaseMagic, reviewBaseDomain, "review base context"); err != nil {
		return nil, err
	}
	reason, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid review reason")
	}
	started, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid review start time")
	}
	notBefore, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid review delay")
	}
	deadline, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid appeal deadline")
	}
	identityCell, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing review market identity")
	}
	identity, err := identityCell.BeginParse()
	if err != nil {
		return nil, errors.New("invalid review market identity")
	}
	market, err := loadHash(identity, "review market id")
	if err != nil {
		return nil, err
	}
	rules, err := loadHash(identity, "review rules hash")
	if err != nil || finish(identity, "review market identity") != nil {
		return nil, errors.New("invalid review market identity shape")
	}
	result := &PredictionReviewBaseContextV1{MarketID: market, RulesHash: rules, Reason: ReviewReason(reason),
		ReviewStartedAt: started, ReviewVoteNotBefore: notBefore, AppealDeadline: deadline}
	if result.Reason == ReviewChallenge {
		proposalCell, err := s.LoadRefCell()
		if err != nil {
			return nil, errors.New("missing challenged proposal provenance")
		}
		counterCell, err := s.LoadRefCell()
		if err != nil {
			return nil, errors.New("missing counter-evidence provenance")
		}
		proposal, err := proposalCell.BeginParse()
		if err != nil {
			return nil, errors.New("invalid challenged proposal provenance")
		}
		statement, err := loadHash(proposal, "proposed statement hash")
		if err != nil {
			return nil, err
		}
		proposedOutcome, err := proposal.LoadUInt(8)
		if err != nil {
			return nil, errors.New("invalid proposed outcome")
		}
		proposedEvidence, err := loadHash(proposal, "proposed evidence root")
		if err != nil || finish(proposal, "challenged proposal") != nil {
			return nil, errors.New("invalid challenged proposal shape")
		}
		counter, err := counterCell.BeginParse()
		if err != nil {
			return nil, errors.New("invalid counter-evidence provenance")
		}
		challenger, err := loadCanonicalAddress(counter, "challenger")
		if err != nil {
			return nil, err
		}
		counterOutcome, err := counter.LoadUInt(8)
		if err != nil {
			return nil, errors.New("invalid counter outcome")
		}
		counterEvidence, err := loadHash(counter, "counter evidence root")
		if err != nil || finish(counter, "counter-evidence provenance") != nil {
			return nil, errors.New("invalid counter-evidence shape")
		}
		result.Challenge = &PredictionChallengeReviewV1{ProposedStatementHash: statement, ProposedOutcome: Outcome(proposedOutcome),
			ProposedEvidenceRoot: proposedEvidence, ChallengerAddress: challenger, CounterOutcome: Outcome(counterOutcome),
			CounterEvidenceRoot: counterEvidence}
	}
	if err := finish(s, "review base context"); err != nil {
		return nil, err
	}
	rebuilt, err := BuildPredictionReviewBaseContextCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("review base context is not canonical")
	}
	return result, nil
}

func BuildPredictionReviewVoteContextCell(value PredictionReviewVoteContextV1) (*cell.Cell, error) {
	if value.ReviewBaseContextHash.IsZero() || value.ReviewRoundNonce.IsZero() || value.ReviewRoundOpenedAt == 0 {
		return nil, errors.New("invalid review vote context")
	}
	return cell.BeginCell().MustStoreUInt(reviewVoteMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(reviewVoteDomain[:], 256).MustStoreSlice(value.ReviewBaseContextHash[:], 256).
		MustStoreSlice(value.ReviewRoundNonce[:], 256).MustStoreUInt(value.ReviewRoundOpenedAt, 64).EndCell(), nil
}

func DecodePredictionReviewVoteContextV1(root *cell.Cell) (*PredictionReviewVoteContextV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, 1, 0); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid review vote context")
	}
	if err := loadMagicAndDomain(s, reviewVoteMagic, reviewVoteDomain, "review vote context"); err != nil {
		return nil, err
	}
	base, err := loadHash(s, "review base context hash")
	if err != nil {
		return nil, err
	}
	nonce, err := loadHash(s, "review round nonce")
	if err != nil {
		return nil, err
	}
	opened, err := s.LoadUInt(64)
	if err != nil || finish(s, "review vote context") != nil {
		return nil, errors.New("invalid review vote context shape")
	}
	result := &PredictionReviewVoteContextV1{ReviewBaseContextHash: base, ReviewRoundNonce: nonce, ReviewRoundOpenedAt: opened}
	rebuilt, err := BuildPredictionReviewVoteContextCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("review vote context is not canonical")
	}
	return result, nil
}

func BuildPredictionResolutionStatementCell(value PredictionResolutionStatementV1) (*cell.Cell, error) {
	market, err := parseCanonicalAddress(value.MarketAddress)
	if err != nil || value.MarketID.IsZero() || value.RulesHash.IsZero() || value.RoundPolicyHash.IsZero() ||
		value.RoundContextHash.IsZero() || value.EvidenceRoot.IsZero() || !value.Round.valid() || !value.Outcome.valid() ||
		value.StatementCreatedAt == 0 || value.StatementCreatedAt >= value.StatementExpiry {
		return nil, errors.New("invalid prediction resolution statement")
	}
	identity := cell.BeginCell().MustStoreAddr(market).MustStoreSlice(value.MarketID[:], 256).EndCell()
	policy := cell.BeginCell().MustStoreSlice(value.RulesHash[:], 256).MustStoreSlice(value.RoundPolicyHash[:], 256).EndCell()
	return cell.BeginCell().MustStoreUInt(resolutionMagic, 32).MustStoreUInt(uint64(SchemaVersion), 16).
		MustStoreSlice(resultDomainHash[:], 256).MustStoreInt(int64(value.GlobalID), 32).
		MustStoreUInt(uint64(value.Round), 8).MustStoreUInt(uint64(value.Outcome), 8).
		MustStoreUInt(value.StatementCreatedAt, 64).MustStoreUInt(value.StatementExpiry, 64).
		MustStoreSlice(value.RoundContextHash[:], 256).MustStoreSlice(value.EvidenceRoot[:], 256).
		MustStoreRef(identity).MustStoreRef(policy).EndCell(), nil
}

func DecodePredictionResolutionStatementV1(root *cell.Cell) (*PredictionResolutionStatementV1, error) {
	if err := ensureBoundedOrdinaryDAG(root, 3, 1); err != nil {
		return nil, err
	}
	s, err := root.BeginParse()
	if err != nil {
		return nil, errors.New("invalid prediction resolution statement")
	}
	if err := loadMagicAndDomain(s, resolutionMagic, resultDomainHash, "resolution statement"); err != nil {
		return nil, err
	}
	globalID, err := s.LoadInt(32)
	if err != nil {
		return nil, errors.New("invalid resolution global id")
	}
	round, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid resolution round")
	}
	outcome, err := s.LoadUInt(8)
	if err != nil {
		return nil, errors.New("invalid resolution outcome")
	}
	created, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid resolution creation time")
	}
	expiry, err := s.LoadUInt(64)
	if err != nil {
		return nil, errors.New("invalid resolution expiry")
	}
	context, err := loadHash(s, "resolution round context")
	if err != nil {
		return nil, err
	}
	evidence, err := loadHash(s, "resolution evidence root")
	if err != nil {
		return nil, err
	}
	identityCell, err := s.LoadRefCell()
	if err != nil {
		return nil, errors.New("missing resolution market identity")
	}
	policyCell, err := s.LoadRefCell()
	if err != nil || finish(s, "resolution statement") != nil {
		return nil, errors.New("invalid resolution statement shape")
	}
	identity, err := identityCell.BeginParse()
	if err != nil {
		return nil, errors.New("invalid resolution market identity")
	}
	market, err := loadCanonicalAddress(identity, "resolution market")
	if err != nil {
		return nil, err
	}
	marketID, err := loadHash(identity, "resolution market id")
	if err != nil || finish(identity, "resolution market identity") != nil {
		return nil, errors.New("invalid resolution market identity shape")
	}
	policy, err := policyCell.BeginParse()
	if err != nil {
		return nil, errors.New("invalid resolution policy binding")
	}
	rules, err := loadHash(policy, "resolution rules hash")
	if err != nil {
		return nil, err
	}
	policyHash, err := loadHash(policy, "resolution round policy hash")
	if err != nil || finish(policy, "resolution policy binding") != nil {
		return nil, errors.New("invalid resolution policy binding shape")
	}
	result := &PredictionResolutionStatementV1{GlobalID: int32(globalID), MarketAddress: market, MarketID: marketID,
		RulesHash: rules, RoundPolicyHash: policyHash, RoundContextHash: context, Round: Round(round), Outcome: Outcome(outcome),
		EvidenceRoot: evidence, StatementCreatedAt: created, StatementExpiry: expiry}
	rebuilt, err := BuildPredictionResolutionStatementCell(*result)
	if err != nil || !bytes.Equal(rebuilt.Hash(), root.Hash()) {
		return nil, errors.New("resolution statement is not canonical")
	}
	return result, nil
}

func loadMagicAndDomain(s *cell.Slice, expectedMagic uint64, expectedDomain Hash32, what string) error {
	magic, err := s.LoadUInt(32)
	if err != nil || magic != expectedMagic {
		return errors.New("invalid " + what + " magic")
	}
	version, err := s.LoadUInt(16)
	if err != nil || version != uint64(SchemaVersion) {
		return errors.New("unsupported " + what + " schema")
	}
	domain, err := s.LoadSlice(256)
	if err != nil || !equalHash(domain, expectedDomain) {
		return errors.New("invalid " + what + " domain")
	}
	return nil
}
