package economic

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// Outcome is a job's single derived terminal outcome. A job has at most one; a
// pending release or refund is not one, because the escrow requesting a transfer
// is not the transfer finalizing.
type Outcome string

const (
	// OutcomeNone is a job with no finalized terminal outcome yet.
	OutcomeNone Outcome = ""
	// OutcomeReleased is a verified terminal payment to the provider wallet.
	OutcomeReleased Outcome = "released"
	// OutcomeRefunded is a verified terminal refund to the buyer. It contributes
	// job and refund activity but zero provider receipts and zero settled value.
	OutcomeRefunded Outcome = "refunded"
)

// Attribution records whether a released payment may be counted toward the
// Agent its Quote named. Naming is not participation: a Quote is created by the
// buyer and can name any public Agent, so a release counts toward Agent output
// only when the verification layer proved the provider's Registry standing and
// signer authorization across the job's life. This package consumes that
// verdict; it does not compute it.
type Attribution string

const (
	// AttributionNone is the attribution of a non-released job.
	AttributionNone Attribution = ""
	// AttributionAttributed passed every attribution proof.
	AttributionAttributed Attribution = "attributed"
	// AttributionUnattributed conclusively failed attribution.
	AttributionUnattributed Attribution = "unattributed"
	// AttributionUnresolved could not be decided on the evidence and fails
	// closed: it is neither attributed nor conclusively unattributed.
	AttributionUnresolved Attribution = "attribution_unresolved"
)

var (
	jobIDPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	agentIDPattern   = regexp.MustCompile(`^agent_[0-9a-f]{64}$`)
	capIDPattern     = regexp.MustCompile(`^cap_[0-9a-f]{64}$`)
	codeHashPattern  = regexp.MustCompile(`^tvm-cell-sha256:[0-9a-f]{64}$`)
	accountIDPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// AssetIdentity is the exact asset a job's value is denominated in. Aggregation
// is performed separately per identity: a ticker is display metadata and can
// never join two buckets, so two amounts of different assets are never summed.
type AssetIdentity struct {
	NetworkID       string
	MasterWorkchain int32
	MasterAccountID string
	MasterCodeHash  string
	WalletCodeHash  string
	Decimals        uint32
}

// Validate enforces the shape of an asset identity. V1 escrows are workchain
// zero, and the master account, code hashes, and network are what distinguish
// one stablecoin from another.
func (a AssetIdentity) Validate() error {
	if a.NetworkID == "" || len(a.NetworkID) > 128 {
		return errors.New("asset names no network")
	}
	if a.MasterWorkchain != 0 {
		return errors.New("V1 assets live on workchain zero")
	}
	if !accountIDPattern.MatchString(a.MasterAccountID) {
		return errors.New("asset master account is not a 32-byte hex address")
	}
	if !codeHashPattern.MatchString(a.MasterCodeHash) {
		return errors.New("asset master code hash is malformed")
	}
	if !codeHashPattern.MatchString(a.WalletCodeHash) {
		return errors.New("asset wallet code hash is malformed")
	}
	return nil
}

// key is the canonical bucket key for an asset identity. It joins the fields in
// a fixed order under a delimiter none of them can contain, so two identities
// share a key exactly when they are the same asset, and the order it imposes is
// stable for deterministic output.
func (a AssetIdentity) key() string {
	return strings.Join([]string{
		a.NetworkID,
		strconv.FormatInt(int64(a.MasterWorkchain), 10),
		a.MasterAccountID,
		a.MasterCodeHash,
		a.WalletCodeHash,
		strconv.FormatUint(uint64(a.Decimals), 10),
	}, "\x1f")
}

// VerifiedJob is one job the verification layer has authenticated end to end.
// The times are authenticated finalized block times; the outcome and
// attribution are that layer's verdicts. This package trusts these and computes,
// it does not re-derive them.
type VerifiedJob struct {
	JobID             string
	Asset             AssetIdentity
	BuyerWallet       string
	ProviderAgentID   string
	CapabilityID      string
	CapabilityVersion string

	Outcome     Outcome
	Attribution Attribution
	// Amount is the terminal transfer amount, canonical unsigned atomic. It is
	// present for a terminal job and empty otherwise.
	Amount string

	// AcceptanceTime is the finalized block time of escrow deployment.
	AcceptanceTime uint64
	// FundingTime is the finalized block time the escrow accepted funding.
	FundingTime uint64
	// TerminalTime is the finalized block time the terminal transfer completed,
	// zero for a job with no terminal outcome.
	TerminalTime uint64
}

// Validate enforces the internal consistency this package relies on: a terminal
// job carries a terminal time, an amount, and (for a release) an attribution
// verdict; the authenticated times are ordered acceptance <= funding <=
// terminal. An inconsistent record is refused rather than silently skewing a
// metric.
func (j VerifiedJob) Validate() error {
	if !jobIDPattern.MatchString(j.JobID) {
		return errors.New("job identifier is malformed")
	}
	if err := j.Asset.Validate(); err != nil {
		return err
	}
	if !accountIDPattern.MatchString(j.BuyerWallet) {
		return errors.New("buyer wallet is not a 32-byte hex address")
	}
	if !agentIDPattern.MatchString(j.ProviderAgentID) {
		return errors.New("provider agent identifier is malformed")
	}
	if !capIDPattern.MatchString(j.CapabilityID) {
		return errors.New("capability identifier is malformed")
	}
	if j.CapabilityVersion == "" || len(j.CapabilityVersion) > 64 {
		return errors.New("capability version is malformed")
	}
	if j.AcceptanceTime == 0 {
		return errors.New("job has no acceptance time")
	}
	switch j.Outcome {
	case OutcomeNone:
		if j.Attribution != AttributionNone {
			return errors.New("a non-terminal job cannot carry an attribution verdict")
		}
		if j.Amount != "" || j.TerminalTime != 0 {
			return errors.New("a non-terminal job cannot carry a terminal amount or time")
		}
	case OutcomeReleased:
		if j.Attribution != AttributionAttributed &&
			j.Attribution != AttributionUnattributed &&
			j.Attribution != AttributionUnresolved {
			return errors.New("a released job needs an attribution verdict")
		}
		if err := j.validateTerminal(); err != nil {
			return err
		}
	case OutcomeRefunded:
		if j.Attribution != AttributionNone {
			return errors.New("a refunded job carries no attribution verdict")
		}
		if err := j.validateTerminal(); err != nil {
			return err
		}
	default:
		return errors.New("unknown job outcome")
	}
	return nil
}

func (j VerifiedJob) validateTerminal() error {
	if _, err := parseAtomic(j.Amount); err != nil {
		return errors.New("terminal job has a malformed amount")
	}
	if j.FundingTime == 0 || j.TerminalTime == 0 {
		return errors.New("terminal job is missing a funding or terminal time")
	}
	// Authenticated block times must be ordered. A terminal time before funding,
	// or funding before acceptance, is not a job this layer can trust.
	if j.AcceptanceTime > j.FundingTime || j.FundingTime > j.TerminalTime {
		return errors.New("job times are not ordered acceptance <= funding <= terminal")
	}
	return nil
}

// isTerminal reports whether the job reached a terminal outcome.
func (j VerifiedJob) isTerminal() bool {
	return j.Outcome == OutcomeReleased || j.Outcome == OutcomeRefunded
}
