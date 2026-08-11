package chain

import (
	"context"
	"time"
)

const TaskEscrowActionVersion = "1"

type TaskEscrowActionKind string

const (
	TaskEscrowActionDeploy  TaskEscrowActionKind = "deploy"
	TaskEscrowActionAccept  TaskEscrowActionKind = "accept"
	TaskEscrowActionResult  TaskEscrowActionKind = "result"
	TaskEscrowActionSettle  TaskEscrowActionKind = "settle"
	TaskEscrowActionCancel  TaskEscrowActionKind = "cancel"
	TaskEscrowActionTimeout TaskEscrowActionKind = "timeout"
	TaskEscrowActionReject  TaskEscrowActionKind = "reject"
	TaskEscrowActionDispute TaskEscrowActionKind = "dispute"
	TaskEscrowActionResolve TaskEscrowActionKind = "resolve"
)

type TaskEscrowStatus uint8

const (
	TaskEscrowStatusOpen TaskEscrowStatus = iota
	TaskEscrowStatusAccepted
	TaskEscrowStatusResultSubmitted
	TaskEscrowStatusSettled
	TaskEscrowStatusCancelled
	TaskEscrowStatusExpired
	TaskEscrowStatusRejected
	TaskEscrowStatusDisputed
)

// TaskEscrowAction is an immutable, idempotent intent sent to a private
// key-custody/contract sidecar. The sidecar may sign and publish the action,
// but it cannot assert contract state or finality. Those are independently
// observed by tos-protocol through strict-majority TOS readers.
type TaskEscrowAction struct {
	Version           string               `json:"version"`
	ActionID          string               `json:"actionId"`
	Network           string               `json:"network"`
	Kind              TaskEscrowActionKind `json:"kind"`
	EscrowID          string               `json:"escrowId"`
	ContractAddress   string               `json:"contractAddress,omitempty"`
	Creator           string               `json:"creator"`
	Agent             string               `json:"agent"`
	Verifier          string               `json:"verifier,omitempty"`
	BudgetNanoTOS     uint64               `json:"budgetNanoTOS"`
	FundingNanoTOS    uint64               `json:"fundingNanoTOS,omitempty"`
	DeadlineUnix      uint64               `json:"deadlineUnix"`
	ReviewPeriod      uint32               `json:"reviewPeriod"`
	PolicyHash        string               `json:"policyHash"`
	PermissionHash    string               `json:"permissionHash"`
	QueryID           uint64               `json:"queryId,omitempty"`
	ResultHash        string               `json:"resultHash,omitempty"`
	EvidenceHash      string               `json:"evidenceHash,omitempty"`
	DisputeHash       string               `json:"disputeHash,omitempty"`
	PayoutNanoTOS     uint64               `json:"payoutNanoTOS,omitempty"`
	ExpectedBodyHash  string               `json:"expectedBodyHash,omitempty"`
	ExpiresUnixMillis int64                `json:"expiresUnixMillis"`
}

type TaskEscrowActionReceipt struct {
	Version         string               `json:"version"`
	ActionID        string               `json:"actionId"`
	Network         string               `json:"network"`
	Kind            TaskEscrowActionKind `json:"kind"`
	EscrowID        string               `json:"escrowId"`
	ContractAddress string               `json:"contractAddress"`
	Reference       string               `json:"reference"`
}

type TaskEscrowState struct {
	Network             string           `json:"network"`
	ContractAddress     string           `json:"contractAddress"`
	Creator             string           `json:"creator"`
	Agent               string           `json:"agent,omitempty"`
	HasAgent            bool             `json:"hasAgent"`
	Verifier            string           `json:"verifier,omitempty"`
	HasVerifier         bool             `json:"hasVerifier"`
	BudgetNanoTOS       uint64           `json:"budgetNanoTOS"`
	BalanceNanoTOS      uint64           `json:"balanceNanoTOS"`
	DeadlineUnix        uint64           `json:"deadlineUnix"`
	Status              TaskEscrowStatus `json:"status"`
	ResultHash          string           `json:"resultHash"`
	EvidenceHash        string           `json:"evidenceHash"`
	PolicyHash          string           `json:"policyHash"`
	PermissionHash      string           `json:"permissionHash"`
	ReviewPeriod        uint32           `json:"reviewPeriod"`
	ReviewDeadlineUnix  uint64           `json:"reviewDeadlineUnix"`
	DisputeHash         string           `json:"disputeHash"`
	AttestorPublicKey   string           `json:"attestorPublicKey,omitempty"`
	CodeHash            string           `json:"codeHash"`
	ObservedMasterSeqno uint64           `json:"observedMasterSeqno"`
	ObservedAt          time.Time        `json:"observedAt"`
}

type TaskEscrowReference struct {
	Network            string
	ContractAddress    string
	AllowedCodeHashes  []string
	MinimumMasterSeqno uint64
}

type TaskEscrowTransitionReference struct {
	TaskEscrowReference
	TransactionReference   string
	ExpectedSender         string
	ExpectedKind           TaskEscrowActionKind
	ExpectedQueryID        uint64
	ExpectedBodyHash       string
	ExpectedInboundMinimum uint64
	ExpectedAgent          string
	ExpectedAgentPayout    uint64
	ExpectedCreator        string
	ExpectedCreatorMinimum uint64
}

type TaskEscrowTransition struct {
	State                TaskEscrowState
	TransactionReference string
	Sender               string
	BodyHash             string
	QueryID              uint64
	AgentPaidNanoTOS     uint64
	CreatorPaidNanoTOS   uint64
	ObservedMasterSeqno  uint64
	ObservedAt           time.Time
}

type TaskEscrowActionPublisher interface {
	CheckReady(context.Context) error
	// Resolve is read-only. found=false is permitted only when the enrolled
	// durable journal returns a typed Action-ID-bound authoritative absence.
	Resolve(context.Context, TaskEscrowAction) (TaskEscrowActionReceipt, bool, error)
	Publish(context.Context, TaskEscrowAction) (TaskEscrowActionReceipt, error)
	Close() error
}

type TaskEscrowObserver interface {
	CheckChainReady(context.Context, time.Time) (uint64, time.Time, error)
	ReadTaskEscrow(context.Context, TaskEscrowReference) (TaskEscrowState, error)
	ObserveTaskEscrowTransition(context.Context, TaskEscrowTransitionReference) (TaskEscrowTransition, error)
}
