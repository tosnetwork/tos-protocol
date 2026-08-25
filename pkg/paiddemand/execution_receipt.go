package paiddemand

import (
	"errors"

	"github.com/tosnetwork/tos-service-protocol/pkg/nativecore"
	"github.com/tosnetwork/tosutils-go/tvm/cell"
)

// ExecutionReceiptV1 is the business-neutral view of the escrow Receipt cell.
// The contract shape predates the generic Intent layer, so some evidence slots
// retain historical names in nativecore; this type defines their portable
// meaning for arbitrary Agreement work.
type ExecutionReceiptV1 struct {
	QuoteCommitment     string
	ExecutionID         string
	InputSetDigest      string
	ResultDigest        string
	ArtifactSetDigest   string
	EvaluationDigest    string
	SourceSetDigest     string
	ExecutorDigest      string
	IsolationDigest     string
	ChargedAtomicAmount string
	ProviderAgentID     string
	CompletedAtUnix     uint64
}

func BuildExecutionReceiptV1(value ExecutionReceiptV1) (*cell.Cell, string, error) {
	if value.InputSetDigest == value.SourceSetDigest || value.CompletedAtUnix == 0 {
		return nil, "", errors.New("generic execution Receipt bindings are invalid")
	}
	return nativecore.BuildSoftwareWorkReceiptCellV1(nativecore.SoftwareWorkReceiptV1{
		QuoteCommitment: value.QuoteCommitment, ExecutionID: value.ExecutionID, InputDigest: value.InputSetDigest,
		ResultDigest: value.ResultDigest, ArtifactDigest: value.ArtifactSetDigest, ReportDigest: value.EvaluationDigest,
		SourceDigest: value.SourceSetDigest, ToolchainDigest: value.ExecutorDigest, SandboxDigest: value.IsolationDigest,
		ChargedAtomicAmount: value.ChargedAtomicAmount, ProviderAgentID: value.ProviderAgentID,
		CompletedAt: value.CompletedAtUnix, ExitCode: 0,
	})
}
