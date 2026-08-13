package nativecore

import (
	"context"
	"encoding/base64"
	"errors"

	nativev1 "github.com/tosnetwork/tos-protocol/gen/atos/native/v1"
)

// ContractCellSender is a fee-paying transport boundary. Implementations must
// not interpret or rewrite signed Native semantics.
type ContractCellSender interface {
	SendContractCell(context.Context, string, uint64, string, string) error
}

const (
	MinimumRelayFundingNanoTOS uint64 = 200_000_000
	MaximumRelayFundingNanoTOS uint64 = 100_000_000_000
)

type Relayer struct {
	Locator        *Locator
	Sender         ContractCellSender
	FundingNanoTOS uint64
}

func (r *Relayer) CheckReady(ctx context.Context) error {
	if r == nil || r.Locator == nil || r.Sender == nil || r.FundingNanoTOS < MinimumRelayFundingNanoTOS || r.FundingNanoTOS > MaximumRelayFundingNanoTOS {
		return errors.New("simplified Native relayer is not configured")
	}
	if ready, ok := r.Sender.(interface{ CheckContractCellReady(context.Context) error }); ok {
		return ready.CheckContractCellReady(ctx)
	}
	return nil
}

func (r *Relayer) Submit(ctx context.Context, submission *nativev1.SignedNativeActionV1, queryID uint64) (string, error) {
	if r == nil || r.Locator == nil || r.Sender == nil || r.FundingNanoTOS < MinimumRelayFundingNanoTOS || r.FundingNanoTOS > MaximumRelayFundingNanoTOS || ctx == nil || submission == nil || submission.Action == nil {
		return "", errors.New("simplified Native relayer is not configured")
	}
	built, err := BuildAction(submission.Action)
	if err != nil {
		return "", err
	}
	bodyBuilder := MessageBody
	destinationID := submission.Action.TargetObjectId
	stateInit := ""
	switch payload := submission.Action.Payload.(type) {
	case *nativev1.NativeActionV1_RegisterAgent:
		// Agent registration deploys the target directly.
	case *nativev1.NativeActionV1_RegisterCapability:
		destinationID = payload.RegisterCapability.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_AddCapabilityVersion:
		destinationID = payload.AddCapabilityVersion.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_TransferCapability:
		destinationID = payload.TransferCapability.CurrentOwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	case *nativev1.NativeActionV1_RevokeCapability:
		destinationID = payload.RevokeCapability.OwnerAgentId
		bodyBuilder = AgentAuthorizationBody
	}
	body, err := bodyBuilder(built, submission.AuthoritySignatures, submission.CounterpartySignatures, queryID)
	if err != nil {
		return "", err
	}
	identity, err := r.Locator.Locate(destinationID)
	if err != nil {
		return "", err
	}
	if built.Kind == KindRegisterAgent {
		stateInit = identity.StateInitBOC
	}
	if err := r.Sender.SendContractCell(ctx, identity.Address, r.FundingNanoTOS,
		base64.StdEncoding.EncodeToString(body.ToBOC()), stateInit); err != nil {
		return "", err
	}
	return built.HashString, nil
}
