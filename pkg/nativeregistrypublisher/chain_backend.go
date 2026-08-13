package nativeregistrypublisher

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/codec"
	"github.com/tosnetwork/tos-protocol/pkg/nativeexecution"
	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
)

type ContractSender interface {
	PrepareContractCell(context.Context, string, uint64, string, string) (string, string, error)
	BroadcastPreparedContractCell(context.Context, string, string) error
	CheckContractCellReady(context.Context) error
	EnrollmentBinding() string
	PayerIdentity() string
}

type AnchorObservation struct {
	Found                bool
	Completed            bool
	TransactionReference string
}

// AnchorResolver is strict-majority and read-only. Found=false is canonical
// absence, not a cache miss or bounded-history miss.
type AnchorResolver interface {
	CheckReady(context.Context) error
	ObserveActionAnchor(context.Context, nativeregistry.Submission, nativeexecution.ContractIdentity) (AnchorObservation, error)
	EnrollmentBinding() string
}

type AuthorityResolver interface {
	AnchorResolver
	nativeregistry.Resolver
}

type ChainBackend struct {
	locator  *nativeexecution.ObjectLocator
	resolver AuthorityResolver
	sender   ContractSender
	funding  uint64
	poll     time.Duration
	timeout  time.Duration
	binding  string
}

// The Action Anchor forwards 0.1 TOS to the Agent contract. Enrollment must
// reserve a deterministic additional margin for Anchor compute/action fees;
// accepting exactly the forward value creates a valid VM execution whose
// action phase aborts for lack of funds.
const MinimumFundingNanoTOS uint64 = 200_000_000

func NewChainBackend(locator *nativeexecution.ObjectLocator, resolver AuthorityResolver, sender ContractSender, funding uint64, poll, timeout time.Duration) (*ChainBackend, error) {
	if locator == nil || resolver == nil || sender == nil || funding < MinimumFundingNanoTOS || resolver.EnrollmentBinding() == "" || sender.EnrollmentBinding() == "" {
		return nil, errors.New("invalid Native registry chain backend")
	}
	if poll == 0 {
		poll = time.Second
	}
	if timeout == 0 {
		timeout = 90 * time.Second
	}
	if poll < 100*time.Millisecond || poll > 5*time.Second || timeout < time.Second || timeout > 5*time.Minute {
		return nil, errors.New("invalid Native registry chain backend bounds")
	}
	binding, err := codec.Digest("tos.native-registry-chain-backend-binding.v1", struct {
		Network         string `cbor:"1,keyasint"`
		GenesisRootHash string `cbor:"2,keyasint"`
		GenesisFileHash string `cbor:"3,keyasint"`
		Workchain       int32  `cbor:"4,keyasint"`
		CodeHash        string `cbor:"5,keyasint"`
		ResolverBinding string `cbor:"6,keyasint"`
		SenderBinding   string `cbor:"7,keyasint"`
		FundingNanoTOS  uint64 `cbor:"8,keyasint"`
		PollNanos       int64  `cbor:"9,keyasint"`
		TimeoutNanos    int64  `cbor:"10,keyasint"`
	}{locator.Network.NetworkID, locator.Network.GenesisRootHash, locator.Network.GenesisFileHash,
		locator.Workchain, locator.CodeHash, resolver.EnrollmentBinding(), sender.EnrollmentBinding(), funding, int64(poll), int64(timeout)})
	if err != nil {
		return nil, err
	}
	return &ChainBackend{locator: locator, resolver: resolver, sender: sender, funding: funding, poll: poll, timeout: timeout, binding: binding}, nil
}
func (b *ChainBackend) EnrollmentBinding() string { return b.binding }
func (b *ChainBackend) PayerIdentity() string     { return b.sender.PayerIdentity() }
func (b *ChainBackend) Close() error {
	if b == nil || b.sender == nil {
		return nil
	}
	if closer, ok := b.sender.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}
func (b *ChainBackend) CheckReady(ctx context.Context, policy Policy) error {
	if policy.NetworkID != b.locator.Network.NetworkID ||
		policy.GenesisRootHash != b.locator.Network.GenesisRootHash ||
		policy.GenesisFileHash != b.locator.Network.GenesisFileHash ||
		policy.RegistryWorkchain != b.locator.Workchain ||
		policy.ContractCodeHash != b.locator.CodeHash ||
		policy.LocatorVersion != nativeexecution.LocatorVersion ||
		policy.ActionVersion != nativeexecution.Version ||
		policy.PayerIdentity != b.sender.PayerIdentity() {
		return errors.New("Native registry publisher policy does not match the concrete backend")
	}
	if err := b.resolver.CheckReady(ctx); err != nil {
		return err
	}
	return b.sender.CheckContractCellReady(ctx)
}
func (b *ChainBackend) Resolve(ctx context.Context, s nativeregistry.Submission) (Receipt, error) {
	id, _, err := nativeregistry.ValidateSubmission(s)
	if err != nil {
		return Receipt{}, err
	}
	anchor, err := b.locator.LocateActionAnchor(id)
	if err != nil {
		return Receipt{}, err
	}
	observed, err := b.resolver.ObserveActionAnchor(ctx, s, anchor)
	if err != nil {
		return Receipt{}, err
	}
	if !observed.Found {
		return Receipt{}, nativeregistry.ErrPublisherNotFound
	}
	if !observed.Completed || observed.TransactionReference == "" {
		return Receipt{}, nativeregistry.ErrPublisherPending
	}
	return Receipt{TransactionReference: observed.TransactionReference}, nil
}
func (b *ChainBackend) Prepare(ctx context.Context, s nativeregistry.Submission) (PreparedMutation, error) {
	id, _, err := nativeregistry.ValidateForPublisher(ctx, b.resolver, b.locator, s)
	if err != nil {
		return PreparedMutation{}, err
	}
	anchor, stateInit, err := b.locator.ActionAnchorStateInit(id)
	if err != nil {
		return PreparedMutation{}, err
	}
	body, err := nativeexecution.MessageBody(s.Execution)
	if err != nil {
		return PreparedMutation{}, err
	}
	message, digest, err := b.sender.PrepareContractCell(ctx, anchor.Address, b.funding, base64.StdEncoding.EncodeToString(body.ToBOC()), stateInit)
	if err != nil {
		return PreparedMutation{}, err
	}
	return PreparedMutation{Version: PreparedMutationVersion, MessageBOCBase64: message, MessageDigest: digest}, nil
}

func (b *ChainBackend) Publish(ctx context.Context, s nativeregistry.Submission, prepared PreparedMutation, recovering bool) (Receipt, error) {
	_ = recovering // recovery changes provenance, never the prepared bytes
	receipt, resolveErr := b.Resolve(ctx, s)
	if resolveErr == nil {
		return receipt, nil
	}
	if !errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) && !errors.Is(resolveErr, nativeregistry.ErrPublisherPending) {
		return Receipt{}, resolveErr
	}
	if prepared.Version != PreparedMutationVersion || prepared.MessageBOCBase64 == "" || prepared.MessageDigest == "" {
		return Receipt{}, errors.New("invalid durable Native registry mutation")
	}
	if errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) {
		if _, _, err := nativeregistry.ValidateForPublisher(ctx, b.resolver, b.locator, s); err != nil {
			return Receipt{}, err
		}
		if err := b.sender.BroadcastPreparedContractCell(ctx, prepared.MessageBOCBase64, prepared.MessageDigest); err != nil {
			return Receipt{}, err
		}
	}
	deadline := time.NewTimer(b.timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(b.poll)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return Receipt{}, ctx.Err()
		case <-deadline.C:
			return Receipt{}, nativeregistry.ErrAmbiguous
		case <-ticker.C:
			receipt, resolveErr := b.Resolve(ctx, s)
			if resolveErr == nil {
				return receipt, nil
			}
			if !errors.Is(resolveErr, nativeregistry.ErrPublisherPending) && !errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) {
				return Receipt{}, resolveErr
			}
		}
	}
}
