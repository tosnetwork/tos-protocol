package atosrpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tosnetwork/tos-protocol/pkg/authorization"
	"github.com/tosnetwork/tos-protocol/pkg/chain"
	"github.com/tosnetwork/tos-protocol/pkg/toschain"
)

const (
	DefaultChainAuthorityCallTimeout = 30 * time.Second
	DefaultChainAnchorLifetime       = 5 * time.Minute
	maxChainAuthorityCallTimeout     = 2 * time.Minute
	maxChainAnchorLifetime           = 30 * time.Minute
)

var (
	chainCommitmentKindPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
	chainDigestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type chainAuthorityRuntime interface {
	CheckServiceReady(
		context.Context,
		authorization.Reference,
		time.Time,
	) (toschain.ReadinessSnapshot, error)
	ObservePayment(context.Context, chain.PaymentReference) (chain.PaymentState, error)
}

// ChainAuthorityConfig creates an Authority whose commitment references are
// exact, finalized TOS transactions. Transaction submission remains behind a
// private ActionPublisher so tos-protocol never loads treasury or contract
// private keys. The quorum runtime independently verifies every returned
// transaction and its purpose-specific comment.
//
// This v1 implementation deliberately supports Managed mode only. A finalized
// commitment anchor is not equivalent to economically enforceable TOS escrow.
// Verified mode remains fail-closed until a contract-backed economic driver
// implements reserve, release, settlement, and refund verification.
type ChainAuthorityConfig struct {
	Runtime          *toschain.Runtime
	ServiceReference authorization.Reference
	Publisher        chain.ActionPublisher
	AnchorPayer      string
	AnchorPayee      string
	AnchorAmountNano uint64
	CallTimeout      time.Duration
	AnchorLifetime   time.Duration
	Now              func() time.Time
}

type chainAuthority struct {
	runtime          chainAuthorityRuntime
	serviceReference authorization.Reference
	publisher        chain.ActionPublisher
	network          string
	anchorPayer      string
	anchorPayee      string
	anchorAmountNano uint64
	callTimeout      time.Duration
	anchorLifetime   time.Duration
	now              func() time.Time
	closeOnce        sync.Once
	closeErr         error
}

func NewChainAuthority(config ChainAuthorityConfig) (Authority, error) {
	if config.Runtime == nil {
		return nil, errors.New("TOS chain authority runtime is required")
	}
	return newChainAuthority(
		config.Runtime,
		config.ServiceReference,
		config.Publisher,
		config.AnchorPayer,
		config.AnchorPayee,
		config.AnchorAmountNano,
		config.CallTimeout,
		config.AnchorLifetime,
		config.Now,
	)
}

func newChainAuthority(
	runtime chainAuthorityRuntime,
	serviceReference authorization.Reference,
	publisher chain.ActionPublisher,
	anchorPayer, anchorPayee string,
	anchorAmountNano uint64,
	callTimeout, anchorLifetime time.Duration,
	now func() time.Time,
) (Authority, error) {
	if runtime == nil || publisher == nil {
		return nil, errors.New("TOS chain authority runtime and publisher are required")
	}
	if strings.TrimSpace(serviceReference.Network) == "" ||
		strings.TrimSpace(serviceReference.Address) == "" ||
		strings.TrimSpace(serviceReference.ServiceID) == "" {
		return nil, errors.New("TOS chain authority service reference is required")
	}
	canonicalPayer, err := toschain.CanonicalAddress(anchorPayer)
	if err != nil {
		return nil, fmt.Errorf("invalid TOS chain authority anchor payer: %w", err)
	}
	canonicalPayee, err := toschain.CanonicalAddress(anchorPayee)
	if err != nil {
		return nil, fmt.Errorf("invalid TOS chain authority anchor payee: %w", err)
	}
	if anchorAmountNano == 0 {
		return nil, errors.New("TOS chain authority anchor amount is required")
	}
	if callTimeout == 0 {
		callTimeout = DefaultChainAuthorityCallTimeout
	}
	if callTimeout <= 0 || callTimeout > maxChainAuthorityCallTimeout {
		return nil, errors.New("invalid TOS chain authority call timeout")
	}
	if anchorLifetime == 0 {
		anchorLifetime = DefaultChainAnchorLifetime
	}
	if anchorLifetime <= 0 || anchorLifetime > maxChainAnchorLifetime {
		return nil, errors.New("invalid TOS chain authority anchor lifetime")
	}
	if now == nil {
		now = time.Now
	}
	return &chainAuthority{
		runtime: runtime, serviceReference: serviceReference,
		publisher: publisher, network: serviceReference.Network,
		anchorPayer: canonicalPayer, anchorPayee: canonicalPayee,
		anchorAmountNano: anchorAmountNano, callTimeout: callTimeout,
		anchorLifetime: anchorLifetime, now: now,
	}, nil
}

func (a *chainAuthority) Network() string {
	if a == nil {
		return ""
	}
	return a.network
}

func (a *chainAuthority) Supports(mode TrustMode) bool {
	// The chain Authority supplies the finalized commitment half of Verified.
	// Server.supportsMode additionally requires a contract-backed economic
	// driver before Verified can become active. Native still requires global
	// resolution and federation guarantees that this Authority does not claim.
	return a != nil && (mode == TrustModeManaged || mode == TrustModeVerified)
}

func (a *chainAuthority) CheckReady(ctx context.Context) error {
	if a == nil || a.runtime == nil || a.publisher == nil || a.now == nil {
		return errors.New("invalid TOS chain authority")
	}
	callContext, cancel, err := a.callContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if _, err := a.runtime.CheckServiceReady(
		callContext, a.serviceReference, a.now().UTC(),
	); err != nil {
		return fmt.Errorf("TOS chain authority service is not ready: %w", err)
	}
	if err := a.publisher.CheckReady(callContext); err != nil {
		return fmt.Errorf("TOS chain action publisher is not ready: %w", err)
	}
	return nil
}

func (a *chainAuthority) Commit(
	ctx context.Context,
	kind, objectID, digest string,
) (NetworkReference, error) {
	if a == nil || a.runtime == nil || a.publisher == nil || a.now == nil {
		return NetworkReference{}, errors.New("invalid TOS chain authority")
	}
	kind = strings.TrimSpace(kind)
	objectID = strings.TrimSpace(objectID)
	if !chainCommitmentKindPattern.MatchString(kind) || objectID == "" ||
		len(objectID) > 512 || strings.ContainsRune(objectID, '\x00') ||
		!chainDigestPattern.MatchString(digest) {
		return NetworkReference{}, errors.New("invalid TOS chain commitment")
	}
	callContext, cancel, err := a.callContext(ctx)
	if err != nil {
		return NetworkReference{}, err
	}
	defer cancel()
	if managedEconomicCommitment(kind) {
		// Managed escrow and settlement remain local economic state. Returning
		// a TOS transaction anchor in escrow_ref or settlement_ref would imply
		// custody/finality guarantees that this Authority deliberately does not
		// provide. These transitions must also remain available for local refund
		// and settlement if chain observers become unavailable after startup.
		// Verified remains fail-closed until a contract-backed driver owns them.
		return NewLocalAuthority("tos-local").Commit(callContext, kind, objectID, digest)
	}
	now := a.now().UTC()
	if now.IsZero() {
		return NetworkReference{}, errors.New("invalid TOS chain authority clock")
	}
	before, err := a.runtime.CheckServiceReady(
		callContext, a.serviceReference, now,
	)
	if err != nil {
		return NetworkReference{}, fmt.Errorf("resolve TOS chain authority readiness: %w", err)
	}
	action := a.anchorAction(kind, objectID, digest, now)
	receipt, err := a.publisher.Publish(callContext, action)
	if err != nil {
		return NetworkReference{}, fmt.Errorf("publish TOS chain commitment: %w", err)
	}
	if err := verifyActionReceipt(action, receipt); err != nil {
		return NetworkReference{}, err
	}
	state, err := a.runtime.ObservePayment(callContext, chain.PaymentReference{
		Network: a.network, AuthorizationID: action.ActionID,
		QuoteID: action.ActionID, RequestID: action.ActionID,
		Reference: receipt.Reference, Payer: action.Payer, Payee: action.Payee,
		AmountNanoTOS: action.AmountNanoTOS, Comment: action.Comment,
		MinimumMasterSeqno: before.ObservedMasterSeqno,
	})
	if err != nil {
		return NetworkReference{}, fmt.Errorf("observe TOS chain commitment: %w", err)
	}
	if !state.Confirmed || !state.Finalized || state.Reorganized ||
		state.Network != action.Network || state.Reference != receipt.Reference ||
		state.AuthorizationID != action.ActionID || state.QuoteID != action.ActionID ||
		state.RequestID != action.ActionID || state.Payer != action.Payer ||
		state.Payee != action.Payee || state.AmountNanoTOS != action.AmountNanoTOS ||
		state.Comment != action.Comment ||
		state.ObservedMasterSeqno < before.ObservedMasterSeqno || state.ObservedAt.IsZero() {
		return NetworkReference{}, errors.New("TOS chain commitment finality binding mismatch")
	}
	after, err := a.runtime.CheckServiceReady(
		callContext, a.serviceReference, a.now().UTC(),
	)
	if err != nil || after.ObservedMasterSeqno < state.ObservedMasterSeqno {
		return NetworkReference{}, errors.New("TOS chain commitment finality is not current")
	}
	return NetworkReference{
		Network: a.network, Reference: receipt.Reference,
		Finalized: true, FinalizedCheckpoint: state.ObservedMasterSeqno,
	}, nil
}

func (a *chainAuthority) ResolveCommitment(ctx context.Context, kind, objectID, digest string, reference *NetworkReference) (*NetworkReference, error) {
	if a == nil || reference == nil || reference.Network != a.network || !reference.Finalized || reference.FinalizedCheckpoint == 0 ||
		strings.TrimSpace(reference.Reference) == "" || !chainCommitmentKindPattern.MatchString(kind) || objectID == "" || !chainDigestPattern.MatchString(digest) {
		return nil, errors.New("invalid finalized TOS commitment reference")
	}
	callContext, cancel, err := a.callContext(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	action := a.anchorAction(kind, objectID, digest, a.now().UTC())
	state, err := a.runtime.ObservePayment(callContext, chain.PaymentReference{
		Network: a.network, AuthorizationID: action.ActionID, QuoteID: action.ActionID, RequestID: action.ActionID,
		Reference: reference.Reference, Payer: action.Payer, Payee: action.Payee, AmountNanoTOS: action.AmountNanoTOS,
		Comment: action.Comment, MinimumMasterSeqno: reference.FinalizedCheckpoint,
	})
	if err != nil {
		return nil, fmt.Errorf("re-observe TOS chain commitment: %w", err)
	}
	if !state.Confirmed || !state.Finalized || state.Reorganized || state.Network != action.Network ||
		state.Reference != reference.Reference || state.AuthorizationID != action.ActionID || state.QuoteID != action.ActionID ||
		state.RequestID != action.ActionID || state.Payer != action.Payer || state.Payee != action.Payee ||
		state.AmountNanoTOS != action.AmountNanoTOS || state.Comment != action.Comment ||
		state.ObservedMasterSeqno < reference.FinalizedCheckpoint || state.ObservedAt.IsZero() {
		return nil, errors.New("TOS chain commitment is no longer finalized with the expected binding")
	}
	ready, err := a.runtime.CheckServiceReady(callContext, a.serviceReference, a.now().UTC())
	if err != nil || ready.ObservedMasterSeqno < state.ObservedMasterSeqno {
		return nil, errors.New("TOS chain commitment finality observation is not current")
	}
	return &NetworkReference{Network: a.network, Reference: reference.Reference, Finalized: true, FinalizedCheckpoint: state.ObservedMasterSeqno}, nil
}

func (a *chainAuthority) anchorAction(
	kind, objectID, digest string,
	now time.Time,
) chain.Action {
	hash := sha256.New()
	for _, value := range []string{
		"ATOS-TOS-CHAIN-AUTHORITY-V1",
		chain.ChainActionVersion,
		a.network,
		a.serviceReference.Address,
		a.serviceReference.ServiceID,
		string(chain.ActionKindAnchor),
		kind,
		objectID,
		digest,
		a.anchorPayer,
		a.anchorPayee,
		strconv.FormatUint(a.anchorAmountNano, 10),
	} {
		hash.Write([]byte(value))
		hash.Write([]byte{0})
	}
	anchorDigest := hex.EncodeToString(hash.Sum(nil))
	return chain.Action{
		Version:  chain.ChainActionVersion,
		ActionID: "anchor-" + anchorDigest, Network: a.network,
		Kind: chain.ActionKindAnchor, ObjectID: objectID, Digest: digest,
		Payer: a.anchorPayer, Payee: a.anchorPayee,
		AmountNanoTOS:     a.anchorAmountNano,
		Comment:           "atos:v1:" + anchorDigest,
		ExpiresUnixMillis: now.Add(a.anchorLifetime).UnixMilli(),
	}
}

func managedEconomicCommitment(kind string) bool {
	switch kind {
	case "escrow", "escrow-release", "settlement":
		return true
	default:
		return false
	}
}

func verifyActionReceipt(action chain.Action, receipt chain.ActionReceipt) error {
	if receipt.Version != action.Version || receipt.ActionID != action.ActionID ||
		receipt.Network != action.Network || receipt.Kind != action.Kind ||
		receipt.ObjectID != action.ObjectID || receipt.Digest != action.Digest ||
		receipt.Payer != action.Payer || receipt.Payee != action.Payee ||
		receipt.AmountNanoTOS != action.AmountNanoTOS || receipt.Comment != action.Comment ||
		strings.TrimSpace(receipt.Reference) == "" {
		return errors.New("TOS chain action publisher changed the immutable commitment")
	}
	return nil
}

func (a *chainAuthority) callContext(
	ctx context.Context,
) (context.Context, context.CancelFunc, error) {
	if ctx == nil {
		return nil, nil, errors.New("nil TOS chain authority context")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	callContext, cancel := context.WithTimeout(ctx, a.callTimeout)
	return callContext, cancel, nil
}

func (a *chainAuthority) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		if a.publisher != nil {
			a.closeErr = a.publisher.Close()
		}
	})
	return a.closeErr
}

var _ Authority = (*chainAuthority)(nil)
var _ CommitmentResolver = (*chainAuthority)(nil)
