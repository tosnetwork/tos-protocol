// Package nativeregistrypublisher provides the enrolled journal-before-
// broadcast boundary for Phase 5B Native registry actions.
package nativeregistrypublisher

import (
	"context"
	"errors"
	"sync"

	"github.com/tosnetwork/tos-protocol/pkg/nativeregistry"
)

type Receipt struct {
	TransactionReference string `json:"transaction_reference"`
}

const PreparedMutationVersion = "tos.native.registry-prepared-mutation.v1"

type PreparedMutation struct {
	Version          string `json:"version"`
	MessageBOCBase64 string `json:"message_boc_base64"`
	MessageDigest    string `json:"message_digest"`
}

type Backend interface {
	CheckReady(context.Context, Policy) error
	EnrollmentBinding() string
	// Resolve observes the deterministic Action Anchor without mutation.
	// ErrPublisherNotFound is permitted only after authoritative absence.
	Resolve(context.Context, nativeregistry.Submission) (Receipt, error)
	// Prepare produces the exact signed external wallet message without network
	// mutation. The Publisher durably commits these bytes before Publish.
	Prepare(context.Context, nativeregistry.Submission) (PreparedMutation, error)
	// Publish may resubmit only the same durable prepared bytes. Wallet seqno and
	// message identity make a lost-response replay one canonical transaction.
	Publish(context.Context, nativeregistry.Submission, PreparedMutation, bool) (Receipt, error)
	Close() error
}

type Policy struct {
	NetworkID         string `json:"network_id"`
	GenesisRootHash   string `json:"genesis_root_hash"`
	GenesisFileHash   string `json:"genesis_file_hash"`
	RegistryWorkchain int32  `json:"registry_workchain"`
	ContractCodeHash  string `json:"contract_code_hash"`
	LocatorVersion    string `json:"locator_version"`
	ActionVersion     string `json:"action_version"`
	PayerIdentity     string `json:"payer_identity"`
}

type Publisher struct {
	store   *actionStore
	backend Backend
	policy  Policy
	mu      sync.Mutex
}

// Enroll validates the concrete mutation/recovery backend before making its
// immutable identity durable. A failed capability or network check cannot
// strand a newly created journal.
func Enroll(ctx context.Context, path, journalIdentity string, policy Policy, backend Backend) error {
	if ctx == nil || backend == nil {
		return errors.New("native registry enrollment backend is required")
	}
	if err := backend.CheckReady(ctx, policy); err != nil {
		return errors.Join(errors.New("native registry backend is not ready for enrollment"), err)
	}
	return InitializeJournal(path, journalIdentity, policy, backend.EnrollmentBinding())
}

func Open(path, journalIdentity string, policy Policy, backend Backend) (*Publisher, error) {
	if backend == nil {
		return nil, errors.New("native registry backend is required")
	}
	store, err := openActionStore(path, journalIdentity, policy, backend.EnrollmentBinding())
	if err != nil {
		return nil, err
	}
	return &Publisher{store: store, backend: backend, policy: policy}, nil
}

func (p *Publisher) CheckReady(ctx context.Context) error {
	if p == nil || p.store == nil || p.backend == nil {
		return errors.New("native registry publisher is not configured")
	}
	return p.backend.CheckReady(ctx, p.policy)
}

func (p *Publisher) Close() error {
	if p == nil {
		return nil
	}
	var storeErr, backendErr error
	if p.store != nil {
		storeErr = p.store.close()
	}
	if p.backend != nil {
		backendErr = p.backend.Close()
	}
	return errors.Join(storeErr, backendErr)
}

// Resolve is strictly read-only. A missing enrolled record returns the typed
// ErrPublisherNotFound value; pending and conflicting records fail closed.
func (p *Publisher) Resolve(ctx context.Context, submission nativeregistry.Submission, actionID, semanticDigest string) error {
	computedID, computedDigest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil || computedID != actionID || computedDigest != semanticDigest {
		return errors.New("native registry publisher semantic mismatch")
	}
	record, err := p.store.get(actionID)
	if err != nil {
		return err
	}
	if record == nil {
		_, resolveErr := p.backend.Resolve(ctx, submission)
		if errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) {
			return nativeregistry.ErrPublisherNotFound
		}
		if resolveErr != nil {
			return nativeregistry.ErrAmbiguous
		}
		// Canonical completion without a local record is a valid fresh-replica
		// recovery result. It is deliberately not projected into this journal:
		// Resolve is read-only and must never invent a prior local intent.
		return nil
	}
	if record.SemanticDigest != semanticDigest {
		return errors.New("native registry publisher idempotency conflict")
	}
	receipt, resolveErr := p.backend.Resolve(ctx, submission)
	if errors.Is(resolveErr, nativeregistry.ErrPublisherPending) && record.State != stateCompleted {
		return nativeregistry.ErrPublisherPending
	}
	if errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) {
		// A local pending/completed record can never turn canonical absence into
		// replay authorization. The inconsistency is fail-closed.
		return nativeregistry.ErrAmbiguous
	}
	if resolveErr != nil || receipt.TransactionReference == "" {
		return nativeregistry.ErrAmbiguous
	}
	if record.State != stateCompleted {
		if err := p.store.complete(actionID, semanticDigest, receipt); err != nil {
			return err
		}
		return nil
	}
	return nil
}

func (p *Publisher) Publish(ctx context.Context, submission nativeregistry.Submission, actionID, semanticDigest string) error {
	computedID, computedDigest, err := nativeregistry.ValidateSubmission(submission)
	if err != nil || computedID != actionID || computedDigest != semanticDigest {
		return errors.New("native registry publisher semantic mismatch")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	record, err := p.store.claim(actionID, semanticDigest, submission)
	if err != nil {
		return err
	}
	if record.State == stateCompleted {
		_, resolveErr := p.backend.Resolve(ctx, submission)
		if resolveErr != nil {
			return nativeregistry.ErrAmbiguous
		}
		return nil
	}
	recovering := record.Attempts > 0
	if recovering {
		receipt, resolveErr := p.backend.Resolve(ctx, submission)
		if resolveErr == nil && receipt.TransactionReference != "" {
			return p.store.complete(actionID, semanticDigest, receipt)
		}
		if !errors.Is(resolveErr, nativeregistry.ErrPublisherNotFound) && !errors.Is(resolveErr, nativeregistry.ErrPublisherPending) {
			return nativeregistry.ErrAmbiguous
		}
	}
	prepared := record.Prepared
	if prepared == nil {
		if recovering {
			// An attempt without durable prepared bytes is an old/corrupt journal
			// state. It is impossible to prove what was handed to key custody.
			return nativeregistry.ErrAmbiguous
		}
		value, prepareErr := p.backend.Prepare(ctx, submission)
		if prepareErr != nil {
			return prepareErr
		}
		if err := p.store.prepare(actionID, semanticDigest, value); err != nil {
			return err
		}
		prepared = &value
	}
	if err := p.store.markAttempt(actionID, semanticDigest); err != nil {
		return err
	}
	receipt, err := p.backend.Publish(ctx, submission, *prepared, recovering)
	if err != nil {
		return err
	}
	if receipt.TransactionReference == "" {
		return errors.New("native registry backend returned an empty transaction reference")
	}
	return p.store.complete(actionID, semanticDigest, receipt)
}
