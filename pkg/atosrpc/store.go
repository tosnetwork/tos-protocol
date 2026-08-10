package atosrpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	edgev1 "github.com/tosnetwork/tos-protocol/gen/tos/edge/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

var (
	bucketMeta              = []byte("meta-v1")
	bucketIdentities        = []byte("identities-v1")
	bucketIdentityURIs      = []byte("identity-uris-v1")
	bucketPrincipalBindings = []byte("principal-bindings-v1")
	bucketCapabilities      = []byte("capabilities-v1")
	bucketCapabilityLatest  = []byte("capability-latest-v1")
	bucketQuoteCommitments  = []byte("quote-commitments-v1")
	bucketSignerAuths       = []byte("signer-authorizations-v1")
	bucketEscrows           = []byte("escrows-v1")
	bucketEscrowByQuote     = []byte("escrow-by-quote-v1")
	bucketSettlements       = []byte("settlements-v1")
	bucketSettlementByJob   = []byte("settlement-by-job-v1")
	bucketSettlementByRcpt  = []byte("settlement-by-receipt-v1")
	bucketReceipts          = []byte("execution-receipts-v1")
	bucketReceiptByJob      = []byte("receipt-by-job-v1")
	bucketEvidence          = []byte("proof-of-service-v1")
	bucketProofs            = []byte("proofs-v1")
	bucketServiceQuotes     = []byte("service-quotes-v1")
	bucketJobs              = []byte("execution-jobs-v1")
	bucketIdempotency       = []byte("idempotency-v1")
)

var allBuckets = [][]byte{
	bucketMeta, bucketIdentities, bucketIdentityURIs, bucketPrincipalBindings,
	bucketCapabilities, bucketCapabilityLatest, bucketQuoteCommitments,
	bucketSignerAuths, bucketEscrows, bucketEscrowByQuote, bucketSettlements,
	bucketSettlementByJob, bucketSettlementByRcpt, bucketReceipts,
	bucketReceiptByJob, bucketEvidence, bucketProofs, bucketServiceQuotes,
	bucketJobs, bucketIdempotency,
}

const signingKeyName = "execution-signing-key-ed25519"

type store struct {
	db             *bolt.DB
	maxRecordBytes int
}

func openStore(path string, maxRecordBytes int) (*store, error) {
	if !filepath.IsAbs(path) {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		path = absolute
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create ATOS RPC state directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second, NoGrowSync: false})
	if err != nil {
		return nil, fmt.Errorf("open ATOS RPC state: %w", err)
	}
	s := &store{db: db, maxRecordBytes: maxRecordBytes}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range allBuckets {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize ATOS RPC state: %w", err)
	}
	return s, nil
}

func (s *store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *store) view(fn func(*bolt.Tx) error) error   { return s.db.View(fn) }
func (s *store) update(fn func(*bolt.Tx) error) error { return s.db.Update(fn) }

func (s *store) putProto(tx *bolt.Tx, bucket []byte, key string, value proto.Message) error {
	if tx == nil || value == nil || key == "" {
		return errors.New("invalid protobuf store write")
	}
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > s.maxRecordBytes {
		return errors.New("ATOS RPC record exceeds byte limit")
	}
	return tx.Bucket(bucket).Put([]byte(key), encoded)
}

func (s *store) getProto(tx *bolt.Tx, bucket []byte, key string, value proto.Message) (bool, error) {
	if tx == nil || value == nil || key == "" {
		return false, errors.New("invalid protobuf store read")
	}
	encoded := tx.Bucket(bucket).Get([]byte(key))
	if encoded == nil {
		return false, nil
	}
	if len(encoded) > s.maxRecordBytes {
		return false, errors.New("ATOS RPC stored record exceeds byte limit")
	}
	if err := proto.Unmarshal(append([]byte(nil), encoded...), value); err != nil {
		return false, err
	}
	return true, nil
}

func (s *store) putJSON(tx *bolt.Tx, bucket []byte, key string, value any) error {
	if tx == nil || key == "" {
		return errors.New("invalid JSON store write")
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > s.maxRecordBytes {
		return errors.New("ATOS RPC record exceeds byte limit")
	}
	return tx.Bucket(bucket).Put([]byte(key), encoded)
}

func (s *store) getJSON(tx *bolt.Tx, bucket []byte, key string, value any) (bool, error) {
	if tx == nil || key == "" || value == nil {
		return false, errors.New("invalid JSON store read")
	}
	encoded := tx.Bucket(bucket).Get([]byte(key))
	if encoded == nil {
		return false, nil
	}
	if len(encoded) > s.maxRecordBytes {
		return false, errors.New("ATOS RPC stored record exceeds byte limit")
	}
	if err := json.Unmarshal(append([]byte(nil), encoded...), value); err != nil {
		return false, err
	}
	return true, nil
}

func (s *store) signingKey() (ed25519.PrivateKey, error) {
	var privateKey ed25519.PrivateKey
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketMeta)
		if encoded := bucket.Get([]byte(signingKeyName)); encoded != nil {
			if len(encoded) != ed25519.PrivateKeySize {
				return errors.New("stored execution signing key is invalid")
			}
			privateKey = append(ed25519.PrivateKey(nil), encoded...)
			return nil
		}
		_, generated, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privateKey = append(ed25519.PrivateKey(nil), generated...)
		return bucket.Put([]byte(signingKeyName), privateKey)
	})
	return privateKey, err
}

type idempotencyRecord struct {
	RequestDigest string `json:"request_digest"`
	Response      []byte `json:"response,omitempty"`
	Status        string `json:"status"`
	CreatedAtMS   int64  `json:"created_at_ms"`
	UpdatedAtMS   int64  `json:"updated_at_ms"`
}

const (
	idempotencyInProgress = "in_progress"
	idempotencyCompleted  = "completed"
)

type storedServiceQuote struct {
	Quote           []byte `json:"quote"`
	Route           Route  `json:"route"`
	InputCommitment []byte `json:"input_commitment"`
	MaxOutputBytes  uint64 `json:"max_output_bytes"`
	// ThirdPartyBinding is set instead of Route when this quote was produced
	// by QuoteExecution's third-party branch -- exactly one of Route/
	// ThirdPartyBinding is meaningful for a given stored quote, mirroring
	// storedExecutionJob's Kind discriminator.
	ThirdPartyBinding *edgev1.ThirdPartyBindingRef `json:"third_party_binding,omitempty"`
}

// jobKind discriminates which durable execution state machine owns a
// storedExecutionJob: the native model-serving path (invokeDurableJob/
// recoverDurableJob against Worker) or the third-party path
// (invokeThirdPartyDurableJob/recoverThirdPartyDurableJob against
// ThirdPartyWorker). Both share completeDurableJob unchanged -- receipt
// signing, escrow charge and execution-signer authorization never depend on
// which one produced the completion.
type jobKind string

const (
	jobKindNative     jobKind = ""
	jobKindThirdParty jobKind = "third_party"
)

type storedExecutionJob struct {
	Record        []byte  `json:"record"`
	Kind          jobKind `json:"kind,omitempty"`
	WorkerRequest []byte  `json:"worker_request,omitempty"`
	// ThirdPartyWorkerRequest is set instead of WorkerRequest when Kind ==
	// jobKindThirdParty. Exactly one of the two is populated for a given
	// stored job.
	ThirdPartyWorkerRequest []byte `json:"third_party_worker_request,omitempty"`
	RequestDigest           string `json:"request_digest"`
	Input                   []byte `json:"input,omitempty"`
	Output                  []byte `json:"output,omitempty"`
	OutputDigest            string `json:"output_digest,omitempty"`
	Usage                   []byte `json:"usage,omitempty"`
	CanonicalReceipt        []byte `json:"canonical_receipt,omitempty"`
	ReceiptDigest           string `json:"receipt_digest,omitempty"`
}

type storedProof struct {
	ProofType string `json:"proof_type"`
	Bytes     []byte `json:"bytes"`
	Digest    string `json:"digest"`
	Network   string `json:"network"`
	Reference string `json:"reference"`
}
