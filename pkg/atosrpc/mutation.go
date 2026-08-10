package atosrpc

import (
	"fmt"

	atostosv1 "github.com/tosnetwork/tos-protocol/gen/atos/tos/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/protobuf/proto"
)

// atomicMutation applies a local state mutation and its idempotency record in
// one bbolt transaction. External Worker calls use the execution-specific
// two-phase journal instead.
func (s *Server) atomicMutation(
	method string,
	context *atostosv1.RequestContext,
	request proto.Message,
	response proto.Message,
	apply func(*bolt.Tx) error,
) error {
	if err := validateMutationContext(context, s.now()); err != nil {
		return err
	}
	requestDigest, err := mutationRequestDigest(method, request)
	if err != nil {
		return invalid("INVALID_ARGUMENT", "request cannot be canonicalized")
	}
	key := idempotencyKey(method, context)
	return s.store.update(func(tx *bolt.Tx) error {
		var record idempotencyRecord
		found, err := s.store.getJSON(tx, bucketIdempotency, key, &record)
		if err != nil {
			return err
		}
		if found {
			if record.RequestDigest != requestDigest {
				return conflict("IDEMPOTENCY_CONFLICT", "idempotency key is bound to a different request")
			}
			if record.Status != idempotencyCompleted || len(record.Response) == 0 {
				return unavailable("EXECUTION_UNCERTAIN", "idempotent mutation is still in progress")
			}
			if err := proto.Unmarshal(record.Response, response); err != nil {
				return fmt.Errorf("decode idempotent response: %w", err)
			}
			return nil
		}
		if err := apply(tx); err != nil {
			return err
		}
		encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(response)
		if err != nil {
			return err
		}
		nowMS := s.now().UnixMilli()
		return s.store.putJSON(tx, bucketIdempotency, key, idempotencyRecord{
			RequestDigest: requestDigest, Response: encoded,
			Status: idempotencyCompleted, CreatedAtMS: nowMS, UpdatedAtMS: nowMS,
		})
	})
}

type mutationRequestWithContext interface {
	GetContext() *atostosv1.RequestContext
}

// withoutTransportContext returns a clone of msg with the transport-scoped
// RequestContext fields that a well-behaved caller legitimately varies across
// retries of the same logical operation -- request_id, trace_id, deadline --
// zeroed out. caller_id and idempotency_key are left untouched: they are part
// of the request's durable identity, not its transport envelope.
//
// Anything derived from the result (an idempotency digest, or an Authority
// commitment digest) stays stable across retries of unchanged business
// content. Skipping this before computing an Authority.Commit digest is what
// let a retry after a partial local failure mint a second, divergent
// commitment for what the caller believed was one operation -- msg is not a
// mutationRequestWithContext, the clone is returned unchanged.
func withoutTransportContext(msg proto.Message) proto.Message {
	normalized := proto.Clone(msg)
	if withContext, ok := normalized.(mutationRequestWithContext); ok {
		if requestContext := withContext.GetContext(); requestContext != nil {
			requestContext.RequestId = ""
			requestContext.TraceId = ""
			requestContext.DeadlineUnixMillis = 0
		}
	}
	return normalized
}

// mutationRequestDigest binds the business request while excluding transport
// metadata that legitimately changes across retries. The idempotency record key
// already binds caller_id, method, and idempotency_key; keeping caller_id and
// idempotency_key in the normalized message is deliberate defense in depth.
func mutationRequestDigest(method string, request proto.Message) (string, error) {
	if request == nil {
		return "", fmt.Errorf("mutation request is required")
	}
	normalized := withoutTransportContext(request)
	withContext, ok := normalized.(mutationRequestWithContext)
	if !ok || withContext.GetContext() == nil {
		return "", fmt.Errorf("mutation request context is required")
	}
	return protoDigest("ATOS-RPC-IDEMPOTENCY-V1:"+method, normalized)
}
