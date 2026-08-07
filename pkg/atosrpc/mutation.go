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
	requestDigest, err := protoDigest("ATOS-RPC-IDEMPOTENCY-V1:"+method, request)
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
