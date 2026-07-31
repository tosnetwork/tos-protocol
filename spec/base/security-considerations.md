# Security considerations

The protocol crosses public discovery, chain state, payment, local runtimes,
and potentially physical equipment. No single document is authoritative for
all of them.

## Required separations

- ARD and Registry results are untrusted discovery hints.
- A descriptor is not a live service manifest.
- A manifest capability claim is not admission or proof.
- A quote is not payment.
- Payment is not permission to violate owner, site, privacy, or safety policy.
- A receipt proves only what its signer, schema, digest, and evidence policy
  actually bind.

Clients MUST re-resolve controller and revocation authority, verify a fresh
manifest and runtime role, negotiate critical extensions, and bind session,
quote, authorization, execution, and receipt identifiers and revisions.
Authority snapshots must have a bounded age and bind the current canonical
manifest digest; a still-valid old signature does not authorize a replaced
manifest or revoked runtime key. Semantic payload validation and complete
session/operation/request/intent binding occur before nonce or request state
is committed.

A chain authority adapter must match the requested network, contract address,
and service ID; require an approved contract code hash and the configured
finality level; honor cancellation and timeout; and reject state older than a
caller-maintained masterchain high-water mark. Service response-attestation
keys are not manifest-controller keys unless an explicit authoritative
binding says so.

## Bounded state

Every connection, parser, redirect, lookup, federation edge, session, nonce,
delegation budget, idempotency record, quote, watcher, queue, stream, journal,
artifact, log, and cache needs a size, count, lifetime, and cleanup owner.
Backpressure MUST occur
before expensive allocation or runtime dispatch. Failure, timeout,
cancellation, payment rejection, and restart paths MUST release RAM, disk,
accelerator memory, file descriptors, reservations, and watchers.

Do not allocate using a remote uint64 limit without checking it against a
smaller local policy and the host integer range.

Session and delegation limits are cumulative, not per-request hints.
Signature verification without atomic usage accounting is insufficient.
Nonce claim, idempotent request creation, and every authority-budget increment
must commit together. Exact replay must not charge again, while changed
charge, grant, delegation chain, or request intent must fail.

Payment RPC output must echo the complete authorization, quote, request,
network, and settlement reference. Require fresh monotonic chain state and an
explicit finality policy. The safe default rejects both underpayment and
overpayment: accepting a value above the exact quote is a profile policy and
must still remain within the client's signed maximum. Applying payment must
atomically bind its globally unique authorization/reference to one pending
request; exact replay has no second effect. A recorded reorganization must
block new paid dispatch until an authenticated reconciliation policy resolves
it. Payment records, watcher cursors, retry history, and tombstones require
the same count, lifetime, and cleanup ownership as requests.

Paid dispatch must atomically persist one globally unique Worker task ID, an
internal digest of the exact private invocation, its quote/payment/deadline
and journal-retention binding, and the `authorized -> running` transition.
Generic transitions must not bypass the claim. Exact claim replay is read-only;
a changed request or cross-request task reuse must fail. Replay must recheck
that the persisted payment has not been reorganized. The execution record and
both indexes must be size/count/lifetime bounded and deleted with their
request.

A paid request terminal state and its signed receipt must commit atomically.
Persist the complete envelope, recompute its fingerprint, and require the
canonical payload to match the request, payment, revisions, status, usage,
charge, result commitment, and completion time. Workers never receive the
receipt private key. Receipt IDs and request indexes are bounded and unique;
exact retry must not create a second terminal effect.

Do not accept a raw Worker protobuf as receipt evidence. Preserve an opaque
validated result containing its immutable request binding, requested output
limit, deadline, task ID, private-request digest, completion time, byte
accounting, usage, and output. Before signing, repeat these against the exact
paid running request, durable execution claim and quote. Give
key custody only canonical receipt bytes, then re-verify its returned payload,
validity, key role, and signature. Concurrent semantically identical signing
attempts may create more than one envelope but must resolve to exactly one
durable receipt and request transition.

Do not persist Worker, adapter, model, or signer error strings as terminal
protocol state. Map a non-success receipt status to one deterministic bounded
error code. The generic fallback is zero-charge with an explicit empty usage
array and no result digest. Reject an early timeout and re-check payment
reorganization immediately before atomic application.

## Parsing and transport

Reject unknown fields in security-sensitive typed values, duplicate JSON or
CBOR keys, floats, tags, indefinite CBOR, invalid UTF-8, excessive nesting,
oversized compressed bodies, and ambiguous value-or-reference objects.
Remote fetching requires SSRF controls covering DNS rebinding, redirects,
private/link-local ranges, URL credentials, decompression, content type,
timeouts, and total fan-out.

Transport encryption does not replace signed object verification. RLDP and
relay endpoints are subject to the same authority and replay checks as HTTPS.

The Edge-to-worker RPC is not a public transport. Its Unix socket and parent
directory must be non-symlink objects owned by the Edge process user, with no
group or other permissions. Both peers bound protobuf messages. Edge applies
its own deadline and byte policy before dispatch, verifies correlation and
usage fields on every result, and never retries an invocation implicitly.
Public work must not acquire emergency, control, real-time, owner-local, or
background priority merely by setting a wire enum.

A durable Edge claim is not proof that the Worker observed the call. Across
the claim/RPC crash boundary, recovery must use an idempotent task-status or
exact-result-replay contract with bounded retention. The reference client
implements strict `GetTask` validation, but each Worker must still durably
enforce the task binding and retention contract. Automatic invocation retry is
unsafe and must remain disabled until that property is demonstrated.

Dispatch code must branch on the durable claim disposition, not on an HTTP,
RPC, context, or process error. Only a new claim can invoke. Replay, ambiguous
failure, and `NOT_FOUND` can query or enter profile-specific reconciliation,
but cannot resubmit the operation. Error results must retain the committed
claim identity so callers cannot accidentally treat them as pre-claim
failures.

Task cancellation must repeat the request ID, task ID, and invocation digest,
and the response must echo them. Never authorize cancellation from an
uncorrelated request ID or an unvalidated boolean response.

A vertical mapper never owns security fields in the private Worker request.
Before calling it, Edge recomputes the profile/version/operation-bound public
intent commitment. After it returns, Edge derives task identity, correlation,
payment, limit, deadline, retention, and external priority fields, then runs
the concrete Worker client's full local-policy validation before atomically
claiming execution. Mapper failure or panic must not leave a paid request in
`running`; mapper output drift after restart must not create another task.
Mapper selection must also be exact: do not fall back across profile versions,
extension sets, or operations. The reference registry is immutable and
capacity-bounded at construction so hostile request diversity cannot grow a
process-global mapper cache.

## Keys and updates

Runtime and update keys are distinct. Rotation must overlap safely, honor
revocation, and fail closed for unknown critical policy. Private keys, wallet
keys, model credentials, and sensor credentials are never placed in ARD,
manifests, receipts, logs, or vertical worker payloads.

## Vertical execution

Profiles define isolation, cancellation, metering, privacy, and cleanup beyond
this base. A physical AI profile additionally requires disconnected local
operation, independent safety interlocks, signed model/update rollback,
real-time local priority, raw-I/O denial, and bounded fleet control. A generic
network authorization MUST NOT directly command an actuator.

This draft has not received an independent security audit and MUST NOT be
represented as production-ready.
