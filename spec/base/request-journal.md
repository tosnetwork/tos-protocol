# Durable request journal

Edge Core persists replay and idempotency state before it authorizes payment
or dispatches a vertical operation. The journal is a local implementation
boundary, not a public protocol document and not evidence that a request was
correctly executed.

## Identity and intent binding

One record is keyed by:

```text
network
+ authority
+ serviceId
+ sessionId
+ operation
+ requestId
```

The key is bound to the canonical request-intent digest. Reusing the complete
key with the same digest returns the existing record. Reusing it with a
different digest returns `REPLAY_DETECTED`; it never replaces the old intent.
Changing a network, authority, service, session, or operation creates a
different replay scope.

After the envelope has been authenticated, admission also claims its nonce in
the same storage transaction. The nonce index is scoped by network, authority,
and service, and is bound to the envelope domain, session, operation, request
ID, expiry, and domain-separated signed-envelope fingerprint. Reusing a live
nonce with a different binding or another signed envelope is rejected. An
exact retry returns the existing request record; it does not create another
operation. Re-signing the same request with a new nonce also returns the
existing record while consuming the new nonce.

The retention deadline is fixed when a record is first created. A replay
cannot extend or shorten it. Callers choose a deadline that covers the signed
request window, execution deadline, payment reconciliation policy, clock
skew, and required terminal-result availability, subject to local maximums.
The request deadline cannot precede its admitted envelope expiry.

## State machine

```text
pending -> authorized -> running -> succeeded
   |           |           |
   +-----------+-----------+-> failed
   +-----------+-----------+-> canceled
   +-----------+-----------+-> timed_out
   |
   +-> rejected
```

Terminal states never transition. Updates use a monotonically increasing
revision and compare-and-swap semantics. A stale revision is rejected rather
than silently overwriting a concurrent transition.

`succeeded` requires a result digest. `rejected`, `failed`, and `timed_out`
require a bounded error code. Diagnostic text, payloads, prompts, credentials,
model output, wallet data, and physical-site details do not belong in the
journal.

## Durability and bounds

The Go reference implementation in `pkg/journal` uses one synchronous
transaction for the nonce claim, nonce expiry index, request record, request
expiry index, and persistent counts. Admission is visible only after that
transaction commits. Restarting Edge Core therefore recovers either the prior
state or the complete new state, not a nonce without its request or a request
without its nonce.

Payment application uses the same database and transaction boundary. One
globally unique `network + authorizationId + settlement reference` record,
one request-to-payment index, and the request's `pending -> authorized`
transition commit or roll back together. Exact replay does not advance the
request revision. A newer observation may advance only monotonically; a
rollback is rejected. A recorded reorganization prevents
`authorized -> running` for the paid request.

Paid dispatch uses a separate execution claim in that same database. One
globally unique `network + serviceId + taskId`, one request-to-execution index,
the exact quote and payment identifiers, a deterministic digest of the complete
private Worker invocation, its deadline and millisecond-rounded-up retention
boundary, and the request's
`authorized -> running` transition commit or roll back together. The payment
must still be applied and not reorganized. Generic state transition cannot
bypass this claim. Exact replay returns the original claim and request revision
even after the execution deadline only while payment remains applied; it does
not authorize new work. A later recorded payment reorganization blocks claim
replay but does not erase the audit record. Changing the task, invocation
digest, quote, deadline, or request binding is a conflict, and reusing a live
task ID for another request is rejected.

Paid Worker claims require no more than seven days of remaining request
retention, even if a journal deployment permits longer non-execution records.
The Worker client may configure a lower maximum; request admission and Worker
policy must use compatible values.

Receipt application also uses one transaction. A globally unique
`network + receiptId`, its request index, the complete signed receipt
envelope, parsed bounded fields, and the request terminal transition commit or
roll back together. The journal recomputes the envelope fingerprint and
requires its canonical payload to match every persisted receipt field.
Exact replay returns the existing terminal record. A receipt cannot move a
different request, exceed the applied payment, or complete a reorganized
payment. Once a request has a receipt, a different receipt ID or semantic
outcome is a conflict; an index that references no stored receipt is journal
corruption and fails closed.

Paid `authorized` and `running` requests cannot use the generic terminal
transition. Success requires a receipt from `running`; failed, canceled, and
timed-out receipts may terminate an authorized request before worker dispatch
or a running request after dispatch.

The store has explicit limits for request count, nonce count, encoded record
bytes, retention, cleanup batch size, and file-open time. When capacity is
full it removes only entries whose retention deadline has passed. If no safely
evictable entry remains, new admission fails with backpressure.

There is at most one payment record and index per request, so payment state
cannot exceed the configured request count. Its encoded size uses the request
record byte limit, it inherits the immutable request retention deadline, and
cleanup deletes the payment and index in the same transaction as the request.
There is likewise at most one receipt and receipt index per request. It uses
the same encoded-record and retention limits and is deleted atomically with
the request. There is also at most one execution record and execution index per
request. It has a fixed encoded-size bound, inherits the immutable request
retention deadline, and is deleted in the same transaction as the request.

The payment reconciliation scanner stores one fixed-size cursor in journal
metadata. Each page examines at most the configured cleanup/write batch
limit, with an implementation hard cap of 4,096, counts expired entries
toward that limit, and returns only live payments. Cursor advance is
compare-and-swap. A crash before advance repeats the page safely; a stale
concurrent scanner is rejected instead of skipping another scanner's
position.

Cleanup runs in bounded batches owned by Edge Core. The on-disk file may keep
previously allocated pages for reuse, so file high-water size is not treated
as current record count. Operators monitor logical request records, nonce
claims, budget usage, payment, execution and receipt records, and file bytes.
The database file is
mode `0600`; its parent directory, backup, filesystem encryption, and offline
compaction remain deployment policy.

The reference store is local file-backed state. It does not put request state
on chain and does not create unbounded anonymous heap retention.

## Recovery boundary

After restart, a `pending`, `authorized`, or `running` record is not
automatically executed. A recovery coordinator must recheck current
controller/runtime authority, request expiry, payment state, owner policy,
worker disposition, and profile-specific recovery rules before taking the
next legal transition.

For a claimed `running` request, recovery may use only the stored task ID and
the exact invocation whose digest matches the claim. The claim proves that
Edge committed its dispatch decision; it does not prove that the Worker
received, started, or completed the call. The private RPC provides a read-only
`GetTask` method bound to the request ID, task ID, and stored invocation digest;
the client validates status, result, deterministic status/error mapping,
completion time, and retention before exposing an opaque recovered result. It
still performs no automatic retry. Production recovery requires the Worker to
durably implement that task table, return the same outcome for an exact task
replay, and reject a changed request under the same task ID.

The reference coordinator makes this distinction executable: a fresh atomic
claim can invoke once, whereas an exact journal replay can only query task
state. Transport failure is reported as uncertain without dropping the claim.
`NOT_FOUND` does not authorize resubmission because the Worker might have
performed an irreversible effect before losing or failing to expose state.
Recovery lookup remains legal after the execution deadline only inside the
original bounded retention window.

The resolution coordinator leaves `uncertain`, `NOT_FOUND`, `ACCEPTED`, and
`RUNNING` without a receipt or terminal journal change. Only validated terminal
Worker outcomes reach receipt application. Their deterministic receipt ID is
bound to the durable execution identity, not its outcome, so exact replay is
idempotent and a contradictory terminal observation fails closed.

The journal deliberately stores the private invocation digest, not prompts,
payloads, credentials, or model input. After restart, an authenticated client
retry or deterministic profile mapper must reproduce the exact invocation;
Edge replays the claim only if its digest matches. If the payload cannot be
reproduced, Edge may inspect journal and Worker state but must not invent or
blindly resubmit work.

The bootstrap `tos-edge` binary still exposes discovery only. The journal does
not enable public session, payment, or action routes by itself.

## Session and delegation budgets

An authenticated client request carries one session budget and zero to five
delegation budgets. Each budget binds the exact signed-grant fingerprint,
identifier, maximum cumulative actions, maximum cumulative nano-TOS, and the
session retention boundary.

Edge Core performs one bbolt transaction that:

1. claims or verifies the signed request nonce
2. creates or recovers the idempotent request
3. creates or verifies the request-to-budget claim
4. increments the session and every delegation budget

An exact request replay, including one re-signed with a fresh nonce, recovers
the existing budget claim and does not increment usage again. Reusing a
request with different charge, grant fingerprint, limits, client, or budget
chain fails. A session-managed request cannot be replayed through the
unbudgeted admission method.

Budget records and their expiry index are count-bounded independently of
requests and nonces. They remain until session expiry and are pruned in
bounded batches; request budget-claim entries are removed with their request
records.
