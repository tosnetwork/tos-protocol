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

The store has explicit limits for request count, nonce count, encoded record
bytes, retention, cleanup batch size, and file-open time. When capacity is
full it removes only entries whose retention deadline has passed. If no safely
evictable entry remains, new admission fails with backpressure.

There is at most one payment record and index per request, so payment state
cannot exceed the configured request count. Its encoded size uses the request
record byte limit, it inherits the immutable request retention deadline, and
cleanup deletes the payment and index in the same transaction as the request.

Cleanup runs in bounded batches owned by Edge Core. The on-disk file may keep
previously allocated pages for reuse, so file high-water size is not treated
as current record count. Operators monitor logical request records, nonce
claims, budget usage, payment records, and file bytes. The database file is
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
