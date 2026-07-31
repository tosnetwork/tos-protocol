# Payment and settlement

The base protocol separates quote, payer authorization, chain observation,
execution, receipt, and final settlement.

## Binding

A quote commits to the session, request-intent digest, service, profile,
service/resource revisions, network, payee, settlement target, price, resource
limits, expiry, and execution deadline. A payment authorization repeats the
exact quote/request IDs, network, payee, settlement reference, and maximum
amount.

Changing any bound field requires a new quote and authorization. A service
MUST NOT ask a client to authorize one destination and then settle another.
The authorization expires no later than the quote acceptance window.

## Observation states

An implementation maintains an idempotent durable state for each
`network + authorizationId + settlement` tuple:

```text
unseen -> observed -> confirmed -> applied
                 \-> rejected
observed/confirmed -> reorganized
applied -> refund-pending -> refunded
```

Exact confirmation policy is network and profile specific. The service states
it before authorization. Unless a signed policy explicitly allocates
zero-confirmation risk, work starts only after the required confirmation.

Duplicate observations and process restarts MUST converge on one application
effect. Watchers persist the block/reference cursor and enough request state
before acknowledging payment. They bound pending entries, retries,
reconciliation scans, block history, logs, and tombstones.

The Go reference implements the strict observation and exact-once local
application boundary described in
[payment-observation.md](payment-observation.md): runtime-signed quote,
client/delegation-signed authorization, exact echoed chain reference, party
and amount checks, high-water/freshness checks, and explicit finality and
overpayment policy. The resulting opaque observation, payment replay index,
and pending-to-authorized request transition are persisted atomically.
Monotonic reorganization state blocks paid dispatch. Post-expiry rechecks use
the durable immutable binding, and a count-bounded coordinator advances one
crash-safe CAS scan cursor only after attempting its page. A concrete TOS
contract adapter and `tos-edge` wiring, adaptive watcher backoff, exported
operational metrics, and refund handling remain required before public paid
execution. The library scheduler is opt-in and applies a whole-batch timeout
and shutdown cancellation; it does not infer production chain endpoints or
policy.

## Reorganization and failure

A reorganization never silently creates a second charge. The service returns
`PAYMENT_REORGANIZED`, pauses settlement where possible, and follows the
signed completion/refund policy. If useful work already completed, the receipt
records the actual outcome and charge state without asserting finality that no
longer exists.

Timeout, cancellation, adapter failure, overpayment, underpayment, and unused
authorization follow profile policy. Refund identifiers are idempotent and
bind the original authorization and receipt.

## Receipts

A receipt is signed by a manifest-authorized `receipt` key and binds the
quote, authorization, service/resource revisions, status, usage, charge,
result commitment, and completion time. It is evidence of that signer's
statement, not automatic proof of semantic correctness or chain finality.

The Go reference verifies the receipt against the original opaque payment and
current manifest role. Edge Core then persists the complete signed envelope,
its fingerprint, request-intent/payment identifiers, bounded usage and charge
while transitioning the exact paid request to its terminal state in one
transaction. A paid `authorized` or `running` request cannot bypass this path
with a plain terminal journal transition. Receipt IDs are globally unique per
network, exact replay has no second effect, and a charge above the applied
payment or a reorganized payment is rejected.

The Go reference also implements the internal successful-result issuance
boundary. Before dispatch, Edge Core atomically stores the exact private
invocation digest and globally unique task ID with the paid request's running
transition. The private Worker client returns an opaque validated response;
Edge Core repeats that durable execution claim, the paid running request and
quote limits, derives the output digest and fixed bounded usage fields, and
gives only canonical receipt bytes to a purpose-specific signer. It rejects
payload, task, invocation, validity, key, role, or signature substitution
before atomic persistence. Concurrent equivalent signatures resolve to the
one durable semantic receipt.

The generic fail-closed non-success policy is also implemented internally.
`failed`, `canceled`, and `timed_out` receipts contain an empty usage array,
zero charge, no result digest, and no raw diagnostic text. Edge derives the
only persisted error code from the status. A timeout cannot be issued before
the signed quote deadline; payment reorganization blocks every new failure
receipt. This conservative default is not a profile's final refund or partial
work charging policy.

This does not provide production key custody or public delivery. A deployment
must supply a bounded signer adapter, keep its private key outside the Worker,
define profile intent-to-Worker mapping and any partial-work refund/charging
policy, add an idempotent Worker task-status/result-replay recovery contract,
and expose only the stored signed envelope through an authenticated receipt
resource.

The initial integration should consume the released Service Actor and escrow
interfaces through a pinned chain adapter. Contract code, ABI, deployment
address, network, confirmation policy, and feature flags belong in the
compatibility manifest; they are not inferred from ARD.
