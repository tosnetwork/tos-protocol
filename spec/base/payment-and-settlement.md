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
contract adapter, automatic watcher scheduling/backoff, operational
observability, and refund handling remain required before public paid
execution.

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

The initial integration should consume the released Service Actor and escrow
interfaces through a pinned chain adapter. Contract code, ABI, deployment
address, network, confirmation policy, and feature flags belong in the
compatibility manifest; they are not inferred from ARD.
