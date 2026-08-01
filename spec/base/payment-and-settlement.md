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
pending-to-authorized request transition, and minimal immutable execution
authorization derived from the verified quote/payment/profile binding are
persisted atomically. The durable authorization is recovery material for that
exact paid request only; it MUST NOT admit another request or extend the quote
acceptance window.
Monotonic reorganization state blocks paid dispatch. Post-expiry rechecks use
the durable immutable binding, and a count-bounded coordinator advances one
crash-safe CAS scan cursor only after attempting its page. The concrete quorum
TOS adapter, `tos-edge` startup composition, adaptive watcher backoff, and
operational health counters are implemented. Refund handling, reviewed public
profile wiring, and production receipt delivery remain required before public
paid execution. The library scheduler is opt-in and applies a whole-batch
timeout and shutdown cancellation; it does not infer production chain
endpoints or policy.

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
receipt. This conservative default cannot be changed by a successful-receipt
policy.

A reviewed exact-profile registration may select a declarative successful
charge fraction from 0 through 10,000 basis points. An absent policy preserves
the compatible full quoted price. Edge calculates the result from the quoted
price using overflow-safe integer arithmetic rounded down to whole nano-TOS.
All successful completion and resolution paths require the same immutable plan
and durable negotiated selector. A non-default fraction is committed into the
private Worker task ID, so rebuilding an equivalent plan after restart is
deterministic and changed policy conflicts before task lookup or receipt
issuance. Receipt replay also compares the exact computed charge and fails
closed on drift. The policy is data-only, has no Worker callback, and creates
no per-request process state. Usage-dependent charging and charging failed work
remain outside this v0.1 rule.

The dispatch-resolution boundary issues a receipt only for a validated
terminal Worker outcome. `uncertain`, `NOT_FOUND`, `ACCEPTED`, and `RUNNING`
remain nonterminal and do not call key custody or mutate receipt state.
Terminal resolution derives `receipt-<sha256>` from the durable execution
identity. Exact retry therefore replays the stored receipt, while a changed
terminal meaning for the same execution conflicts at the journal boundary.

For restart recovery, the reference journal stores bounded semantic quote and
payment-authorization values plus the negotiated profile selector in the same
transaction that applies payment. It deliberately does not store the public
intent or private Worker payload. A caller must resupply the intent; Edge
recomputes its profile-bound digest and exact Worker mapping. An authorized
request may be invoked once, an already-running request may only use read-only
`GetTask`, and a terminal request may only replay its stored receipt. Missing
legacy context, malformed or mismatched context, and a reorganized nonterminal
payment fail closed. Receipt issuance still requires the current manifest and
current `receipt` role; persisted recovery context is never signing authority.

The reference HTTP server provides a bounded opt-in delivery adapter that
returns only an exact stored signed receipt envelope after a deployment-owned
authorizer produces the matching journal scope. The stock binary leaves it
disabled, and the adapter deliberately does not define or weaken the required
session/client authentication scheme.

This does not by itself provide production key custody or authenticated public
delivery. A deployment
must deploy the included software-key sidecar or an HSM-backed replacement
behind the bounded private Unix signer client, keep its private key outside
Edge and the Worker,
register reviewed vertical mappers behind the generic intent-to-Worker
boundary, define any refund reconciliation or unsupported usage-dependent
charging policy, implement the
specified idempotent Worker task table, and expose only the stored signed
envelope through an authenticated receipt resource.

The initial integration should consume the released Service Actor and escrow
interfaces through a pinned chain adapter. Contract code, ABI, deployment
address, network, confirmation policy, and feature flags belong in the
compatibility manifest; they are not inferred from ARD.
