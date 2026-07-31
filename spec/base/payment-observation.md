# Quote and payment observation authorization

This layer connects a runtime-issued quote, a client-signed payment
authorization, and one fresh chain observation without treating discovery,
an RPC endpoint, or an unsigned JSON value as payment evidence. It does not
yet implement a production chain watcher/cursor, automatic reorganization
reconciliation, refunds, or settlement.

## Runtime quote

A quote is canonical CBOR in a `tos.quote.v1` envelope signed by a current
manifest runtime key with the `quote` role. Verification requires:

- the exact current network, service ID, and manifest revision
- a profile ID declared by that manifest
- a valid quote/session/request/operation/intent binding
- bounded input, output, resource, price, acceptance, and deadline fields
- a signed-envelope interval that covers the quote acceptance interval

The verified quote is opaque. Raw ARD, descriptor, profile, HTTP, RLDP, or
JSON-RPC data cannot construct it.

## Client payment authorization

The verified quote is combined with the exact runtime-issued session. The
quote must bind that session, service, profile, network, operation, and
request intent, and its acceptance interval must remain inside the session.

The payment authorization is canonical CBOR in a
`tos.payment-authorization.v1` envelope signed by the session client or the
leaf of a complete verified delegation chain. It repeats the quote/request,
network, payer, payee, settlement reference, maximum amount, and expiry.
Destination substitution, cross-session reuse, and a maximum amount that
expands any session/delegation budget are rejected.
The payer must equal the root session key's authenticated principal;
delegation does not permit payer substitution.

Edge Core can atomically admit this exact client envelope and quoted charge
into the nonce, idempotency, and cumulative-budget journal. This creates a
pending request; it is not proof that payment occurred.

## Chain observation

The observer queries exactly:

```text
network + authorizationId + quoteId + requestId + settlement reference
```

The chain adapter response must echo every query field and return payer,
payee, amount, confirmation/finality state, masterchain sequence, and
observation time. The observer rejects:

- a mismatched response or party
- a reorganized or unconfirmed payment
- a non-final payment when local policy requires finality
- an observation below the caller's masterchain high-water mark
- a stale or excessively future-dated observation
- underpayment or payment above the client's signed maximum

By default, the observed amount must equal the quote price. A profile may
explicitly enable overpayment acceptance, but the amount still cannot exceed
the client's signed maximum. Non-final confirmation is likewise an explicit
local risk policy, never an implicit fallback.

Resolver calls are context-cancelable and deadline-bounded. The verifier adds
no process-global cache or watcher; every result expires with the configured
observation freshness window.

## Durable application

Edge Core accepts only the observer's opaque `VerifiedObservation`, repeats
the complete authorization/request binding, and applies it to the already
pending request in one bbolt transaction. That transaction:

1. creates one payment record keyed by
   `network + authorizationId + settlement reference`
2. creates the request-to-payment index
3. transitions the exact request from `pending` to `authorized`

The payment key is globally unique inside the journal. Reuse for another
request fails, exact replay returns the stored state without advancing either
request or budget usage, and a newer observation may only advance its
masterchain high-water position. A lower sequence or observation time is
rejected. Payment records are bounded one-to-one by request records and are
deleted with the request retention boundary.

The journal can monotonically mark an applied payment `reorganized`. A paid
request with that status cannot transition from `authorized` to `running`.
This is a storage and dispatch safety primitive; callers cannot treat a raw
RPC response as a verified reorganization.

## Remaining integration

A subsequent milestone must implement the production watcher, persist its
scan cursor, authenticate reorganization events before calling the journal,
and implement bounded restart reconciliation and signed completion/refund
policy. Until those pieces and isolated execution are connected, the public
server exposes no paid invocation route.
