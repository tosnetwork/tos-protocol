# HTTP transport binding

HTTPS is the baseline public transport for ARD interoperability and browser
gateways. The generic server contains a bounded paid-action resource, but it
registers that resource only when deployment composition supplies the complete
current-authority authorizer, payment observer, exact vertical profile plan,
private Worker, receipt signer, readiness checks, durable journal, retention
policy, and concurrency bound. The stock `tos-edge` command supplies no
vertical plan and therefore remains discovery-only.

## Discovery

| Path | Method | Content type |
|---|---|---|
| `/.well-known/ai-catalog.json` | `GET` | `application/json` |
| `/.well-known/tos-service.json` | `GET` | `application/vnd.tos.service+json` |

Discovery responses are short-lived, revalidated, bounded JSON. Clients MUST
honor the descriptor's declared expiry even if an HTTP cache serves it.
`Content-Type` is authoritative; clients do not sniff HTML or executable
content as a TOS document.

## Transaction resources

The draft resource layout is:

```text
POST /tos/v1/sessions
POST /tos/v1/quotes
POST /tos/v1/actions
GET  /tos/v1/actions/{actionId}
POST /tos/v1/actions/{actionId}:cancel
GET  /tos/v1/actions/{actionId}/events
GET  /tos/v1/receipts/{receiptId}
```

These paths reserve the base namespace. The generic server currently implements
`POST /tos/v1/actions` plus optional authenticated action-status and receipt
resources. Session and quote issuance exist as transport-neutral verified
libraries; public session/quote creation, cancellation, and events are not registered. The
receipt resource is installed only when deployment composition supplies both
an explicit receipt-access authorizer and a trusted durable receipt source.
The stock `tos-edge` binary supplies neither public resource composition and
therefore keeps both routes absent.
Vertical operations are selected by a negotiated profile and operation
identifier, not by accepting arbitrary executable URLs.

An enabled action resource accepts one strict, bounded JSON document containing
the exact intent bytes and signed session, quote, delegation, and payment
envelopes. It rejects unknown or duplicate fields, content encoding, query
parameters, oversized bodies, incomplete dependencies, and excess concurrency.
After authentication, a new request rejects known-unready chain, signer,
Worker, or exact-profile state before payment admission. An existing durable
request remains eligible for strict `GetTask` recovery while new-work capacity
is full or draining; that path cannot call `Invoke`. Current authority uses a
process-monotonic chain high-water mark with a concurrent
overtaking check. Payment application, execution claim, Worker task identity,
terminal receipt, and replay remain durable. A new claim may call `Invoke` once;
every replay uses `GetTask`. Ambiguous private-RPC delivery returns `202` with
status `uncertain` and never grants permission to resubmit work. Terminal
success returns bounded output and the signed receipt; terminal failure returns
only the signed zero-charge receipt.

The v0.1 implementation admits at most eight concurrent action handlers per
process (default four). Admission occurs before body allocation, and each body
and response has a fixed byte ceiling. Deployments scale with additional
bounded processes instead of raising an edge terminal to an unbounded
request-buffer or in-flight task population.

An enabled action-status resource authenticates the exact path action ID before
consulting durable state and returns only `{version, actionId, status}` plus the
original signed receipt envelope when a terminal request has an applied
payment. It never serializes the intent, output, payer/payee fields, Worker
payload, execution claim, timestamps, error diagnostics, or other journal
metadata. A paid terminal record without its atomically required receipt fails
closed. A legitimate terminal record created before payment may omit a receipt.
Authorization denial or panic, malformed IDs, query parameters, missing state,
and expired state share the same non-enumerating `404`; internal inconsistency
uses a redacted `503`. Responses use `Cache-Control: no-store`.

An enabled receipt resource authenticates before consulting durable state,
uses one bounded authorization deadline, requires the resulting scope to match
the server network and service, and returns only the exact stored signed
envelope with `Cache-Control: no-store`. Authorization denial, malformed IDs,
missing records, and expired records share one non-enumerating response.
Internal journal fields, output bytes, payer metadata, and private errors are
never serialized. The transport-neutral hook is not itself an authentication
scheme: a deployment still has to implement current session/client or
delegation verification and bind it to the exact receipt ID and request scope.

Creation requests require a bounded unpredictable idempotency key. Reuse with
identical canonical content returns the existing disposition; reuse with
different content returns `REPLAY_DETECTED`. HTTP retry behavior follows
`errors.md`, not the method name alone.

Signed protocol values are transported in `signed-envelope.schema.json`.
Authentication verifies the canonical payload, exact domain, runtime role,
session, expiry, nonce, revocation, and replay state before parsing vertical
content.

## Limits

Servers set finite header, body, decompression, connection, stream, request,
idle, write, and total execution limits. They apply admission before reading
or allocating profile maximums whenever possible. Slow clients, disconnects,
timeouts, cancellation, and write failures converge on the same bounded
cleanup path.

TLS identity protects transport but does not replace controller/runtime
signatures. Proxies and relays must not rewrite signed objects or become
payment authority.
