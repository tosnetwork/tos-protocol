# HTTP transport binding

HTTPS is the baseline public transport for ARD interoperability and browser
gateways. Public paid execution remains disabled until authentication,
idempotency, production payment observation, profile-specific isolated
invocation, production receipt key custody, failure policy, and authenticated
delivery are wired end to end.

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

These paths reserve the base namespace; they are not implemented by the
bootstrap server. Vertical operations are selected by a negotiated profile
and operation identifier, not by accepting arbitrary executable URLs.

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
