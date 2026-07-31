# RLDP and TOS Sites transport binding

TOS Sites carries the same HTTP resource semantics over ADNL/RLDP. It changes
reachability, not the signed application protocol.

A client may reach a service through:

- a `name.tos` site record resolved to ADNL
- a raw, already trusted ADNL address from a signed manifest
- an owner-selected relay or reverse tunnel

A `.tos` name is optional. Raw ADNL operation does not bypass manifest,
profile, session, quote, payment, replay, or receipt verification.

## Authority

The ADNL endpoint used for RLDP MUST appear in a fresh controller-signed
manifest or an explicitly trusted local policy. DNS resolution, proxy
configuration, and successful RLDP delivery do not independently authorize
the endpoint.

An `rldp-http-proxy` is a transport bridge. It must not receive wallet owner
keys, re-sign application values, select a payee, or convert discovery data
into execution authority. Clients verify end-to-end signed objects after
proxy transport.

## Semantic parity

Methods, paths, content types, canonical bodies, idempotency keys, status
mapping, cancellation, and event ordering are the same as `transport-http.md`.
Transport-specific retry MUST NOT duplicate a non-idempotent action. A client
retries using the same protocol request ID and queries its prior disposition.

RLDP transfer limits are no larger than the application body's local policy.
Implementations bound concurrent transfers, declared and reassembled size,
timeouts, peer state, retransmission, incomplete transfers, and response
buffers. Endpoint fallback is finite and preserves the original service,
session, request, and quote bindings.

Browser clients normally require an HTTPS gateway, local TOS Sites proxy, or
approved native helper. The gateway's HTTPS identity remains distinct from
the TOS controller and runtime signer.
