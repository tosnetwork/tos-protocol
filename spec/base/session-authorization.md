# Session and delegation authorization

This layer turns a fresh verified service manifest into bounded client request
authority. It still does not prove payment, runtime capacity, executor
isolation, or permission to bypass local owner policy.

## Session grant

A session grant is canonical CBOR signed in a `tos.session.v1` envelope by a
current manifest runtime key with the `authenticate` role. Verification binds:

- service ID, runtime key ID, and current manifest revision
- exact profile ID and semantic version
- negotiated profile extensions
- client key identifier and permitted operations
- issue/expiry time inside the runtime key and manifest lifetime
- cumulative `maxRequests` and `maxNanoTos`

Every negotiated profile extension must also be declared by the signed
manifest; a syntactically valid but undeclared extension is rejected.
The signed envelope must cover the complete grant lifetime. A still-valid
grant is reverified when manifest authority freshness expires.

## Client-key resolution

The grant contains a key identifier, not an unauthenticated public key.
`ClientKeyResolver` obtains the Ed25519 key from chain state, the authenticated
session-opening exchange, or an explicitly approved local trust policy. Every
result binds network, service, and key ID and includes:

- key validity and key-revocation status
- the authenticated client/payment principal represented by the key
- a bounded delegation-revocation list
- observation time and optional masterchain sequence

The verifier propagates context cancellation and a caller-maintained
masterchain high-water mark. Resolver results are defensively copied and
cached only inside one authorization call, for at most six distinct signers.

## Delegation chain

Zero delegations means the session client signs the request directly.
Otherwise, the first delegation has depth zero and is signed by the session
client. Every child:

- is signed by the previous subject
- binds the exact runtime-issued session ID
- names the previous delegation as parent and increases depth by one
- keeps the service audience
- contains the operation-specific required scope
- cannot increase action, nano-TOS, or time limits
- uses a distinct delegation and signer identifier

Depth is at most four, so the chain contains at most five delegations. Every
issuer key and delegation revocation is checked. The final request envelope
must be signed by the leaf subject and remain inside the session, leaf-key,
and delegation validity windows.

Delegation changes the signing key, not the root principal. A payment
authorization's payer must match the root session client's authenticated
principal unless a future explicit sponsorship capability defines otherwise.

The message-specific semantic callback receives the canonical payload, exact
request/session/operation/intent binding, and exact nano-TOS charge. Edge Core
independently repeats the binding and charge before persistence.

## Atomic cumulative admission

Successful signature verification produces an opaque value, not immediate
execution permission. Edge Core converts it to one session budget plus every
delegation budget and commits them with the nonce and idempotent request in
one bbolt transaction.

Each budget records its signed-envelope fingerprint, maximum actions,
maximum nano-TOS, used actions, used nano-TOS, and session expiry. A new
request increments all budgets or none. Exact replay returns the existing
request and budget claim without incrementing again. Concurrent requests are
serialized by the database transaction and fail with budget exhaustion once
any ancestor limit is reached.

The default journal bounds budget records to 600,000: six authority budgets
for each of 100,000 request records in the worst configured default shape.
No process-global session or delegation cache is introduced.

## Remaining integration

The production deployment must provide the authoritative client-key resolver
and payment observer, then connect this admission result to the isolated
Worker RPC. The discovery-only server exposes no public session or invocation
route in this milestone.
