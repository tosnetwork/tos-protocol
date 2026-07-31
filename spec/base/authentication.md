# Authentication and delegated authority

TOS Service Protocol separates keys by consequence:

- owner keys control recovery and MUST remain offline or in a dedicated wallet
- controller keys publish and rotate operational service authority
- runtime keys authenticate sessions and sign only the roles listed in a
  fresh controller-signed manifest
- session keys are short-lived client or service keys scoped to one session
- delegated keys receive an attenuated subset of authority

A runtime process MUST NOT load an owner wallet key.

## Manifest verification

Before accepting a runtime signature, a verifier MUST:

1. resolve the expected controller through an approved TOS chain or local
   trust policy
2. verify the controller signature over the canonical manifest
3. check network, service ID, manifest revision, issue time, and expiry
4. find the runtime `keyId`, verify Ed25519 public-key encoding, role, and key
   validity
5. check revocation and replacement state
6. verify the message envelope under its exact domain

HTTPS, RLDP, relay, ARD, DNS, and Registry transport identity do not replace
these checks.

The reference implementation and its exact admission boundary are described
in [authorization-pipeline.md](authorization-pipeline.md). Its authority
snapshot is time-bounded; a valid old signature does not override controller
rotation, manifest replacement, or runtime-key revocation.

## Replay

Every signed envelope has an unpredictable 128-bit nonce and a maximum
24-hour validity. Nonces are necessary but not sufficient. After signature,
manifest role, delegation, revocation, profile, and payload checks succeed,
the server MUST atomically claim the nonce and create or recover the durable
request record. It MUST NOT claim attacker-supplied nonces before
authentication.

Nonce uniqueness is scoped by network, authority, and service. Reusing a live
nonce for another session, operation, request, domain, or expiry is rejected.
The claim also stores a domain-separated SHA-256 fingerprint of the complete
signed envelope. An exact retry of the same signed, idempotent request may
return its existing record without executing it again. A different envelope
that reuses the nonce is rejected even when it names the same request. A
request signed again with a fresh nonce may recover the existing record, but
the new nonce is consumed.

Servers MUST keep bounded replay and idempotency state keyed by authority,
service, session, operation, and request ID until the relevant expiry or
durable terminal record. Request retention MUST cover the signed-envelope
expiry. When full, the server MUST reject new admissions or safely evict only
records whose replay window has ended.

## Delegation

A child delegation MUST:

- identify its parent and be signed by the parent's subject
- bind the same session ID as its parent and the runtime-issued session grant
- increase depth by exactly one and never exceed depth four
- keep the same audience
- select only parent scopes
- use no later expiry, no earlier start, and no larger action or payment limit

Validation of one child structure is not chain validation. A consumer MUST
validate every parent, signature, issuer authority, revocation state, expiry,
and cumulative use before authorizing work.

Session grants and delegations authorize bounded protocol access. Neither is
a payment, proof of capacity, permission to bypass local safety policy, or
permission to expose raw sensors or actuators.

The reference implementation verifies a session grant under the current
manifest `authenticate` runtime key. The grant binds the exact profile ID and
version, negotiated extensions, manifest revision, client key identifier,
operations, lifetime, cumulative request count, and cumulative nano-TOS
limit. Client and delegated keys are re-resolved through a fresh authoritative
resolver with cancellation and masterchain high-water propagation.

Every delegation envelope is canonical, signed by its named issuer, checked
for issuer-to-subject continuity, root depth, parent ID, audience, required
scope, monotonic lifetime/action/payment attenuation, key and delegation
revocation, and maximum depth. Edge Core then consumes the session budget and
every delegation budget atomically with nonce/request admission. See
[session-authorization.md](session-authorization.md).
