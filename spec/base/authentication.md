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

## Replay

Every signed envelope has an unpredictable 128-bit nonce and a maximum
24-hour validity. Nonces are necessary but not sufficient. Servers MUST keep
bounded replay and idempotency state keyed by authority, service, session,
operation, and request ID until the relevant expiry or durable terminal
record. When full, the server MUST reject new admissions or safely evict only
records whose replay window has ended.

## Delegation

A child delegation MUST:

- identify its parent and be signed by the parent's subject
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
