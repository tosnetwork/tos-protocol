# TOS Service Protocol v0.1

Status: Draft. This document and the adjacent schemas are not a production
security claim.

## Scope

The base protocol lets a client discover a service, authenticate its current
runtime authority, negotiate one vertical profile, obtain a live quote,
authorize payment, and verify a receipt and supporting evidence. It does not
define AI inference, physical actuation, storage, or commerce semantics. Those
belong to independently versioned profiles.

ARD and the public TOS descriptor are discovery inputs. They do not authorize
an action, reserve capacity, establish price, select a payment destination, or
prove a capability. Before a transaction, a client MUST resolve the controller
authority, verify a fresh signed service manifest, negotiate the profile, and
obtain a live signed quote.

## Documents

| Value | Purpose | Authority |
|---|---|---|
| ARD catalog entry | Protocol-neutral public discovery | Publisher FQDN and Registry provenance |
| `/.well-known/tos-service.json` | Stable TOS handoff and profile references | Controller-bound discovery |
| Service manifest | Runtime keys, endpoints, profiles, revisions, claims | Controller signature |
| Terminal manifest | Short-lived readiness, owner reservation, resource and evidence snapshot | Runtime key with `evidence` role |
| Session grant | Bounded runtime access | Runtime key with `authenticate` role |
| Quote | Admission, revisions, limits, price, expiry | Runtime key with `quote` role |
| Payment authorization | Payer's maximum authorized payment | Payer or approved policy service |
| Receipt | Terminal outcome and bounded metering | Runtime key with `receipt` role |
| Evidence bundle | Typed claims and evidence references | Runtime key or approved issuer |

JSON documents MUST validate against the matching Draft 2020-12 schema. An
implementation MUST additionally run semantic validation: JSON Schema cannot
prove signature authority, freshness relationships, delegation attenuation,
quote/payment/receipt correlation, or revocation state.

## Base flow

1. `RESOLVE`: obtain ARD results, a `.tos` record, an ADNL address, or a known
   HTTPS descriptor.
2. `DESCRIBE`: fetch the descriptor and a fresh service manifest; verify
   identity, signature, expiry, endpoint, and revision bindings.
3. `OPEN`: negotiate one exact profile version and supported critical
   extensions, then request a bounded session grant.
4. `QUOTE`: send an idempotent request intent and receive current admission,
   price, byte limits, resource revision, deadline, and expiry.
5. `AUTHORIZE`: bind a payer-approved maximum to the exact quote and request.
6. Execute a profile operation. Profiles define their own state machines; the
   base protocol does not assume every operation streams.
7. `RECEIPT`: verify correlation IDs, revisions, result commitment, metering,
   charge, signer role, and terminal status.
8. `VERIFY`, `SETTLE`, and `CLOSE` as required by the selected payment and
   profile policies.

Every create operation MUST carry a globally unpredictable correlation or
idempotency identifier. A service MUST persist enough bounded state to return
the same terminal disposition for a replay; it MUST NOT execute the same
authorized action twice.

## Limits

The Go reference implementation enforces:

- 1 MiB maximum canonical signed value and 2 MiB JSON conversion input
- 16 levels of nesting
- 4,096 entries in one map or array and 16,384 total decoded items
- 24-hour maximum manifest, signed-envelope, session, delegation, and quote
  lifetime
- 10-minute maximum terminal resource snapshot lifetime
- 32 profile versions, profile extensions, operations, usage units, or
  evidence claims where applicable
- 64 quote resource limits and readiness components; 128 terminal resource
  claims
- delegation depth no greater than four

Profiles MUST publish smaller workload-specific input, output, context,
stream, queue, artifact, and duration limits. A wire limit is not permission
to allocate that amount before admission.

## Evidence

The common levels are `declared`, `observed`, `benchmarked`, `audited`,
`attested`, `replicated`, and `cryptographically-proven`. The level is a
classification, not proof by itself. Clients MUST display and evaluate issuer,
subject, scope, digest, collection time, expiry, revocation, and the selected
profile's verifier semantics.

## Normative language

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are to be
interpreted as described by RFC 2119 and RFC 8174 when written in capitals.
