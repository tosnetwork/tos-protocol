# Bootstrap architecture

This bootstrap turns the repository boundary in the TOS design documents into
code without claiming that the full protocol is implemented.

```text
Internet
   |
   | HTTPS / TOS Sites (discovery only in bootstrap)
   v
tos-edge ------------------> TOS chain adapter
   |
   | validated private ConnectRPC, owned Unix socket 0600
   v
vertical worker (for example tos-ai-worker)
   |
   +--> bounded scheduler
   +--> approved runtime adapter
   +--> isolated executor (next milestone)
```

The base value contracts, canonical encoding, signatures, schemas, conformance
vectors, and a durable bounded request journal now exist. Edge Core owns
transactional replay/idempotency records, compare-and-swap request
transitions, authenticated-envelope nonce admission, restart recovery data,
capacity backpressure, exact-once payment application, payment reorganization
gating, atomic paid execution claims, atomic signed-receipt terminal
application, and bounded expiry cleanup.
The authorization library
verifies fresh controller authority, the current signed manifest, runtime
roles and revocation, canonical semantic payloads, and admission bindings.
Its stateless chain-resolver boundary enforces finality, code-hash allowlists,
timeouts, reference matching, and caller high-water sequence checks. The
session layer verifies the authenticate-role runtime signature, exact
manifest/profile revision, fresh client keys, bounded root-to-leaf delegation
chains, revocation, request semantics, and cumulative limits. Edge Core
claims the request nonce and every session/delegation action and nano-TOS
budget in one bbolt transaction, so concurrent requests and replay cannot
overspend. The private Worker client enforces socket-directory and socket
ownership/mode, Connect message limits, request deadlines, response
correlation and byte accounting, no implicit retries, and a default
external-service-only priority policy. Before dispatch, Edge atomically binds
one globally unique task ID and deterministic private-request digest to the
paid request's `authorized -> running` transition. Successful invocation
responses cross into Edge Core only as opaque validated results. Edge repeats
the exact paid execution claim, scope, quote limits, and deadline, hashes the
output, delegates canonical receipt bytes to an external signer, verifies the
returned envelope against the current manifest, and applies it atomically. The
generic mapping boundary now recomputes the profile/version/extension-bound
public intent commitment, gives a mapper only a defensive intent copy, derives
all Worker security fields itself, and validates the resulting request under
the concrete Worker client policy before the atomic claim. Exact
reconstruction replays across restart and any mapper drift conflicts. Mapper
selection uses an immutable startup registry bounded to 128 exact
profile/version/extension/operation selectors, with no wildcard fallback or
request-driven state. The dispatch coordinator invokes only a newly committed
claim. A replay performs only a binding-preserving task lookup, and an RPC
failure produces an `uncertain` outcome that retains the claim for recovery
rather than retrying. `NOT_FOUND` is an observation, not permission to
resubmit. The quorum TOS contract/RPC decoder, Agent Account authority and
client-key resolver, and native-payment adapter are implemented as a startup
runtime bundle. `tos-edge` accepts strict operator configuration, preflights
the configured service authority, and separates `/healthz` liveness from
quorum-backed `/readyz`. When a durable journal is also configured, the
bounded payment reconciliation schedule starts automatically. It uses one
exponentially backed-off timer so a chain outage cannot sustain base-rate
polling. The public process must still supply a reconciliation/refund policy,
reviewed production profile mappers, invocation isolation, production
receipt key custody, partial-work refund/charging policy, and public receipt
delivery before it forwards paid work. A production Worker must additionally
implement the specified bounded task table and idempotent `Invoke` behavior so
Edge can resolve the remaining crash window after a claim commits but before
an RPC result is received.
Those runtime operations remain absent from the public server, so it exposes
no invocation route.

## Dependency decisions

| Concern | Baseline | Bootstrap status |
|---|---|---|
| Language | Go 1.24+ | implemented |
| Local process API | ConnectRPC + Protobuf over private Unix socket | invocation, `GetTask` recovery and exact-claim cancellation contracts plus opaque validated-result clients implemented: owner/mode, message/deadline, request-digest, task/result/retention binding, priority and no-retry controls; new claims invoke once, replay only queries, cancellation acceptance is nonterminal, uncertain/active/missing outcomes create no receipt, and validated terminal outcomes enter one deterministic atomic receipt path; durable idempotent Worker implementation remains |
| Public discovery | ARD v0.9 Draft | structural model and bounded Registry implemented |
| Base service protocol | TOS v0.1 Draft | schemas, Go types, terminal/resource declarations, canonical encoding and conformance vectors implemented |
| Manifest authorization | fresh authority snapshot + Ed25519/CBOR verifier | controller/current-digest/runtime-role/revocation, opaque admission result, strict chain-resolver boundary, Agent Account decoder, majority JSON-RPC composition and startup authority preflight implemented; public signed-manifest request wiring remains |
| Session/delegation authorization | runtime session grant + fresh client-key resolver + bounded signed chain | exact profile/runtime binding, key/delegation revocation, high-water checks, semantic charge binding, atomic cumulative budget admission and current Agent Account controller source implemented |
| Quote/payment observation | runtime quote role + client/delegation authorization + exact chain echo | exact native transaction BOC/source/destination/value/hash verification, majority finality/high-water, post-expiry recheck, bounded batch coordinator, adaptive scheduler and binary runtime composition implemented; refund reconciliation remains |
| Receipt authorization | current manifest `receipt` role + original opaque payment | signature/canonical payload and payment binding implemented; successful validated Worker results and zero-charge failed/canceled/timed-out outcomes use a purpose-specific signer, deterministic execution-bound receipt identity, immediate manifest re-verification and concurrency-safe application; production signer, profile refund/charging policy and public delivery remain |
| Profile invocation mapping | profile/version/extension-bound intent commitment + Edge-derived Worker security fields | generic deterministic mapper boundary, immutable bounded exact-selector registry, pre-claim Worker-policy validation, restart replay and mapping-drift rejection implemented; reviewed vertical mapper implementations and startup configuration remain |
| Durable request state | bbolt-backed local journal | atomic nonce/request/budget admission, exact-once payment application, reorganization dispatch gate, exact paid execution claim, full signed-receipt terminal application, persistent CAS payment-scan cursor, bounded replay state, restart recovery and cleanup implemented as an Edge Core library |
| Distributed Registry backend | AGNTCY Directory | adapter planned; no fork |
| Chain access | TOS JSON-RPC/lite APIs | bounded TOS success/error envelopes plus strict-majority authority, key and native-payment adapters, startup preflight and freshness-bounded readiness implemented and three-node tested |
| Policy | OPA | adapter planned after policy vocabulary is normative |
| Workload identity | SPIFFE | adapter planned |
| Artifacts | ORAS + Cosign + TUF | interfaces planned; AI repository starts manifest verification |

The Registry accepts only local operator-approved catalogs in this milestone.
Remote crawling is withheld until DNS rebinding, redirect, IP range,
decompression, recursion, federation, retry, and per-publisher limits are all
enforced.
