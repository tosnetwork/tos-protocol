# Bootstrap architecture

This repository implements the bounded non-streaming v0.1 control and action
boundaries while keeping optional vertical composition explicit.

```text
Internet
   |
   | HTTPS / TOS Sites (discovery; paid action only when fully composed)
   v
tos-edge ------------------> TOS chain adapter
   |
   | validated private ConnectRPC, owned Unix socket 0600
   v
vertical worker (for example tos-ai-worker)
   |
   +--> durable bounded task store
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
application, and bounded expiry cleanup. Payment application atomically retains
the minimum verified quote/payment/profile context required to reconstruct the
same execution after restart and quote expiry. Recovery revalidates every
binding, never stores the intent or Worker payload, uses `GetTask` for a
running or terminal claim, and can only replay an already-committed terminal
receipt after the retained Worker result matches it exactly.
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
request-driven state. A constructor-validated deployment plan narrows that
registry to the exact declared selector allowlist required by every paid
claim, recovery, and dispatch path; installed but undeclared mappers remain
unreachable.
The dispatch coordinator invokes only a newly committed
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
polling. The public process must supply an explicitly installed reviewed
profile mapper, isolated Worker, production receipt key custody, chain-backed
paid-action authorizer, payment observer, retention policy, and bounded
concurrency before the opt-in action route exists. Partial composition fails
server construction.
The action-level composition now couples dispatch and resolution so an
ambiguous private RPC cannot lose its durable claim. A client retry after a
terminal response was lost reconstructs the exact Worker lookup from durable
state, performs no `Invoke`, and returns output only when its usage, digest,
completion time, charge, and receipt identity all match the stored signed
receipt. Direct and recovered completion times use the same millisecond wire
precision. The authorization layer can also derive and issue quotes without
letting an ingress handler supply manifest/session authority fields; canonical
quote signing is immediately re-verified under the current role key.
Edge Core now supports an immutable exact-profile successful-charge fraction
with full-charge compatibility, deterministic recovered evaluation, and
fail-closed replay. Every successful completion/resolution requires the plan,
and non-default policy is committed into the durable task ID so recovery drift
fails before Worker lookup; failed, canceled, and timed-out work remains
zero-charge.
Usage-dependent or failed partial-work charging remains outside v0.1. A
production Worker must additionally
wire the reusable bounded task table to an idempotent runtime job or durable
sandbox supervisor. The table provides atomic claim/replay, exact lookup,
terminal persistence, capacity backpressure, and cleanup, but cannot infer
whether an external executor ran before a process crash.
The generic public server contains the bounded opt-in action route, strict
exact-byte JSON credential adapter, and independently authenticated
non-enumerating durable action-status/receipt reads. Status reads expose no
intent, output, payment metadata, Worker payload, or journal internals. The
stock `tos-edge` command installs no
vertical plan or public-action dependencies and therefore remains
discovery-only.

## Dependency decisions

| Concern | Baseline | Bootstrap status |
|---|---|---|
| Language | Go 1.26.5+ | implemented |
| Local process API | ConnectRPC + Protobuf over private Unix socket | invocation, `GetTask` recovery and exact-claim cancellation contracts plus opaque validated-result clients implemented: owner/mode, message/deadline, request-digest, task/result/retention binding, priority and no-retry controls; reusable bbolt Worker task table provides bounded atomic claim/replay, owner-local slot reserve, priority-aware capacity, terminal persistence, lookup, cleanup, startup audit and payload-free active-task pagination; synchronous workers can fail interrupted tasks closed, while durable executor/supervisor recovery remains |
| Public discovery | ARD v0.9 Draft | mandatory bounded `POST /search`, deterministic optional `GET /agents` with pinned List filter/order grammar and view-bound pagination, stable bounded Go client, deterministic privacy-minimized projection, strict known-extension validation, bounded exact-filter indexing, atomic local reload, opt-in cached federation with HTTPS-origin/IP/redirect/body/depth/source/TTL controls, and an opt-in pinned-upstream conformance gate implemented |
| Base service protocol | TOS v0.1 Draft | schemas, Go types, terminal/resource declarations, canonical encoding and conformance vectors implemented |
| Manifest authorization | fresh authority snapshot + Ed25519/CBOR verifier | controller/current-digest/runtime-role/revocation, opaque admission result, strict chain-resolver boundary, Agent Account decoder, majority JSON-RPC composition and startup authority preflight implemented; public signed-manifest request wiring remains |
| Session/delegation authorization | runtime session grant + fresh client-key resolver + bounded signed chain | exact profile/runtime binding, key/delegation revocation, high-water checks, semantic charge binding, atomic cumulative budget admission and current Agent Account controller source implemented |
| Quote/payment observation | runtime quote role + client/delegation authorization + exact chain echo | manifest/session-derived quote issuance through a purpose-fixed, identity-pinned, bounded no-retry Unix signer client/software sidecar, defensive signed-envelope delivery, exact native transaction BOC/source/destination/value/hash verification, majority finality/high-water, atomic bounded recovery context, post-expiry recheck, bounded batch coordinator and adaptive scheduler implemented; public quote-route composition, HSM deployment and refund reconciliation remain |
| Receipt authorization | current manifest `receipt` role + original opaque payment | signature/canonical payload and payment binding implemented; successful validated Worker results support a bounded immutable exact-profile quoted-price fraction (default full charge), deterministic live/recovered evaluation and fail-closed replay, while failed/canceled/timed-out outcomes remain zero-charge; all terminal outcomes use a purpose-specific signer, deterministic execution-bound receipt identity, immediate manifest re-verification and concurrency-safe application; bounded no-retry private Unix signer client, software-key sidecar, exact expected-key startup/per-response cryptographic binding, side-effect-free Edge readiness wiring, and the fully dependency-gated public action result are implemented, while stock-binary composition, HSM deployment, automated rotation, refund reconciliation and usage-dependent charging remain |
| Profile invocation mapping | profile/version/extension-bound intent commitment + Edge-derived Worker security fields | generic deterministic mapper boundary, immutable bounded exact-selector registry, constructor-validated deployment plan required by every paid claim/recovery/dispatch path, pre-claim Worker-policy validation, restart and terminal-output replay with mapping-drift rejection implemented; `tos-ai` owns the first reviewed text-generation mapper and can construct the exact plan either in-process or from a fresh fully validated private Worker capability snapshot; the public route exists only in a fully composed vertical deployment |
| Durable request state | bbolt-backed local journal | atomic nonce/request/budget admission, exact-once payment plus bounded execution-authorization persistence, reorganization dispatch gate, exact paid execution claim, quote-expiry-safe Worker recovery, full signed-receipt terminal application/replay, persistent CAS payment-scan cursor, bounded replay state, restart recovery and cleanup implemented as an Edge Core library |
| Distributed Registry backend | AGNTCY Directory | adapter planned; no fork |
| Chain access | TOS JSON-RPC/lite APIs | bounded TOS success/error envelopes plus strict-majority authority, key and native-payment adapters, startup preflight and freshness-bounded readiness implemented and three-node tested |
| Policy | OPA | bounded fixed-endpoint HTTPS/loopback adapter plus exact disconnected static evaluator implemented; operator policy vocabulary and deployment remain external |
| Workload identity | SPIFFE | exact URI-SAN verifier under a cloned operator X.509 root pool implemented; ARD/DNS identity is never accepted |
| Artifacts | signed provenance plus exact SHA-256 | bounded canonical Ed25519 provenance/evidence verifiers and complete-artifact hashing implemented; repository/transport and production trust ceremony remain external |

The Registry accepts either local operator-approved catalogs or one opt-in
cached federation generation; the two sources cannot be mixed implicitly.
An operator can derive such a catalog from a fresh validated Worker snapshot.
The projection creates one service entry with the operator-approved stable ARD
identifier that its TOS descriptor must bind. A bounded TOS extension carries
the sorted external capability selectors and model/runtime revisions, while
live capacity, evidence references, attributes, local paths, and hardware
identifiers are omitted. Generation is not publication authority and does not
open a listener. The optional local file handoff is atomic, mode 0600, and
rejects symlink or non-regular targets before an operator explicitly loads it
into `tos-edge` or the Registry.
When the Registry loads a valid TOS Worker extension, it builds a separate
lowercase search/filter projection capped at 16 KiB per entry. Model,
operation, runtime, digest, and Worker service ID become discoverable without
indexing live capacity or hardware evidence. Exact `x-tos.*` filters are
case-insensitive, and filters on different Worker fields must match the same
capability selector. The extension is parsed only at catalog admission, not
repeatedly for every query; filter terms are compiled once per request and
the per-entry projection is scanned without splitting or copying it.
Configured Registry catalogs can be replaced only through the local filesystem
and an explicit `SIGHUP`. The reader rejects symlinks, non-regular files,
group/other-writable inputs, and a file identity that changes during reading.
All configured catalogs are decoded and projected before one locked index
replacement. A malformed file, cross-source identifier collision, publisher
quota, entry limit, or projection limit rejects the complete reload and leaves
the previous generation intact. There is one fixed signal goroutine, no file
watcher, polling loop, historical generation cache, or remote mutation API.
Search and deterministic List execution share a fixed 16-request non-queuing
admission gate. List implements only fields actually represented by the pinned
ARD catalog schema: exact case-insensitive `displayName`, `type`, and
`publisherId`, plus RFC3339 `updatedAfter`; `createdAfter` is rejected because
the same pinned schema has no `createdAt` value. Sorting supports identifier,
displayName, and updatedAt with a stable identifier tie-breaker. Pagination
tokens bind the index generation, normalized filter, and normalized order, so
they cannot be replayed across views.
Every indexed entry is capped at 64 KiB and the complete index at 64 MiB,
including the precomputed Worker search projection. These byte quotas compose
with entry and per-publisher quotas and are checked before an atomic generation
replacement. Over-capacity requests receive a retryable 503 before catalog candidate/result
allocation; health checks do not consume a slot. This bounds concurrent index
work inside the process, while deployment-level connection and traffic limits
remain the responsibility of the front proxy or service manager.
Remote crawling is withheld until DNS rebinding, redirect, IP range,
decompression, recursion, federation, retry, and per-publisher limits are all
enforced.

The stable client surface includes both Go and a dependency-free
Node.js/TypeScript implementation. Both pin one Registry origin, reject
redirects, require the exact JSON response media type, bound decoded response
bytes before parsing, reject duplicate JSON keys and validate returned entry
identity fields. The independent client runs in CI and does not infer an
authority, payment destination or runtime endpoint from search output.

`pkg/trustpolicy` supplies explicit deployment trust adapters rather than
another discovery layer. Workload certificates require one exact SPIFFE URI
SAN under an operator-owned X.509 root. Artifact provenance binds an allowed
subject, builder and source/material digests to the complete artifact hash.
Evidence bundles are accepted only from configured keys, issuer identities,
claim types and maximum assertion levels. OPA decisions use a fixed endpoint,
bounded non-queuing concurrency, strict JSON and a maximum 24-hour lifetime;
disconnected rules compare complete scalar tuples and fail closed on unknown
inputs. None of these adapters consults ARD metadata.

Canonical `.tos` syntax is now independently reusable through
`NormalizeTOSName`: lowercase DNS labels, no empty/overlong/edge-hyphen labels,
and an exact `.tos` suffix. This intentionally does not specify a registrar
message, fee, ownership transition or contract address. Those values require
the actual frozen chain ABI and governance decision and cannot be completed by
a MOCK without misrepresenting on-chain compatibility.
