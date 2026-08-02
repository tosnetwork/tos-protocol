# TOS Protocol

`tos-protocol` is the generic off-chain service foundation for TOS Network.
It owns protocol envelopes, ARD-compatible discovery, the chain integration
boundary, Edge Core, shared SDKs, and conformance tests. It does not contain
validator consensus code or AI runtime implementations.

Current delivery status and ordered follow-up work are maintained in
[`ROADMAP.md`](ROADMAP.md). Code completion is deliberately separated from the
real-chain, key-custody, physical-isolation, network, and load evidence required
for a production claim.

This repository is an early Go 1.24 foundation. It now includes the draft
TOS Service Protocol v0.1 contracts: deterministic signed values, operational
service manifests, exact profile negotiation, bounded sessions and
delegations, quote/payment/receipt binding, evidence levels, error semantics,
privacy-preserving terminal/resource declarations, Draft 2020-12 JSON
Schemas, and fixed conformance vectors.

The security boundary is intentional:

- `tos-edge` is the public control-plane process. The stock binary serves
  health and discovery documents only and can fail closed against an explicitly
  configured live TOS authority/client-key/payment runtime. The HTTP library
  has opt-in paid-action, authenticated action-status, and non-enumerating
  signed-receipt routes, but no route exists unless its complete dependency set
  is installed. Paid execution requires all authorizers, payment observer, exact profile
  plan and capability-drift readiness, private Worker, signer, retention bound,
  and concurrency bound are supplied together. The stock binary supplies no
  public-route dependencies.
- `tos-ard-registry` provides the mandatory ARD `POST /search` baseline and a
  minimal optional, unfiltered `GET /agents` browsing endpoint over a bounded
  in-memory index loaded either from operator-approved local catalogs or from
  a cached bounded federation generation. Federation requires explicit HTTPS
  roots and origins, validates every dial/redirect, bounds compressed and
  decoded bytes/depth/sources/TTL, and never performs network I/O from search.
  The draft
  List `filter` and `orderBy` extensions are not advertised by this bootstrap.
  Valid TOS Worker extensions contribute
  bounded model, operation, runtime, digest, and service-ID terms to lexical
  search and same-capability exact `x-tos.*` filters.
- `pkg/ard.BuildWorkerCatalog` converts a fresh validated private Worker
  capability snapshot into one deterministic, privacy-minimized public service
  entry. The operator-approved ARD identifier remains stable and bindable by
  the TOS descriptor; a bounded extension includes only externally callable
  selectors. Dynamic capacity and private hardware evidence are omitted.
- `pkg/ard.WriteCatalogFile` provides an atomic mode-0600 local handoff for
  explicitly configured `tos-edge` or Registry inputs and refuses symlink or
  non-regular targets. It performs no network publication.
- `pkg/ard.ReadCatalogFile` refuses symlink, non-regular, group/other-writable,
  or concurrently replaced inputs. Registry multi-catalog reload is one atomic
  bounded generation change, never a partially visible sequence.
- Known TOS Worker extensions are strictly validated at the catalog boundary;
  unknown third-party ARD extensions remain bounded and opaque.
- vertical workers use the versioned ConnectRPC API over a private Unix
  socket. The reference client verifies the private directory, socket type,
  mode and owner, bounds messages and deadlines, and does not retry work.
  Workers do not receive wallet owner keys.

## Build

```sh
make all
make test-race
```

The module declares Go 1.24. Older Go installations with `GOTOOLCHAIN=auto`
will download a compatible toolchain.

## Commands

```sh
go run ./cmd/tos-edge \
  -listen 127.0.0.1:8080 \
  -descriptor ./examples/tos-service.json \
  -catalog ./examples/ai-catalog.json \
  -request-journal /absolute/private/path/requests.db

go run ./cmd/tos-ard-registry \
  -listen 127.0.0.1:8090 \
  -catalog ./examples/ai-catalog.json

# Or use cached federation (mutually exclusive with -catalog):
go run ./cmd/tos-ard-registry \
  -listen 127.0.0.1:8090 \
  -federation-root https://registry.example/ai-catalog.json \
  -federation-origin https://registry.example \
  -federation-refresh 5m

go run ./cmd/tos-quote-signer \
  -socket /absolute/private/quote-signer.sock \
  -seed-file /absolute/private/quote.seed \
  -key-id manifest-quote-key
```

`tos-ard-registry` reads only regular local catalog files that are not
group/other writable. After an operator atomically replaces one or more
configured files, `SIGHUP` performs an all-or-nothing reload. Every catalog,
known extension, identifier ownership rule, publisher quota, and search-memory
bound is validated before the index generation changes. A failed reload keeps
the last valid generation and its pagination tokens unchanged.
The public `/search` and minimal `/agents` handlers admit at most 16 concurrent active
requests and reject excess work immediately with `503 RESOURCE_EXHAUSTED` and
`Retry-After`; `/healthz` remains allocation-light and outside that work gate.
Indexed entries are capped at 64 KiB each and 64 MiB in aggregate in addition
to the entry and per-publisher quotas, so legal but data-heavy catalogs cannot
turn the process into an unbounded in-memory document store.
Federation is opt-in and mutually exclusive with local catalog flags. Public
mode rejects loopback, private, link-local, multicast and unspecified dial
addresses even after DNS resolution, disables environment proxies, validates
every redirect against the exact origin list, and expires a stale generation
when refresh can no longer succeed. `-federation-allow-private` is an explicit
operator choice for a private federation and must not be enabled accidentally
on a public Registry.

After replacing the placeholder controller, RPC URLs, and reviewed contract
code hash, add `-tos-chain-config ./examples/tos-chain.json` to make startup
and `/readyz` fail closed against the live TOS quorum. This does not expose an
invocation route.

Remote crawling, federation, and payment forwarding are deliberately not
enabled in this bootstrap. Paid invocation is available only through the
fail-closed library composition described below; the stock command remains
discovery-only.

For TOS Worker entries, `POST /search` additionally accepts exact,
case-insensitive `x-tos.serviceId`, `x-tos.operation`, `x-tos.model`,
`x-tos.modelDigest`, and `x-tos.runtime` filters. Multiple values for one
field are OR alternatives; different TOS fields must match one capability
selector rather than unrelated capabilities in the same service entry.

## Base protocol

The draft normative index is [spec/base/README.md](spec/base/README.md).
Public documents remain JSON. Signatures and cross-language commitments use
RFC 8949 Core Deterministic CBOR over a bounded JSON data model that forbids
floats, tags, indefinite objects, duplicate keys, non-string map keys, and
noncanonical encodings.

Discovery is never transaction authority:

```text
ARD / .tos / known endpoint
        |
        v
descriptor -> controller-signed manifest -> profile negotiation
        -> bounded session -> live quote -> payment authorization
        -> vertical operation -> signed receipt and evidence
```

The quote binds the exact session, request-intent digest, service/profile and
resource revisions, network, payee, settlement target, limits, price, and
deadline. The generic server exposes `POST /tos/v1/actions` only when a strict
JSON authorizer and the complete live execution dependency set are installed.
The request carries base64 exact intent bytes plus signed session, quote,
delegation, and payment envelopes. Duplicate/unknown fields, oversized bodies,
content encoding, partial deployment configuration, and excess concurrency
fail closed. New work also requires current chain, signer, Worker, and exact
profile readiness before payment admission. A previously persisted request can
still perform strict `GetTask`-only recovery while new-work capacity is full;
it cannot call `Invoke` again. The route verifies current authority with a
concurrency-safe monotonic chain high-water mark, observes payment, atomically
executes or recovers the action, and returns only a bounded status or bounded
output plus the signed receipt. The stock
`tos-edge` command does not install this vertical composition. When both the
chain runtime and request journal are configured, the
bounded durable payment reconciliation scheduler is enabled automatically;
consecutive chain or entry failures exponentially back off its one shared
timer to a fixed operator limit, and a successful batch resets the base
interval.
An independently authenticated `GET /tos/v1/actions/{actionId}` may be
installed with the durable Core. It returns only the bounded state and, for a
terminal paid action, the original signed receipt. It never serializes intent,
output, payment metadata, Worker payload, or journal internals; malformed IDs,
denial, absence, and expiry share one non-enumerating response.
The manifest/runtime verifier, strict stateless chain-resolver boundary,
atomic signed-envelope nonce admission, bounded durable request journal, and
cleanup owner are implemented as internal libraries. The private Worker RPC
client also enforces Unix-socket ownership, message limits, response
correlation, byte accounting, deadlines, and an external-service priority
allowlist. Runtime-signed session grants, fresh client keys, complete bounded
delegation chains, and cumulative session/delegation budgets are verified and
atomically admitted without double-charging replay. Runtime-signed quotes and
client-signed payment authorizations can also be matched to a fresh, exact,
final-by-default chain observation through the bounded payment observer.
Quote issuance has a purpose-specific custody boundary and a bounded,
no-retry Unix-socket client/software sidecar: Edge derives every
manifest and session authority field, accepts only request, price,
destination, and bounded resource draft fields, delegates canonical bytes to
a `QuoteSigner`, rejects payload or validity substitution, immediately
verifies the result under the current manifest quote role, and exposes only a
defensive signed envelope during its verified lifetime.
Edge Core can apply that opaque observation exactly once: the payment record,
global replay index, and pending-to-authorized request transition commit in
one bounded journal transaction and survive restart. That transaction also
stores the minimal immutable quote, payment, and negotiated-profile context
needed to reconstruct only the already-paid execution after a process restart;
it does not preserve an expired quote as authority for new work. The journal
can also record a monotonic reorganization and block paid dispatch. Before
paid work may enter `running`, Edge Core now commits the globally unique Worker task ID,
a deterministic digest of the exact private invocation, its quote/payment
binding, and the `authorized -> running` transition in one transaction. An
exact recovery replay returns the immutable claim without another transition;
a changed request or cross-request task reuse fails closed. A production chain
recheck can run after quote expiry, and Edge Core provides a count-bounded
batch coordinator with a crash-safe CAS scan cursor. An optional adaptive
scheduler adds whole-batch deadlines, shutdown cancellation, serialized scan
ownership, health counters, and bounded exponential failure backoff; it is
disabled unless an observer and all bounds are explicitly configured. A current
manifest `receipt` key can also
produce an opaque verified receipt; its full signed envelope, intent/payment
binding, bounded usage, charge, and terminal request transition persist in
one exact-replay-safe transaction. The private Worker client now requires a
task ID and returns an opaque validated invocation result rather than a
caller-mutable protobuf. Edge Core correlates its task ID and invocation
digest, retained limits, deadline, byte accounting, and output digest to the
exact durable execution claim, delegates only canonical receipt bytes to
purpose-specific key custody, re-verifies the signature against the current
manifest, and commits one success receipt under concurrent retry.
An immutable exact-profile deployment plan may additionally select a
declarative 0..10,000 basis-point fraction of the quoted price for successful
receipts. The absent policy preserves full charge. Edge uses overflow-safe
integer round-down semantics in live and recovered completion, never accepts a
Worker-supplied charge, requires the plan on every successful completion, and
commits non-default policy into the durable task ID so pre-receipt recovery and
receipt replay both reject drift.
Failed, canceled, and timed-out paid requests use the same signer and atomic
path with an empty usage array, no result or diagnostic payload, deterministic
bounded error code, and zero charge; timeout cannot be declared before the
signed quote deadline. Both pre-dispatch cancellation and post-dispatch
failure converge under concurrent retry.
The generic profile intent-to-Worker boundary is implemented internally. It
binds exact intent bytes to the negotiated profile version, extension set and
signed quote, lets a vertical mapper return only its model and payload,
derives all security fields in Edge, validates the complete request against
the concrete Worker client before changing durable state, and
deterministically replays the same task after restart. A startup-only,
immutable registry holds at most 128 mappers by exact profile ID, version,
extension set, and operation; it has no wildcard fallback or request-driven
growth. Production composition wraps it in an immutable deployment plan whose
constructor requires a bounded exact selector allowlist. Only mappers that are
both installed and declared can enter any paid claim, recovery, or dispatch
path. No production vertical mapper is included in this repository.
The first externally maintained mapper candidate is
`tos.ai.text-generation` v0.1.0 in `tosnetwork/tos-ai`; the local registry can
verify its exact version, extension set, and operation before a deployment
advertises it, but this base module never auto-loads vertical code.
Deployment composition constructs the mapper registry and validates its
bounded set of unique required selectors in one operation; any invalid,
duplicate, or missing exact mapper aborts startup without version or extension
fallback. Installing unused mapper code does not silently enable it.
The internal dispatch coordinator now performs the only safe next action:
one newly committed claim may call `Invoke` once, while every exact replay
uses read-only `GetTask`, including after the execution deadline while bounded
retention remains live. RPC failure returns an explicit `uncertain` result
that still exposes a defensive copy of the durable claim; even `NOT_FOUND`
never authorizes automatic resubmission.
`ExecuteRegisteredPaidAction` and `RecoverRegisteredPaidAction` compose this
rule with terminal resolution so callers cannot accidentally discard the
claim-preserving error path or retry `Invoke`. Terminal retries reconstruct
the exact mapper output, task ID, request digest, deadline, and retention from
durable state, use only `GetTask`, and compare recovered output, usage,
completion time, charge, and receipt identity to the existing signed receipt.
Successful and failed terminal retries reuse the original receipt without
another signature. Direct and recovered completion timestamps use the exact
Worker-owned `completed_unix_millis` carried by both `Invoke` and retained
`GetTask`, preventing RPC latency from creating false replay conflicts.
Its resolution boundary creates no receipt for `uncertain`, `NOT_FOUND`,
`ACCEPTED`, or `RUNNING`. Only a validated direct/recovered success or a
validated recovered `FAILED`, `CANCELED`, or `TIMED_OUT` outcome enters the
existing atomic receipt path. The receipt ID is derived deterministically from
the durable execution identity, so concurrent or restarted resolution reaches
one exact-replay-safe terminal record instead of inventing new IDs.
After restart, Edge can recover the exact persisted payment context, recompute
and compare the supplied intent, query an already-running Worker task without
invoking it again, and issue or replay the terminal receipt under the current
manifest key. Missing legacy recovery context, changed intent, corrupt binding,
or a reorganized nonterminal payment fails closed before Worker access.
Explicit cancellation is also claim-bound: Edge rechecks that the exact
execution still owns the durable `running` request before sending the
request/task/digest tuple to the Worker. Accepted, rejected, and ambiguous
cancellation attempts preserve the claim and never create a terminal receipt;
only a later validated `GetTask` terminal observation can do that.
The concrete quorum TOS authority/client-key/native-payment adapters are
implemented, exercised against a three-node chain, and available to `tos-edge`
through strict operator startup configuration and `/readyz`. Bounded,
no-retry purpose-signer clients and independent software-key
`tos-quote-signer` and `tos-receipt-signer` processes implement separate
private Unix-socket custody boundaries. Both sides enforce ownership,
permissions, message size, fixed
concurrency, and exact payload/time preservation before current-manifest
verification accepts a signature. Edge startup pins the expected signer key ID
and Ed25519 public key and rejects a different sidecar identity before opening
its listener and on every later signing response. This operator binding does
not replace manifest role and revocation verification. HSM integration,
automatic key rotation, refund reconciliation, and usage-dependent or partial
failure charging remain deployment or later-policy work. Receipt-signer flags
alone add the signer to `/readyz` but do not enable public routes; the complete
vertical action composition is still required. Graceful sidecar shutdown stops
new signing, synchronizes with active signatures, and clears the software
private-key buffer before exit; this is best-effort process-memory hygiene, not
HSM-grade erasure.
Edge synchronously cancels and closes its bounded signer client during shutdown,
so the private Unix transport does not remain an implicit process-lifetime
resource.
The private RPC now
defines a binding-preserving task-status/result lookup, and its client can
feed a recovered successful result through the existing receipt path. A
reusable bbolt Worker task store now provides atomic claim/replay, exact
`GetTask`, bounded terminal persistence, capacity backpressure, expiry cleanup,
startup corruption auditing, bounded payload-free active-task pagination,
atomically enforced owner-local slot and retained-byte reserves, and O(1)
priority-aware capacity snapshots. Retained-byte admission reserves terminal
result space at claim time, so later completion cannot lose a storage race;
physical bbolt allocation remains protected by an operator filesystem quota.
A production Worker must still choose an explicit reconciliation policy:
`tos-ai` fails interrupted synchronous work closed before opening its listener,
while a future durable runtime may recover only through an idempotent job or
sandbox supervisor bound to the exact task ID. Neither the Edge claim nor the
task table alone proves that an external executor accepted or completed an RPC
interrupted by a crash. None of these internal boundaries enable a public
action unless the complete opt-in HTTP dependency set is installed; partial
configuration prevents server construction.

The chain mapping, quorum rules, canonical references, startup composition,
and local rehearsal are documented in
[`docs/tos-chain-adapters.md`](docs/tos-chain-adapters.md).
Worker-side persistence and `tos-ai` integration are documented in
[`docs/worker-task-store.md`](docs/worker-task-store.md).
The no-retry private key-custody transport and sidecar requirements are
documented in
[`docs/receipt-signer-sidecar.md`](docs/receipt-signer-sidecar.md).
The remaining environment-owned certification work is separated from the
implemented code and maintained as the canonical status ledger in
[`docs/non-streaming-v0.1-production-gates.md`](docs/non-streaming-v0.1-production-gates.md).

## Repository map

```text
api/                  versioned worker RPC contract
cmd/tos-edge/         public Edge Core entry point
cmd/tos-ard-registry/ ARD HTTP Registry entry point
cmd/tos-quote-signer/ independent purpose-specific quote key process
cmd/tos-receipt-signer/ independent purpose-specific receipt key process
pkg/ard/              pinned ARD model, Worker catalog projection and validation
pkg/chain/            bounded JSON-RPC adapter
pkg/toschain/         quorum TOS authority, client-key and payment composition
pkg/edge/             safe public discovery server
pkg/authorization/    controller manifest and runtime-envelope authorization
pkg/identity/         domain-separated Ed25519 envelopes
pkg/codec/            deterministic bounded CBOR and commitment hashing
pkg/journal/          durable bounded request, payment, execution and receipt state
pkg/localrpc/         validated private Worker RPC client and durable bounded task store
pkg/payment/          strict signed quote/payment chain observation
pkg/protocol/         v0.1 manifests, profiles, sessions, quotes and receipts
pkg/registry/         bounded ARD index and HTTP API
spec/base/            normative draft schemas, rules, and test vectors
spec/profile-registry profile registration requirements
tests/conformance/    schema and cross-language vector checks
```

## Upstream foundations

- ARD v0.9 Draft is the pinned public discovery contract.
- AGNTCY Directory is the preferred distributed indexing/storage foundation
  for a later production Registry backend.
- ConnectRPC is the local process API.
- OPA, SPIFFE, ORAS, Cosign, and TUF are planned adapters; they are not pulled
  into the bootstrap binaries before their authority and update policies are
  specified.

Licensed under the [GNU General Public License v3.0](LICENSE).
