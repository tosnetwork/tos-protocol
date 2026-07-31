# TOS Protocol

`tos-protocol` is the generic off-chain service foundation for TOS Network.
It owns protocol envelopes, ARD-compatible discovery, the chain integration
boundary, Edge Core, shared SDKs, and conformance tests. It does not contain
validator consensus code or AI runtime implementations.

This repository is an early Go 1.24 foundation. It now includes the draft
TOS Service Protocol v0.1 contracts: deterministic signed values, operational
service manifests, exact profile negotiation, bounded sessions and
delegations, quote/payment/receipt binding, evidence levels, error semantics,
privacy-preserving terminal/resource declarations, Draft 2020-12 JSON
Schemas, and fixed conformance vectors.

The security boundary is intentional:

- `tos-edge` is the public control-plane process. The initial binary serves
  health and discovery documents only. It can fail closed against an explicitly
  configured live TOS authority/client-key/payment runtime, but public paid
  invocation stays disabled until reviewed profile mappers, isolated
  execution, production signing, and receipt delivery are wired end to end.
- `tos-ard-registry` provides the mandatory ARD `POST /search` and
  `GET /agents` baseline over a bounded in-memory index loaded from
  operator-approved local catalogs.
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
```

After replacing the placeholder controller, RPC URLs, and reviewed contract
code hash, add `-tos-chain-config ./examples/tos-chain.json` to make startup
and `/readyz` fail closed against the live TOS quorum. This does not expose an
invocation route.

Remote crawling, federation, payment forwarding, and invocation are
deliberately not enabled in this bootstrap. They require the SSRF, provenance,
authentication, replay, and bounded-state controls described in the
architecture plan.

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
deadline. `tos-edge` still exposes discovery only until manifest-backed
authorization uses the configured live TOS runtime in a public request path,
with production profile mappers, execution isolation, signing, and public
delivery. When both the chain runtime and request journal are configured, the
bounded durable payment reconciliation scheduler is enabled automatically;
consecutive chain or entry failures exponentially back off its one shared
timer to a fixed operator limit, and a successful batch resets the base
interval.
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
immutable registry selects at most 128 mappers by exact profile ID, version,
extension set, and operation; it has no wildcard fallback or request-driven
growth. No production vertical mapper is included in this repository.
The internal dispatch coordinator now performs the only safe next action:
one newly committed claim may call `Invoke` once, while every exact replay
uses read-only `GetTask`, including after the execution deadline while bounded
retention remains live. RPC failure returns an explicit `uncertain` result
that still exposes a defensive copy of the durable claim; even `NOT_FOUND`
never authorizes automatic resubmission.
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
The concrete quorum TOS authority/client-key/native-payment adapters are now
implemented, exercised against a three-node chain, and available to `tos-edge`
through strict operator startup configuration and `/readyz`. Failed/canceled
refund and charging policy, the production signer adapter, isolated executor,
and public receipt route remain intentionally disconnected.
The private RPC now
defines a binding-preserving task-status/result lookup, and its client can
feed a recovered successful result through the existing receipt path. A
reusable bbolt Worker task store now provides atomic claim/replay, exact
`GetTask`, bounded terminal persistence, capacity backpressure, expiry cleanup,
and startup corruption auditing. A production Worker must still reconcile its
durable `ACCEPTED/RUNNING` records with an idempotent runtime job or sandbox
supervisor: neither the Edge claim nor the task table alone proves that an
external executor accepted or completed an RPC interrupted by a crash. None
of these internal boundaries enable public actions by themselves.

The chain mapping, quorum rules, canonical references, startup composition,
and local rehearsal are documented in
[`docs/tos-chain-adapters.md`](docs/tos-chain-adapters.md).
Worker-side persistence and `tos-ai` integration are documented in
[`docs/worker-task-store.md`](docs/worker-task-store.md).

## Repository map

```text
api/                  versioned worker RPC contract
cmd/tos-edge/         public Edge Core entry point
cmd/tos-ard-registry/ ARD HTTP Registry entry point
pkg/ard/              pinned ARD v0.9 data model and validation
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

No license has been selected for this new repository yet. Add one before the
first public release.
