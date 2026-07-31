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
  health and discovery documents only; public paid invocation stays disabled
  until live TOS authority/client-key resolution, the production TOS payment
  adapter/watcher policy, and isolated execution are wired end to end.
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
authorization is connected to the live TOS contract/RPC decoder and durable
payment watching, execution isolation, and receipt persistence are
implemented.
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
one bounded journal transaction and survive restart. The journal can also
record a monotonic reorganization and block paid dispatch. A production chain
recheck can run after quote expiry, and Edge Core provides a count-bounded
batch coordinator with a crash-safe CAS scan cursor. The concrete TOS payment
contract adapter, automatic watcher scheduling, refund/completion policy, and
isolated executor remain intentionally disconnected, so none of these
internal boundaries enable public actions by themselves.

## Repository map

```text
api/                  versioned worker RPC contract
cmd/tos-edge/         public Edge Core entry point
cmd/tos-ard-registry/ ARD HTTP Registry entry point
pkg/ard/              pinned ARD v0.9 data model and validation
pkg/chain/            bounded JSON-RPC adapter
pkg/edge/             safe public discovery server
pkg/authorization/    controller manifest and runtime-envelope authorization
pkg/identity/         domain-separated Ed25519 envelopes
pkg/codec/            deterministic bounded CBOR and commitment hashing
pkg/journal/          durable bounded replay, payment and idempotency state
pkg/localrpc/         validated private Unix-socket Worker RPC client
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
