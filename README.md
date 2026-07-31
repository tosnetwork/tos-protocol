# TOS Protocol

`tos-protocol` is the generic off-chain service foundation for TOS Network.
It owns protocol envelopes, ARD-compatible discovery, the chain integration
boundary, Edge Core, shared SDKs, and conformance tests. It does not contain
validator consensus code or AI runtime implementations.

This repository is an early Go 1.24 foundation. The security boundary is
intentional:

- `tos-edge` is the public control-plane process. The initial binary serves
  health and discovery documents only; public paid invocation stays disabled
  until authentication and payment authorization are implemented.
- `tos-ard-registry` provides the mandatory ARD `POST /search` and
  `GET /agents` baseline over a bounded in-memory index loaded from
  operator-approved local catalogs.
- vertical workers use the versioned ConnectRPC API over a private Unix
  socket. They do not receive wallet owner keys.

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
  -catalog ./examples/ai-catalog.json

go run ./cmd/tos-ard-registry \
  -listen 127.0.0.1:8090 \
  -catalog ./examples/ai-catalog.json
```

Remote crawling, federation, payment forwarding, and invocation are
deliberately not enabled in this bootstrap. They require the SSRF, provenance,
authentication, replay, and bounded-state controls described in the
architecture plan.

## Repository map

```text
api/                  versioned worker RPC contract
cmd/tos-edge/         public Edge Core entry point
cmd/tos-ard-registry/ ARD HTTP Registry entry point
pkg/ard/              pinned ARD v0.9 data model and validation
pkg/chain/            bounded JSON-RPC adapter
pkg/edge/             safe public discovery server
pkg/identity/         domain-separated Ed25519 envelopes
pkg/protocol/         TOS service descriptor and base validation
pkg/registry/         bounded ARD index and HTTP API
spec/                 version pins and protocol notes
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
