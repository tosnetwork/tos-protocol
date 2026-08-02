# Local MOCK and conformance closeout — 2026-08-02

Status: all newly identified host-executable code and MOCK gates passed;
deployment certification remains external

This report records the follow-up closure work performed across the compatible
`tos-protocol` and `tos-ai` working-tree candidate. It is not release evidence
until the revisions are committed, independently built by CI and recorded in
the production-gate ledger.

## Protocol closure

- Added explicit fail-closed adapters for exact SPIFFE workload certificates,
  signed artifact provenance, signed evidence requirements, fixed-endpoint OPA
  decisions and disconnected exact-tuple policy.
- Added canonical `.tos` name syntax independently of the registrar contract
  ABI. Contract messages, fees and ownership transitions remain deliberately
  unspecified until the real chain ABI is frozen.
- Added a dependency-free Node.js/TypeScript Registry client. It fixes one
  origin, rejects redirects and duplicate JSON keys, incrementally bounds the
  response body and validates the stable Search/List result boundary.
- The exact pinned upstream ARD v0.9 conformance suite passed for the Registry
  manifest and endpoints. The custom TOS media type produced only the
  upstream tool's informational unknown-media warning.

## AI terminal closure using MOCK dependencies

- Added an exclusive GPU alias lease client in front of a future reviewed
  NVIDIA container backend. Concurrent MOCK executions prove capacity fails
  closed and no alias is shared. Backend errors and panics synchronously release
  every lease.
- Added a deterministic benchmark runner boundary that signs
  privacy-minimized benchmark claims in the protocol EvidenceBundle domain.
  Error and panic injection produce no evidence.
- Added a fixed-action fleet executor. A validated command can select only
  install-release, rollback, apply-policy, rollback-policy, drain or resume;
  no path, URL, service unit, shell text or runtime endpoint crosses the
  boundary.
- Added a fixed-unit systemd reference adapter that invokes no shell and accepts
  no request-selected executable, unit or verb. MOCK timeout, panic and
  injection tests fail closed.
- Added a separately authenticated bounded reference metrics collector. It
  uses unique per-terminal credentials, stores one bounded snapshot per
  privacy-minimized alias, returns defensive sorted copies and performs TTL
  cleanup without a goroutine or retry queue.

## Commands and results

The following gates passed on the local host:

```text
cd /home/tomi/tos-protocol
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
node --test sdk/typescript/client.test.mjs

cd /home/tomi/tos-ai
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...
```

The `tos-ai` commands emitted only compiler warnings from deprecated symbols in
the pinned NVIDIA NVML headers; no project test or static-analysis gate failed.

## Claims that MOCK cannot close

| Claim | Why it remains external |
|---|---|
| `.tos` registrar compatibility | Requires the frozen deployed contract ABI, fee rules and governance address |
| Production workload/provenance/evidence trust | Requires real operator roots, issuer ceremonies and revocation operations |
| NVIDIA execution isolation | Requires exact driver/runtime/kernel hardware and proof that OCI injection matches each leased alias |
| Benchmark performance | MOCK validates evidence semantics, not tokens/second, latency, thermal or power performance |
| Service-manager and policy-loader operation | Requires the selected deployment's fixed unit, restart, health and policy authority |
| Public ARD/TLS/fleet operation | Requires public endpoints, certificates, network policy and physical safety interlocks |
| Long-duration bounded-memory claim | Requires a target-duration soak on the release hardware and configuration |

No remaining item in this table can be converted into genuine production
evidence merely by adding another in-process MOCK.
