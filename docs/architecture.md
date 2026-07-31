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
   | private versioned ConnectRPC, Unix socket 0600
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
capacity backpressure, and bounded expiry cleanup. The authorization library
verifies fresh controller authority, the current signed manifest, runtime
roles and revocation, canonical semantic payloads, and admission bindings.
Its stateless chain-resolver boundary enforces finality, code-hash allowlists,
timeouts, reference matching, and caller high-water sequence checks. The
public process must still supply the TOS contract decoder/RPC composition,
client session/delegation policy, payment observation and reconciliation,
invocation isolation, and receipt persistence before it forwards paid work.
Those runtime operations remain absent from the public server, so it exposes
no invocation route.

## Dependency decisions

| Concern | Baseline | Bootstrap status |
|---|---|---|
| Language | Go 1.24+ | implemented |
| Local process API | ConnectRPC + Protobuf | implemented |
| Public discovery | ARD v0.9 Draft | structural model and bounded Registry implemented |
| Base service protocol | TOS v0.1 Draft | schemas, Go types, terminal/resource declarations, canonical encoding and conformance vectors implemented |
| Manifest authorization | fresh authority snapshot + Ed25519/CBOR verifier | controller/current-digest/runtime-role/revocation, opaque admission result, and strict stateless chain-resolver boundary implemented; live TOS contract/RPC composition remains |
| Durable request state | bbolt-backed local journal | atomic nonce/request binding, bounded replay state, transitions, restart recovery and cleanup implemented as an Edge Core library |
| Distributed Registry backend | AGNTCY Directory | adapter planned; no fork |
| Chain access | TOS JSON-RPC/lite APIs | bounded generic JSON-RPC client and interface implemented |
| Policy | OPA | adapter planned after policy vocabulary is normative |
| Workload identity | SPIFFE | adapter planned |
| Artifacts | ORAS + Cosign + TUF | interfaces planned; AI repository starts manifest verification |

The Registry accepts only local operator-approved catalogs in this milestone.
Remote crawling is withheld until DNS rebinding, redirect, IP range,
decompression, recursion, federation, retry, and per-publisher limits are all
enforced.
