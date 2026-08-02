# tos-protocol Roadmap

Status: non-streaming v0.1 M1 integration-complete candidate
Last reviewed: 2026-08-02

This is the repository-level delivery roadmap for the generic TOS Service
Protocol. The cross-repository program view lives in
[`tos/doc/tos-network-roadmap.md`](https://github.com/tosnetwork/tos/blob/main/doc/tos-network-roadmap.md).
Normative behavior remains in `spec/`; architecture and production evidence
requirements remain in `docs/`.

## Completed

- Deterministic base protocol values, canonical JSON, signatures, fixed test
  vectors, descriptors, manifests, profile negotiation, and critical-extension
  rejection.
- Bounded session grants, delegation chains, Quote issuance and verification,
  client payment authorization, exact request-intent commitments, and signed
  receipt issuance.
- Current TOS chain authority, client-key, and finalized native-payment
  adapters with strict-majority observation, monotonic master-seqno protection,
  bounded RPC fan-out, and error propagation.
- Durable bounded request, payment, execution, and receipt journals with
  idempotent transitions, expiry, restart recovery, and reorganization gates.
- Complete non-streaming paid-action library path: authenticate the exact
  manifest/session/quote/delegation/payment set, apply the matching payment,
  invoke a Worker task at most once, recover only through `GetTask`, and replay
  the exact terminal result and signed receipt.
- Dependency-gated public `POST /tos/v1/actions`, authenticated
  `GET /tos/v1/actions/{actionId}`, and non-enumerating signed Receipt delivery,
  with strict media types and fixed body, response, deadline, and concurrency
  limits.
- Purpose-fixed private Unix Quote and Receipt signer clients and software-key
  sidecars with startup key/domain/path binding, bounded admission, panic
  containment, and returned-signature revalidation.
- Unary WorkerService v0.1: structured readiness/evidence, resource claims,
  capability freshness, requested/committed limits, Quote, digest-bound Invoke,
  retained `GetTask`, and exact Cancel.
- Separate WorkerStreamService v0.2 candidate with bounded chunks, exact
  sequence/offset validation, transport backpressure, retained-task-only
  resume, final stream commitment, usage/Receipt binding, and no re-execution
  after disconnect.
- Bounded ARD bootstrap Registry with mandatory `POST /search`, minimal optional
  unfiltered List, privacy-minimized Worker projection, exact TOS extension
  filters, atomic local catalog reload, and per-request/per-entry/aggregate
  memory limits.
- Cached ARD federation ingestion with exact HTTPS-origin policy, bounded
  redirects, compressed/decoded bodies, depth, cycles and source count,
  catalog/publisher/index quotas, TTL expiry, and whole-generation atomic
  replacement. Search never performs network I/O.
- Cross-repository compatibility with `tos-ai` text generation, capability-
  derived profile plans, owner-reserved task capacity, and route-identity drift
  readiness.
- Full repository race tests, static analysis, conformance tests, repeated
  concurrency tests, CI, and GPL-3.0 licensing.
- Production `tos-ai-edge` composition through current three-node chain
  authority, real Agent Account client keys, exact native payment, private
  session/Quote/Receipt signers, private Worker, signed Receipt and exact
  restart replay. Direct Invoke and retained GetTask now share one durable
  Worker-owned completion timestamp.
- Strict deployment material/config generation, bounded server-side paid-action
  diagnostics, systemd/config examples, one-node quorum tolerance, two-node
  fail-closed startup, Worker/signer outage readiness, and the local bounded
  anonymous-input rehearsal recorded in
  `docs/local-three-node-ai-edge-m1-evidence-2026-08-01.md`.
- Independent-module, non-cached race/static gates; byte-identical command
  builds; session issuance/revocation; signer rotation identity drift; TLS
  malformed-input load; and the complete local closure matrix recorded in
  `docs/local-production-gate-closure-2026-08-01.md`.
- Deterministic complete protocol release bundles containing all commands,
  normative specifications and GPL license, with internal/external SHA-256
  manifests, archive safety checks, optional detached Ed25519 verification,
  tamper tests, and CI enforcement.

## In Progress

The active milestone is P2, the immutable v0.1 production candidate. All
identified locally executable engineering sub-gates are complete; the
remaining work is deployment policy and external evidence:

- keep `tos-ai` pinned to the resulting immutable protocol revision, rerun
  both repositories independently and in CI, and prepare the release pair;
- select and audit deployment-owned session/Quote issuance and authenticated
  Action-status/Receipt-read policy;
- complete controller/key rotation, revocation, stale-node and settlement
  rehearsals without weakening the strict-majority/high-water rules;
- finish the applicable target hardware, custody, public perimeter,
  long-duration memory and release-governance certification rows below;
- create the immutable v0.1 release tag only after those selected production
  claims have evidence.

## Next

1. Add the draft List filter/order behavior only against a pinned upstream
   version and authoritative conformance suite; cached federation is complete.
2. Complete the `.tos` registrar application and stable operator/client SDK
   surfaces needed by independent deployments.
3. Add reference policy adapters only where their trust semantics are explicit:
   workload identity, artifact provenance, policy evaluation, and evidence
   verification must not be inferred from discovery metadata.
4. Extend conformance coverage to independent-language clients and additional
   vertical profiles without changing the stable base envelope formats.
5. Add production relay, subscriptions/channels, multi-region routing, and
   advanced settlement/evidence as later versioned protocol work.

## External Certification

External certification spans live-chain authority and settlement, key custody
and public authentication, target hardware and execution isolation, model and
update trust, availability and bounded memory, public networking, ARD
publication, and release governance. Repository CI alone cannot close these
claims.

The only mutable gate status, required evidence, evidence links and
last-verification dates are maintained in
[`docs/non-streaming-v0.1-production-gates.md`](docs/non-streaming-v0.1-production-gates.md).
This ROADMAP intentionally does not duplicate that ledger.

## Release milestones

| Milestone | Exit condition | State |
|---|---|---|
| P0: non-streaming foundation | Base schemas, auth/payment/receipt, chain adapters, Edge Core, WorkerService, bounded Registry, conformance and race tests | Completed |
| P1: AI Edge integration | `tos-ai-edge` uses the frozen interfaces and completes the local discovery-to-receipt flow | Completed |
| P2: v0.1 production candidate | External gates applicable to the reference deployment have evidence and the compatible repositories are tagged | In Progress |
| P3: discovery expansion | Bounded crawler/federation plus stable SDK and registrar surfaces | In Progress: crawler/federation local gates complete |
| P4: streaming v0.2 | Versioned result streaming and Receipt semantics pass compatibility and fault-injection tests | Local implementation complete; release pairing pending |

## Maintenance

Update this file in the same pull request whenever a deliverable changes
category. A code item may move to Completed after merge and CI. External gate
status changes only in the canonical production-gate ledger; this ROADMAP may
advance a milestone only when the linked ledger evidence supports it.
