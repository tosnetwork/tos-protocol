# tos-protocol Roadmap

Status: non-streaming v0.1 M1 integration-complete candidate
Last reviewed: 2026-08-01

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
- Bounded ARD bootstrap Registry with mandatory `POST /search`, minimal optional
  unfiltered List, privacy-minimized Worker projection, exact TOS extension
  filters, atomic local catalog reload, and per-request/per-entry/aggregate
  memory limits.
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

## In Progress

The active milestone is P2, the immutable v0.1 production candidate:

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

1. Add a bounded remote ARD catalog ingestion pipeline with explicit DNS/IP
   policy, SSRF defense, redirect rules, compressed/decoded size limits,
   recursion depth, cycle detection, publisher quotas, expiry, and atomic index
   replacement.
2. Add bounded ARD federation and the draft List filter/order behavior only
   against a pinned upstream version and conformance suite.
3. Complete the `.tos` registrar application and stable operator/client SDK
   surfaces needed by independent deployments.
4. Implement Worker/result streaming as v0.2 after the existing RFC fixes
   ordering, partial results, backpressure, deadlines, cancellation, resume,
   idempotency, usage, output limits, and final receipt binding.
5. Add reference policy adapters only where their trust semantics are explicit:
   workload identity, artifact provenance, policy evaluation, and evidence
   verification must not be inferred from discovery metadata.
6. Extend conformance coverage to independent-language clients and additional
   vertical profiles without changing the stable base envelope formats.
7. Add production relay, subscriptions/channels, multi-region routing, and
   advanced settlement/evidence as later versioned protocol work.

## External Certification

The following gates are intentionally not marked Completed by repository CI:

- **Live chain authority:** reviewed contract deployment; three independent
  RPC endpoints; controller/key rotation; revocation; rollback protection;
  finality and payment-reorganization rehearsal.
- **Key custody:** Quote/Receipt key ceremonies; manifest-role binding; HSM or
  sidecar deployment; rotation, revocation, restart, backup, and outage tests.
- **Authentication policy:** deployment selection and audit of session/Quote
  issuance plus Action/Receipt read authorization. Discovery is not authority.
- **Settlement policy:** deployed destination, full-charge or audited refund
  rules, restart reconciliation, and proof that a receipt is not mistaken for
  an on-chain refund.
- **Availability and memory:** sustained bounded-concurrency, anonymous-input,
  slow-client, malformed-request, chain/signer/Worker outage, disk-quota, and
  restart tests with RSS, heap, goroutine, file-descriptor, journal, and bbolt
  measurements.
- **Network perimeter:** reviewed TLS ingress, rate/connection limits, firewall,
  private Unix sockets, response redaction, and relay/home reachability.
- **ARD publication:** real catalog publication and pinned official ARD
  conformance execution; the current operator-fed Registry is not a claim of
  crawler or federation conformance.
- **Release governance:** reproducible build, compatibility matrix, rollback
  procedure, independent security review, signed artifacts, and testnet
  observation.

The detailed evidence table is maintained in
[`docs/non-streaming-v0.1-production-gates.md`](docs/non-streaming-v0.1-production-gates.md).

## Release milestones

| Milestone | Exit condition | State |
|---|---|---|
| P0: non-streaming foundation | Base schemas, auth/payment/receipt, chain adapters, Edge Core, WorkerService, bounded Registry, conformance and race tests | Completed |
| P1: AI Edge integration | `tos-ai-edge` uses the frozen interfaces and completes the local discovery-to-receipt flow | Completed |
| P2: v0.1 production candidate | External gates applicable to the reference deployment have evidence and the compatible repositories are tagged | In Progress |
| P3: discovery expansion | Bounded crawler/federation plus stable SDK and registrar surfaces | Next |
| P4: streaming v0.2 | Versioned streaming and receipt semantics pass compatibility and fault-injection tests | Next |

## Maintenance

Update this file in the same pull request whenever a deliverable changes
category. A code item may move to Completed after merge and CI. An External
Certification item moves only when the corresponding deployment artifact is
linked from the production-gate record.
