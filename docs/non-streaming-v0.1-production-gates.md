# Non-streaming v0.1 production gates

Status: M1 local integration passed; external deployment certification is not complete

This file is the canonical, mutable production-gate ledger for the compatible
non-streaming `tos-protocol` and `tos-ai` release pair. Repository ROADMAPs
summarize scope and milestone ordering; dated evidence reports record what a
particular rehearsal proved. Neither replaces the status table in this file.

Status meanings:

- **Passed**: every required item for the stated production claim has linked,
  reviewable evidence.
- **Partial**: implementation or representative local evidence exists, but at
  least one deployment-specific requirement remains unverified.
- **Open**: the required representative deployment evidence does not yet exist.
- **Deferred**: the claim is outside non-streaming v0.1 and must not be
  advertised as part of this release.

Last deployed M1 integration pair:

- `tos-protocol`: `c1e33bc6208e9d275fe50f220e471263726fd357`
- `tos-ai`: `515a5cabdec44a57256ddf76bbd590d413778360`

Both revisions passed their independent GitHub CI runs and produced the local
M1 deployment evidence. They are the deployed evidence baseline, not the
current repository HEADs or signed v0.1 release tags. The final immutable
candidate pair must be recorded only after the local-closure changes pass
remote CI and are deliberately tagged.

This document separates repository work from claims that can be established
only by a real TOS Network and physical AI terminal deployment. “Implemented”
means the bounded code path and its automated tests exist. It does not mean a
particular operator, key ceremony, kernel, model, or public endpoint has been
certified.

## Implemented code boundary

The non-streaming v0.1 candidate includes:

- deterministic protocol values, schemas, signatures, intent commitments and
  fixed conformance vectors;
- current TOS authority, client-key and finalized native-payment adapters with
  strict-majority RPC observation and monotonic high-water checks;
- bounded session/delegation, quote, payment and paid-action authorization;
- atomic durable request, payment, execution and signed-receipt state with
  exact replay, restart recovery and payment-reorganization gating;
- a dependency-gated public paid-action handler, authenticated non-enumerating
  action-status and receipt handlers, and fixed request/response/concurrency
  limits;
- purpose-fixed private Unix quote and receipt signer clients and software-key
  sidecars, including startup key/domain/path binding and response revalidation;
- the private unary Worker protocol, exact task recovery/cancellation, bounded
  bbolt task storage, owner reserves and retained-byte admission;
- a bounded ARD `POST /search` Registry and minimal optional unfiltered List,
  including per-entry, aggregate-index and concurrent-request memory limits;
- the `tos-ai` text-generation profile mapper, live Worker capability-derived
  deployment plan, route-identity drift readiness, runtime/resource admission,
  model verification/update state machines, and opt-in isolated containerd
  execution path.

Streaming, arbitrary container execution, bare GPU rental, public shell access,
and request-selected runtime endpoints are outside this candidate.

## Local M1 evidence

The 2026-08-01 local rehearsal completed discovery, current 2-of-3 chain
authority, real Agent Account client-key resolution, exact finalized native
payment, private Worker execution, signed Receipt, exact replay and byte-stable
Worker/Edge restart recovery. It also verified one-node quorum tolerance,
two-node fail-closed behavior, Worker and signer readiness degradation, and a
bounded 5,000-request anonymous malformed-input sample. See
[`local-three-node-ai-edge-m1-evidence-2026-08-01.md`](local-three-node-ai-edge-m1-evidence-2026-08-01.md).

This evidence closes the local integration portion of M1 only. The target
hardware, custody, public perimeter, long-duration soak and release rows below
are not Passed.

## Local engineering closure

All implementation, deterministic automation and fault-injection work that is
applicable to non-streaming v0.1 and executable on the current host has been
completed. This includes independent-module race/static checks, reproducible
builds, session issuance and signer-rotation coverage, simulated NVIDIA
degradation/recovery, TLS malformed-input load, and another live local
three-node discovery-to-Receipt run. See
[`local-production-gate-closure-2026-08-01.md`](local-production-gate-closure-2026-08-01.md).
The follow-up [2026-08-02 local host closeout](local-host-closeout-2026-08-02.md)
adds deterministic signed-bundle tooling, two-slot power-loss recovery,
authenticated lifecycle control, bounded durable history, and a successful
real containerd/runc CPU lifecycle run.
The later [MOCK and conformance closeout](local-mock-and-conformance-closeout-2026-08-02.md)
adds explicit trust adapters, independent-language Registry conformance,
exclusive GPU lease fault injection, signed benchmark evidence, fixed fleet
action routing and a bounded reference metrics collector.

This closes local engineering sub-gates, not the production rows below. Status
remains Partial or Open whenever the remaining evidence requires selected
operator policy, real NVIDIA hardware, exact privileged isolation, HSM
custody, public infrastructure, an independent review, or release approval.

## Production-gate ledger

| ID | Gate | Status | Evidence required before the production claim | Current evidence | Last verified |
|---|---|---|---|---|---|
| PG-01 | Immutable release pair | Partial | Tag the compatible revisions, publish a compatibility matrix and rollback procedure, and produce reproducible signed artifacts. | Exact protocol pin and independent CI passed. Complete byte-identical bundles, full checksum verification, detached Ed25519 verification and tamper gates are implemented; no approved signed v0.1 tag or artifact exists. | 2026-08-02 |
| PG-02 | Live chain authority | Partial | Deploy reviewed Agent Account/service contracts behind at least three independent RPC endpoints and demonstrate controller rotation, client-key revocation, stale-node rejection, finality and payment-reorganization behavior. | The [local M1 report](local-three-node-ai-edge-m1-evidence-2026-08-01.md) proves three-node strict-majority authority, client-key resolution and finalized native payment, but not the remaining rotation/reorganization cases. | 2026-08-01 |
| PG-03 | Key custody | Partial | Complete production Quote/Receipt key ceremonies, bind manifest roles to sidecars or HSMs, and rehearse rotation, revocation, backup, restart and unavailable-signer behavior without reusing wallet-owner keys. | Purpose-fixed software sidecars, response revalidation, unavailable-signer readiness and pinned-identity rotation rejection were tested locally; no production ceremony or HSM evidence exists. | 2026-08-01 |
| PG-04 | Public authentication and read access | Partial | Select, implement and audit the deployment-owned session/Quote issuance ceremony and concrete Action-status/Receipt-read authorizers. | Session issuance plus authenticated, non-enumerating read handlers exist. Operator identity, wallet challenge, mTLS, KYC or gateway policy remains a deployment choice. | 2026-08-01 |
| PG-05 | Settlement policy | Partial | Deploy the production payment destination and document full-charge or independently audited refund/reconciliation rules, including restart behavior. | Exact finalized payment and full-charge Receipt behavior passed locally. A Receipt is not an on-chain refund and no production refund policy has been certified. | 2026-08-01 |
| PG-06 | Tier 1 NVIDIA terminal | Open | Certify the supported driver/runtime matrix, model load, cold start, sustained inference, thermal/power behavior and owner-priority operation on the selected Linux/NVIDIA terminal class. | MOCK telemetry and end-to-end admission cover VRAM, thermal/power degradation, GPU loss and recovery. Exclusive alias leases now pass overlap, capacity and panic-cleanup injection. The host still has no NVIDIA device, so performance and OCI assignment remain simulation rather than terminal evidence. | 2026-08-02 |
| PG-07 | Physical execution isolation | Partial | Run lifecycle and cleanup tests on the exact kernel, cgroup v2, containerd, runc, seccomp, namespace, filesystem and NVIDIA device configuration. Prove no residual workload objects after success, failure, cancellation or restart. | The [2026-08-02 closeout](local-host-closeout-2026-08-02.md) passed the complete CPU lifecycle suite on real local containerd/runc. The [MOCK closeout](local-mock-and-conformance-closeout-2026-08-02.md) adds exclusive GPU lease semantics, but target-kernel adversarial/reboot evidence and actual NVIDIA OCI injection remain uncertified. | 2026-08-02 |
| PG-08 | Model and update supply chain | Partial | Provision real trust roots and signed artifacts; rehearse corruption, incompatible runtime, interrupted activation, disk full, power loss, anti-rollback, known-good rollback and disconnected operation on target hardware. | Signed staging, exact candidate-boot health, power-loss rollback, anti-rollback, tamper handling and authenticated bounded lifecycle history pass automated race tests. No target trust-root ceremony, disk-full or physical power-loss report exists. | 2026-08-02 |
| PG-09 | Availability and bounded memory | Partial | Run sustained bounded-concurrency, slow-client, malformed-input, chain/Worker/signer outage, disk-quota and restart tests while recording RSS, heap, goroutines, file descriptors, task store, bbolt, RAM, VRAM and cache behavior to steady state. | Race tests, TLS test and an additional 30,000-request local sample passed with stable RSS, descriptors and database sizes; this is not a long-duration target-host leak certificate. | 2026-08-01 |
| PG-10 | Public network perimeter | Partial | Certify TLS ingress, connection/rate/body/header limits, firewall policy, private socket ownership, response redaction and supported home/relay reachability. | TLS 1.3 handler load, literal-loopback Edge and private mode-0600 Worker/signer sockets pass locally; no reviewed public TLS perimeter has been deployed. | 2026-08-01 |
| PG-11 | ARD publication | Partial | Publish the operator-approved catalog under the selected domain or TOS naming path and run the pinned official ARD conformance tool. | The bounded Registry passes local Go/TypeScript tests and the exact pinned upstream ARD v0.9 conformance tool. Canonical `.tos` syntax is implemented; public publication and registrar ABI/governance remain open. | 2026-08-02 |
| PG-12 | Offline physical terminal and fleet claims | Deferred | Before advertising this product class, complete disconnected soak, bounded journal, reconnect idempotency, real-time priority, safe update rollout, independent actuator safety, delegation/revocation and bounded fleet fan-out. | Local signed fleet commands, bounded offline queue/reconnect, canary rollback, fixed-action execution, authenticated transport and bounded metrics collection pass race/MOCK tests. Physical interlocks, selected TLS/service-manager/policy-loader integration and a real fleet soak remain external. | 2026-08-02 |
| PG-13 | Release governance | Partial | Produce reproducible builds, signed source/binary artifacts, compatibility and rollback records, an independent security review, testnet observation and final release approval. | Complete deterministic bundle construction and Ed25519 verification are CI gates, and the rollback procedure is documented. Offline signing, independent review, observation and approval remain open. | 2026-08-02 |

## Updating and closing gates

- Change a status only in this table and link the evidence in the same change.
- Evidence must identify the exact source revisions, configuration or hardware
  class, commands, duration and pass/fail criteria without publishing secrets.
- A local rehearsal may move a gate from Open to Partial. Only evidence from
  the deployment described by the claim may move it to Passed.
- ROADMAPs may advance a milestone after this ledger supports the transition;
  they must not maintain an independent copy of gate status.

## Release decision

M1 is integration-complete, but non-streaming v0.1 is not production-certified.
A production-ready or secure-hardware claim must wait until every applicable
row above is Passed on the actual terminal and chain deployment. PG-12 is
Deferred and therefore does not block a release that makes no offline,
physical-control or fleet claim. These gates do not authorize widening v0.1
with streaming; the separate streaming RFC remains targeted at v0.2.
