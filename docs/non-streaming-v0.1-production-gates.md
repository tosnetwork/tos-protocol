# Non-streaming v0.1 production gates

Status: M1 local integration passed; external deployment certification is not complete

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
remain open.

## Gates that require a deployment

| Gate | Evidence required before a production claim |
|---|---|
| Immutable release | Commit and tag `tos-protocol`; update `tos-ai` to the exact immutable protocol revision; run both repositories independently and together in CI. |
| Live chain authority | Deploy the reviewed Agent Account/service contracts, configure at least three independent RPC endpoints and a strict majority, then demonstrate controller rotation, client-key revocation, stale-node rejection and payment reorganization behavior. |
| Key custody | Complete quote and receipt key ceremonies; bind current manifest roles to the deployed sidecars or HSMs; rehearse rotation, revocation, process restart and unavailable-signer behavior without reusing wallet-owner keys. |
| Public authentication policy | Select and implement the deployment-owned session/quote issuance ceremony and the concrete action-status/receipt access authorizers. The base library intentionally does not invent an operator's identity, KYC, mTLS, wallet-challenge or gateway policy. |
| Settlement policy | Deploy the payment destination and decide whether successful receipts always charge the full quote. Any partial successful charge requires an independently audited refund/reconciliation mechanism; the receipt alone does not move funds back to a payer. |
| Physical isolation | Run the containerd lifecycle suite in the exact production kernel, cgroup v2, runc, seccomp, namespace and filesystem configuration. GPU access requires a separate NVIDIA runtime/device-isolation implementation and certification; the current concrete containerd driver is CPU-only and network-none. |
| Model supply chain | Provision operator trust roots and signed model/update manifests; rehearse interrupted download/activation, anti-rollback, corruption, disk-full, known-good rollback and offline operation on the target terminal class. |
| Availability and memory | Execute sustained bounded-concurrency load, slow-client, malformed-input, chain-outage, Worker-crash, signer-outage, disk-quota and restart tests while recording RSS, heap, goroutine, file-descriptor, task-store and bbolt growth. Passing unit race tests is necessary but not a long-duration leak certificate. |
| Network perimeter | Terminate TLS at a reviewed ingress, enforce connection/rate/body/header timeouts outside the process, keep Worker and signer sockets private, and verify that no private runtime, hardware identity, credential or raw error crosses public responses. |
| ARD publication | Publish the operator-approved catalog under the selected domain or TOS naming path and run the pinned official ARD conformance tool. Remote crawling and federation are separate Registry deployment features, not prerequisites for the local bounded Registry. |

## Release decision

The repository candidate is ready for an immutable integration commit when all
automated tests pass. A production-ready or secure-hardware claim must wait for
the relevant rows above to be evidenced on the actual terminal and chain
deployment. These gates do not authorize widening v0.1 with streaming; the
separate streaming RFC remains targeted at v0.2.
