# Local production-gate engineering closure

Date: 2026-08-01 UTC

Status: all code and automated-test work applicable to the non-streaming v0.1
candidate and executable on the current host is complete. Production claims
that require selected operator policy, public infrastructure, physical NVIDIA
hardware, HSM custody, an independent review, or a signed release remain open
in the canonical production-gate ledger.

## Scope and evidence boundary

The source under test was the local candidate derived from:

- `tos-protocol` base `c3509f226e96714956ba0afa1f9f0b1b72eea45f`;
- `tos-ai` base `2b209b171fd5f8d53bc80bd0614a16f22a90dd74`;
- TOS node source `f4a584fe4fad29bcaf8b90b35903ba90834fcacb`.

The candidate additionally contains the tests, deterministic-build scripts,
CI gates, and documentation recorded by the change that adds this report. The
immutable release pair must be replaced with final commit and tag identifiers
only after these changes are committed and both remote CI runs pass.

No GPU, HSM, public TLS endpoint, or independent certification was available.
Those dependencies were represented only by test doubles and fault injection.
Such tests prove fail-closed software behavior; they do not certify the real
device or deployment.

## Local closure matrix

| Gate | Locally executable work | Result | What still requires the claimed environment or a decision |
|---|---|---|---|
| PG-01 | Independent-module race/static checks and byte-for-byte repeatable builds for every command | Passed locally | Immutable tags, signed artifacts, published compatibility/rollback record |
| PG-02 | Quorum, rollback, stale observation, reorganization and revocation fault tests; live 2-of-3 authority/client-key resolution | Passed locally | Production contracts, independent endpoints and an operator controller-rotation ceremony |
| PG-03 | Purpose-bound software custody, panic/error containment, pinned signer identity and key-rotation drift | Passed locally | HSM/keystore ceremony, backup and production key rotation |
| PG-04 | Session issuance, signer response revalidation, revocation and non-enumerating read-policy interfaces | Passed locally | Operator selection of wallet challenge, mTLS or another concrete ingress identity policy |
| PG-05 | Exact finalized payment, full-charge policy, restart recovery and reorganization blocking | Passed locally | Operator selection and audit of any refund policy beyond v0.1 full-charge settlement |
| PG-06 | Mock NVIDIA telemetry, VRAM admission, loss, thermal/power degradation and recovery | Passed by simulation | Driver/runtime/model performance and sustained operation on selected NVIDIA hardware |
| PG-07 | Mock isolation policy, lifecycle, cancellation, residue, bounded output and cleanup conformance | Passed by simulation | Exact kernel/cgroup/containerd/runc/seccomp/NVIDIA device configuration |
| PG-08 | Signed artifact corruption, interrupted activation, persistence failure, anti-rollback and known-good recovery | Passed by fault injection | Real trust-root ceremony, filesystem/power-loss rehearsal and selected runtime artifacts |
| PG-09 | Full race suite, bounded stores, TLS malformed-input test and 30,000-request live local sample | Passed locally | Long-duration target-host soak to steady state under production traffic mix |
| PG-10 | TLS 1.3 handler exercise, strict request rejection, response minimization and private Unix boundaries | Passed locally | Public certificate, reverse proxy, firewall, rate limits and external reachability review |
| PG-11 | Bounded local ARD catalog/search and privacy-minimized projection | Passed locally | Public naming/domain publication and the selected official conformance runner |
| PG-12 | Existing scheduler/update/offline foundations only | Not applicable to v0.1 | The physical-control and fleet product milestone is explicitly deferred |
| PG-13 | Independent-module checks and reproducible executable generation enforced by CI | Passed locally | Signed source/binaries, independent review, observation period and release approval |

## New permanent automated gates

Both repositories now expose:

```text
make local-gates
```

The target runs formatting, `go vet`, a non-cached full race suite, and two
independent deterministic builds. All Go commands use `GOWORK=off`, preventing
the developer workspace from hiding an incorrect `tos-protocol` dependency
pin in `tos-ai`. CI also runs the reproducible-build check.

The added focused coverage proves:

- session material is derived from verified manifest authority and cloned;
- signer payload/key substitution, cancellation, errors and panics fail closed;
- a revoked authenticate key cannot issue a session;
- a client pinned to the former signer identity rejects a rotated sidecar;
- mock NVIDIA VRAM, temperature and power observations degrade safely;
- loss of a required GPU blocks new Quotes without destroying durable replay;
- admission resumes after the simulated GPU recovers and no resource remains
  reserved;
- 2,048 concurrent malformed requests over TLS 1.3 receive either the
  non-oracular HTTP 401 rejection or bounded HTTP 503 load shedding, create no
  durable request, and leave liveness up. Dependency-sensitive readiness is
  covered separately.

## Live local TOS evidence

The three local RPC endpoints were live at approximately masterchain seqno
365,165 and agreed within one block. The following opt-in tests passed:

```text
go test -race -count=1 ./pkg/toschain -run TestLiveThreeNodeAdapters -v
go test -race -count=1 ./pkg/edgegateway \
  -run TestLiveThreeNodeDiscoveryToReceipt -v
```

The first resolved current service authority and its Agent Account client key
through a strict 2-of-3 majority. The second used the local service and client
Agent Accounts, private session/Quote/Receipt signers, exact finalized native
payment, private Worker, signed Receipt and exact replay. The terminal result
and Receipt fingerprint were stable on replay.

The running local Edge was then sent 20,000 and 10,000 malformed anonymous
requests with concurrency 64. All 30,000 returned HTTP 401. Across the sample:

- Edge RSS changed from 35,384 KiB to 35,232 KiB;
- Worker RSS changed from 34,320 KiB to 34,420 KiB;
- Edge and Worker file-descriptor counts returned to 7 and 8;
- Edge journal size remained 262,144 bytes;
- Worker task-store size remained 65,536 bytes;
- `/readyz` remained ready.

This is evidence of bounded behavior for this finite local sample, not a
long-duration memory-leak certificate.

## Reproduction

Run the repository-local gates independently:

```text
cd /home/tomi/tos-protocol && make local-gates
cd /home/tomi/tos-ai && make local-gates
```

The live tests are intentionally opt-in and require deployment-owned paths and
identifiers in environment variables. Seed material must never be copied into
this report, shell history, CI logs, or source control.

## Conclusion

There is no remaining non-streaming v0.1 implementation or deterministic
local-test gap identified by the production-gate audit. The canonical gates
remain Partial or Open where the missing evidence is, by definition, tied to
the actual deployment or to an operator/release decision. A simulated NVIDIA
backend, software signer, local TLS server, or local three-node chain must not
be relabeled as physical-hardware, HSM, public-perimeter, or release
certification.
