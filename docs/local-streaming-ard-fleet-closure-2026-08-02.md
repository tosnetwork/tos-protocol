# Local Streaming, ARD Federation, and Fleet-Control Closure

Date: 2026-08-02
Scope: locally executable implementation and fault-injection gates

## Result

The locally executable portions of Worker result streaming v0.2, cached ARD
federation, and terminal-side fleet control are implemented in the paired
`tos-protocol` and `tos-ai` worktrees. Hardware-dependent cases use the
existing deterministic AI adapter, fake NVIDIA probes, MOCK fleet terminals,
and injected execution/availability failures. No test below is represented as
physical NVIDIA, public-perimeter, operator-key-custody, or actuator-safety
certification.

## Implemented boundaries

### WorkerStreamService v0.2

- separate service, preserving WorkerService v0.1 compatibility;
- execute once through the existing durable task claim;
- bounded chunk and total sizes, sequence and byte-offset cursors, maximum
  event count, immutable request/task/digest/model/runtime bindings;
- receiver-driven Connect backpressure;
- retained-task-only resume with an exact output commitment and prefix;
- one authenticated terminal state with final usage and durable completion;
- conversion to `ValidatedInvocation`, so existing Receipt issuance binds the
  same final usage and output digest as unary execution; and
- no Receipt or successful result from partial chunks or transport close.

### Cached ARD federation

- explicit HTTPS origin allowlist and transport-level DNS/IP validation on
  every dial, with public defaults rejecting loopback, private, link-local,
  multicast and unspecified address space;
- proxy disabled, manually validated redirects, fixed redirect/depth/source
  bounds, canonical URLs and cycle elimination;
- compressed transport and decoded-body limits, strict JSON content type and
  existing strict ARD structural/catalog limits;
- existing per-entry, per-publisher and aggregate index quotas;
- bounded cache TTL and explicit expiry; and
- whole-generation replacement only after every source validates. A failed
  refresh leaves the previous searchable generation unchanged. Search never
  performs network I/O.

### Fleet control

- domain-separated Ed25519 controller envelopes with exact fleet and terminal
  scope;
- monotonic generations, exact fingerprint replay and conflict rejection;
- bounded bbolt queue, total record count, database bytes and drain batch;
- durable offline ordering, restart recovery, expiry and no overtaking after
  reconnect;
- local real-time-busy gate before fleet work;
- deterministic bounded terminal ordering, canary promotion, failure stop and
  independently signed rollback; and
- privacy-minimized state containing logical IDs and release commitments, not
  GPU serials, hostnames or raw sensor data.

## Automated evidence

Commands executed from clean module boundaries or the explicit two-repository
Go workspace:

```text
cd /home/tomi/tos-protocol
GOWORK=off go test -race -count=1 ./...
GOWORK=off go vet ./...

cd /home/tomi/tos-ai
go test -race -count=1 ./...
go vet ./...
```

All commands passed. Focused tests additionally cover:

- successful multi-chunk Invoke and retained Resume over a real mode-0600
  Unix listener using the `tos-protocol` client and `tos-ai` server;
- duplicate/reordered sequences, missing/conflicting offsets, changed totals,
  changed revisions/digests, oversized chunks, incorrect resume prefixes and
  nonterminal disconnect rejection;
- federation cycles, TTL expiry, failure atomicity, disallowed redirects,
  private-address SSRF attempts, gzip expansion, decoded limits and depth
  overflow; and
- offline queue saturation, exact replay, wrong terminal, stale generation,
  real-time busy, process restart, command ordering, canary failure and signed
  rollback.

## Remaining external evidence

The following are not locally solvable code gaps and remain external gates:

- the selected public DNS, TLS and Registry perimeter plus authoritative ARD
  conformance service;
- independent-language streaming interoperability and production-duration
  network soak;
- the selected NVIDIA driver, device plugin and container isolation on target
  hardware;
- operator transport, fleet-owner key custody and multi-site deployment soak;
  and
- the independent physical safety controller, actuator interlocks and site
  acceptance.

Before independent `tos-ai` CI, publish the matching `tos-protocol` revision
and pin `tos-ai/go.mod` to it. Local cross-repository tests deliberately use
`/home/tomi/go.work`; no relative-module replacement belongs in a release.
