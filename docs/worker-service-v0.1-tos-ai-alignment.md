# WorkerService v0.1 alignment for `tos-ai`

Status: implementation contract for v0.1 freeze

This document fixes the private interface between Edge Core and
`tos-ai-worker`. It records which requirements are already represented by
`api/tos/edge/v1/worker.proto` and gives the fields one interoperable meaning.
It does not make the private Unix-socket API an Internet-facing service.

## Protocol coverage

The current schema already provides:

- structured readiness and evidence levels;
- resource claims with independent revision and freshness evidence;
- per-capability admission limits;
- requested and committed quote limits;
- an exact, digest-bound invocation identity and bounded retention;
- read-only `GetTask` recovery; and
- cancellation bound to request ID, task ID, and request digest.

No additional protobuf field is required for the non-streaming v0.1 runtime.
The remaining work is implementation, validation, and cross-repository
testing. Streaming is deliberately separated into
[`worker-streaming-rfc.md`](worker-streaming-rfc.md).

## AI resource dimensions

`tos-ai` uses the following exact identifiers. Identifiers and units are part
of the contract; consumers must not infer meaning from a unit alone.

| Identifier | Unit | Meaning |
| --- | --- | --- |
| `memory.ram` | bytes | host RAM charged to one execution |
| `memory.vram` | bytes | accelerator memory charged to one execution |
| `memory.kv_cache` | bytes | model KV-cache budget |
| `runtime.context_tokens` | count | maximum model context tokens |
| `runtime.batch` | count | maximum batch size |
| `runtime.output` | bytes | maximum returned payload |
| `runtime.execution` | milliseconds | maximum execution duration |
| `storage.task_slots` | count | one bounded durable task identity |
| `storage.task_bytes` | bytes | conservative retained-byte reservation for that identity |

A capability advertises its maximum admission profile. A quote commits the
actual profile checked for that request. `runtime.output` is the requested
output bound. `runtime.execution` is the smaller of the adapter execution
budget and the remaining request deadline. The other dimensions come from the
startup-reviewed adapter configuration.

Every capability and quote additionally commits one `storage.task_slots` unit
and the Worker's maximum `storage.task_bytes` reservation. Their capacity
claims report only configured limits and current priority-aware availability.
Owner-reserved slots imply maximum-sized owner byte reservations available
only to `LOCAL_ASYNC`; external-service and background tasks cannot consume
them. Neither claim discloses a task identity or storage path, and `ClaimTask`
remains authoritative during Invoke.

`requested_limits` is optional in v0.1. When present, each quantity is an
upper bound accepted by Edge. Every item must use one of the identifiers and
units above, and the worker's actual committed requirement must fit within
it. Unknown, duplicate, zero, unit-mismatched, or caller-invented resource
overrides fail closed. This keeps the task payload from becoming an alternate
local resource-policy channel.

The quote is not a reservation. `tos-ai-worker` performs a current bounded
admission check during Quote and creates the authoritative local reservation
again during Invoke. Invoke uses the committed profile stored with the quote;
it does not trust a payload or recompute a less restrictive caller profile.

Worker v0.1 usage intentionally contains only input/output bytes, optional
model token counts, and elapsed execution milliseconds. Runtime CPU time,
peak memory, block IO, accelerator counters, and energy estimates are local
admission/audit evidence, not portable receipt units in v0.1. A runtime must
still enforce those local ceilings, but Edge must not silently reinterpret them
as billable usage without a future versioned protocol and pricing rule.

## Evidence, freshness, and revision

Evidence levels retain their base-protocol meanings. In particular,
`declared` means constrained by private operator policy; it is not upgraded to
`observed` merely because the worker emitted it. A runtime model digest seen
through a local preflight may be `observed`. Benchmarked or stronger evidence
requires the corresponding evidence artifact and digest.

Each capabilities snapshot carries:

- a collection and expiry time;
- a capacity revision covering current capacity and reservation state;
- a terminal revision identifying the worker build; and
- per-resource evidence whose validity covers the snapshot interval.

Snapshots expire after a short bounded interval and are advisory immediately
after issue. A capacity revision is a comparison token, not a lease.

## Structured readiness

`Health.readiness` contains stable components for the worker, admission,
resource guard, runtime set, model binding, and GPU class. Components use
bounded reason codes rather than raw driver, runtime, model, or filesystem
errors. The legacy `status` string remains a compact human-readable summary,
but consumers make routing decisions from the structured components.

Draining, unavailable resources, an incomplete runtime set, or missing model
binding must remain visible even if another component is ready.

## Hard limits and privacy

The reference private client rejects more than 128 capabilities, 128 resource
claims, 64 readiness components, 64 resource limits, 64 resource attributes,
or six priorities. Identifiers are at most 128 bytes, ordinary values and
revisions at most 512 bytes, and evidence references at most 2,048 bytes.
Encoded messages default to 2 MiB and cannot be configured above 16 MiB.
Implementations may be stricter.

Neither readiness, resources, attributes, revisions, evidence, reason codes,
logs, nor metrics may contain a GPU serial or UUID, PCI address, MAC address,
hostname, IP address, exact site location, credential, raw runtime error, or
another stable hardware fingerprint. `tos-ai` v0.1 emits no resource
attributes that are not on an explicit safe allow-list.

## Durable task migration

Every new Invoke has a globally unique task ID, the protocol-defined request
digest, and a future bounded retention deadline. `tos-ai-worker` claims that
identity in the durable Worker task store before executor admission. Exact
replay cannot start a second execution.

`GetTask` is read-only. `Cancel` repeats and verifies all three identity
fields; request-ID-only cancellation is obsolete. A process restart retains
accepted, running, and terminal observations. The task store alone cannot
decide whether an accepted or running task still has executor ownership, and
it never silently resubmits one.

The current synchronous `tos-ai` adapters have no durable runtime job handle.
Before their private listener becomes reachable, startup therefore performs a
bounded paginated scan and converts every retained interrupted active task to
`FAILED/RUNTIME_FAILED`. Exact terminal lookup remains available until
retention expiry. A future supervisor may recover rather than fail a task only
when it can bind durable executor ownership to the exact task ID.

## Cross-repository release gate

The v0.1 interface is ready to freeze only when:

1. `tos-ai` pins a `tos-protocol` revision containing the complete schema.
2. A real ConnectRPC handler passes through `localrpc.WorkerClient` for
   Health, capabilities, Quote, Invoke, GetTask, and Cancel.
3. Tests cover every AI resource mapping, freshness, privacy, malformed
   limits, quote/Invoke admission recheck, exact cancellation, concurrent
   replay, retained success/failure, restart recovery, and bounded storage.
4. Both repositories pass their full test and race suites.
5. The streaming decision is recorded independently and causes no implicit
   unary compatibility promise.
