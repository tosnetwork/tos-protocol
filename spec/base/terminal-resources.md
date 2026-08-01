# Terminal and resource declarations

A terminal manifest is a short-lived, signed operational snapshot. It is not
an inventory record, benchmark certificate, capacity reservation, or
permission to execute work.

The base structure is defined by `terminal-manifest.schema.json` and
`pkg/protocol.TerminalManifest`. Vertical profiles map their own dimensions to
the generic resource classes and integer units.

## Privacy

`terminalId` MUST be service-scoped or rotating. It MUST NOT be derived from a
serial number, GPU UUID, PCI address, MAC address, hostname, IP address, exact
site location, or another stable hardware fingerprint.

Public resource attributes MUST NOT contain those identifiers. A public
terminal normally reports coarse device class, capacity, compatibility
revision, and evidence freshness. Exact private fleet inventory stays behind
the site or fleet controller.

## Capacity accounting

Every resource claim states:

- total locally measured or configured capacity
- owner-reserved capacity
- currently available external capacity
- unit, revision, evidence level, issuer, collection time, and expiry

`availableExternal` MUST be no greater than `total - ownerReserved`. It must
also exclude existing commitments and locally unavailable capacity. Because
availability can change immediately after publication, it remains advisory.
The worker performs authoritative admission again when creating a quote and
again before executing the action.

Remote quantities are unsigned 64-bit protocol values. Implementations MUST
clamp them to a smaller administrator policy and host integer range before
allocation.

## Evidence and freshness

Each readiness component and resource field group has independent evidence.
`benchmarked`, `audited`, `attested`, `replicated`, and
`cryptographically-proven` claims require an evidence digest. A digest proves
artifact identity, not that the artifact is true or applicable.

The terminal manifest is valid for no more than ten minutes. Supporting
evidence must remain valid for the complete manifest interval. Clients must
evaluate the issuer and selected profile semantics; a self-observed claim is
not converted into third-party attestation by a Registry.

## Readiness

Readiness is structured by component. Allowed base states are `ready`,
`degraded`, `unavailable`, `unknown`, and `draining`. `reasonCode` is a stable
bounded identifier, not a free-form log or secret-bearing error.

An overall ready state does not override a degraded model, runtime, network,
thermal, storage, payment, update, or local safety component. Profiles define
which components are required for one operation.

Temperature and other signed telemetry are readiness evidence, not allocatable
resource quantities. They therefore do not use capacity accounting fields or
generic `ResourceUnit` values.

## Quote limits

`resource-limit.schema.json` defines the generic integer dimensions committed
by a quote. Examples include RAM bytes, accelerator-memory bytes, KV-cache
bytes, context count, batch count, and execution milliseconds.

The dimension identifier gives it meaning; the unit alone does not. A client
must compare the exact identifier, unit, quantity, profile revision, and
resource revision. Unknown required dimensions cause rejection.

The `tos-ai` v0.1 Worker profile fixes the following identifiers and units:

| Identifier | Unit |
| --- | --- |
| `memory.ram` | bytes |
| `memory.vram` | bytes |
| `memory.kv_cache` | bytes |
| `runtime.context_tokens` | count |
| `runtime.batch` | count |
| `runtime.output` | bytes |
| `runtime.execution` | milliseconds |
| `storage.task_slots` | count |
| `storage.task_bytes` | bytes |

Capability values are maximum admission profiles. Quote commitments are the
actual profile checked for that request, including its output and remaining
execution bounds. Requested limits, when present, are Edge-accepted upper
bounds; the committed requirement must fit within them. They are not
permission for a caller to override terminal policy.

`storage.task_slots` is one durable execution identity, not a byte quota.
Capabilities and quotes commit one slot. A terminal may advertise the
configured maximum, owner-reserved subset, and external availability without
exposing task IDs, payloads, results, paths, or retention timestamps.
Owner-reserved slots are available only to owner-local work. The snapshot is
advisory; only the Worker's atomic priority-aware durable claim grants a slot.
See [`docs/worker-service-v0.1-tos-ai-alignment.md`](../../docs/worker-service-v0.1-tos-ai-alignment.md).

`storage.task_bytes` is the conservative retained-byte reservation for that
identity. A Worker charges the deterministic request bytes plus the configured
maximum result size, maximum metadata size, and fixed logical key/index bytes
when it atomically claims a task. It retains that charge through every terminal
state until retention cleanup, so completion cannot fail merely because a
concurrent task consumed the result budget. The terminal may derive an
owner-only byte reserve from its owner-reserved slots. This is a logical
admission bound, not a physical bbolt file-size claim; filesystem allocation,
free pages, and compaction remain operator concerns.
