# Private Worker RPC

The Worker RPC is the versioned local boundary between Edge Core and a
vertical runtime such as `tos-ai-worker`. It is not an Internet API and does
not replace public authentication, session, payment, replay, or authorization
checks.

## Transport identity

The reference client connects only through an absolute, lexically clean Unix
socket path. Before each new connection it verifies that:

- the immediate parent is a real directory, not a symlink
- the parent and socket are owned by the current process user
- neither the parent nor socket grants group or other permissions
- the endpoint is a Unix socket rather than a file or symlink

The worker creates the directory with mode `0700` and socket with mode `0600`.
Deployments that need different operating-system identities require an
explicit authenticated local transport profile; weakening the filesystem
checks is not that profile.

## Bounded calls

ConnectRPC applies independent maximum encoded request and response message
sizes. The default is 2 MiB and the configured ceiling is 16 MiB. Edge checks
payload and requested output limits before serialization and applies:

- a short bounded timeout to health, capability, quote, and cancel calls
- the already-authorized absolute execution deadline to invocation
- a local maximum invocation duration even when the wire value is larger

Nil contexts, expired deadlines, unknown priorities, invalid identifiers,
duplicate resource limits, and locally excessive byte limits fail before the
worker is called.

## Response validation

Transport success is not semantic success. Edge rejects:

- quote responses bound to another request or expiring after its deadline
- empty or malformed revisions and identifiers
- invocation responses bound to another request
- outputs larger than the authorized maximum
- input/output usage counters inconsistent with the transferred bytes
- oversized or duplicate capability, readiness, resource, attribute, and
  resource-limit collections

Control and quote protobuf objects are defensively cloned across the boundary.
An invocation response is instead returned as an opaque validated result. To
consume it, Edge Core must repeat the request, quote, service, and operation
binding. The opaque result retains the requested output limit, absolute
deadline, completion time, byte/token usage, output, and worker revisions so
later receipt issuance cannot substitute a less restrictive request.

## Priority and retries

The default public Edge policy permits only `PRIORITY_EXTERNAL_SERVICE`.
Emergency, control, real-time perception, owner-local, and background classes
belong to explicitly configured local control planes. A remote caller cannot
raise its priority by choosing an enum value.

The client performs no automatic RPC retries. Edge Core and its durable
request journal own idempotency and recovery; retrying below that layer could
execute a non-idempotent action twice.

For a successful paid request, Edge Core accepts only this opaque result. It
requires the durable request to remain `running`, repeats the signed quote's
byte limits and deadline, commits the output digest and bounded usage to a
receipt, and sends only canonical receipt bytes to purpose-specific signing
key custody. The Worker never receives that key.

## Non-goals

This client does not expose a public invocation route, authenticate an
Internet caller, authorize payment, define profile intent-to-protobuf mapping,
attest worker code, or prove executor isolation. Those checks remain
independently mandatory.
