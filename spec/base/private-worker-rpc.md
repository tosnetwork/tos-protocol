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

Returned protobuf objects are defensively cloned across the boundary.

## Priority and retries

The default public Edge policy permits only `PRIORITY_EXTERNAL_SERVICE`.
Emergency, control, real-time perception, owner-local, and background classes
belong to explicitly configured local control planes. A remote caller cannot
raise its priority by choosing an enum value.

The client performs no automatic RPC retries. Edge Core and its durable
request journal own idempotency and recovery; retrying below that layer could
execute a non-idempotent action twice.

## Non-goals

This client does not expose a public invocation route, authenticate an
Internet caller, authorize payment, attest worker code, or prove executor
isolation. Those checks remain independently mandatory.
