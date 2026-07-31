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
worker is called. Every invocation has a mandatory bounded task ID.
Edge computes an internal SHA-256 request commitment with the protobuf
`request_digest` field cleared, persists it in the execution claim, then sends
the populated field. A supplied nonempty digest that does not match the exact
request is rejected before RPC. The invocation also carries the request
journal's retention deadline (rounded up to the next millisecond when needed),
so task state and any result cannot expire before its Edge recovery record.
Edge refuses a paid execution claim whose remaining journal retention exceeds
the protocol's seven-day hard maximum. A deployment-specific Worker client
limit may be lower and must be aligned with request admission policy.

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
deadline, task ID, deterministic digest of the exact private protobuf request,
completion time, byte/token usage, output, and worker revisions so later
receipt issuance cannot substitute a different or less restrictive request.

## Priority and retries

The default public Edge policy permits only `PRIORITY_EXTERNAL_SERVICE`.
Emergency, control, real-time perception, owner-local, and background classes
belong to explicitly configured local control planes. A remote caller cannot
raise its priority by choosing an enum value.

The client performs no automatic RPC retries. Before the first call, Edge Core
must atomically bind the exact invocation digest and globally unique task ID to
the paid request's `running` transition. This makes Edge recovery decisions
durable, but it does not make a non-idempotent Worker safe to retry.

The `GetTask` recovery method is read-only and carries the original request ID,
task ID, request digest, and retention deadline. A response repeats the first
three, and every retained state must exactly repeat the deadline. It returns
exactly one of:

- `NOT_FOUND`, with no result, error, completion time, or retention
- `ACCEPTED` or `RUNNING`, with only a bounded future retention deadline
- `SUCCEEDED`, with the original validated invocation result and completion
  time
- `FAILED`, `CANCELED`, or `TIMED_OUT`, with respectively `RUNTIME_FAILED`,
  `CANCELED`, or `DEADLINE_EXCEEDED` and a completion time, but no raw
  diagnostic or success result

The reference client rejects binding substitution, unknown states, malformed
state/result combinations, inconsistent byte accounting, early timeout,
success after the invocation deadline, future or stale completion times, and
retention outside its configured bound (48 hours by default, seven days hard
maximum). A recovered success remains opaque and can enter the same Edge
receipt path as a live invocation result. The recovery observation itself is
also opaque: an unvalidated caller-constructed value exposes neither a status
nor a result.

Cancellation uses the same request ID, task ID, and request-digest tuple; the
Worker response must echo all three before Edge trusts its `accepted` flag. A
request-ID-only cancellation is not sufficient because it could target a
different retained task.

The Worker must durably return the same stored outcome for the same task and
exact request, reject a different request under that task ID, and remove it at
the bounded retention deadline. The protocol and validated client are present;
the repository does not yet contain a production Worker task store. Therefore
`NOT_FOUND` is evidence only of that Worker's current bounded store, not proof
that a prior process never executed the task, and automatic invocation retry
remains disabled.

Edge's journal stores only the digest, not the potentially sensitive
invocation payload. Recovery therefore starts from an authenticated replay or
a deterministic profile mapping that reproduces the exact request. The
persisted claim and `BindInvocationRequest` reject any changed reconstruction.

For a successful paid request, Edge Core accepts only this opaque result. It
requires the durable request to remain `running`, repeats the execution
claim's task and invocation digest and the signed quote's byte limits and
deadline, commits the output digest and bounded usage to a receipt, and sends
only canonical receipt bytes to purpose-specific signing key custody. The
Worker never receives that key.

RPC failure text is not receipt material. The generic Edge failure path emits
only a typed `failed`, `canceled`, or `timed_out` status with an empty usage
array and zero charge. A profile that permits verified partial-work charging
must define and test that policy separately before enabling it.

## Non-goals

This client does not expose a public invocation route, authenticate an
Internet caller, authorize payment, define profile intent-to-protobuf mapping,
attest worker code, or prove executor isolation. Those checks remain
independently mandatory.
