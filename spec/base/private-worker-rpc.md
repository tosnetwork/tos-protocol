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

The reference dispatch coordinator branches only on the atomic journal claim
disposition. `claimed` permits one `Invoke`; `replay` permits only `GetTask`.
An Invoke or lookup error returns `uncertain` together with a defensive copy of
the already committed claim, so error handling does not erase the recovery
identity. A valid `NOT_FOUND` response is not proof of non-execution and never
becomes retry permission. Task lookup uses a distinct local-policy preflight:
it permits the original execution deadline to have elapsed, but only while the
bounded retention deadline is still live. First dispatch continues to require
a future execution deadline.

The reference resolution coordinator treats `uncertain`, `NOT_FOUND`,
`ACCEPTED`, and `RUNNING` as explicit nonterminal observations and creates no
receipt for them. A validated direct or recovered `SUCCEEDED` result enters the
same successful receipt path. Validated recovered `FAILED`, `CANCELED`, and
`TIMED_OUT` states enter the zero-charge generic failure path. The coordinator
derives one deterministic receipt ID from the durable network, service,
request, task, private-request digest, authorization, and quote identity. It
does not include the observed outcome, so a contradictory terminal outcome
under the same execution identity conflicts instead of creating another
receipt.

Cancellation uses the same request ID, task ID, and request-digest tuple; the
Worker response must echo all three before Edge trusts its `accepted` flag. A
request-ID-only cancellation is not sufficient because it could target a
different retained task.

Before sending cancellation, the reference Edge coordinator re-reads the
journal and requires the same execution record and request revision to remain
`running`. It accepts cancellation only for an uncertain dispatch or a
validated `NOT_FOUND`, `ACCEPTED`, or `RUNNING` recovery observation. A direct
success or recovered terminal result must be resolved instead. Worker
acceptance is not terminal proof: accepted, rejected, and ambiguous attempts
all preserve the durable claim, write no receipt, and require a later
validated `GetTask` observation.

The Worker must durably return the same stored outcome for the same task and
exact request, reject a different request under that task ID, and remove it at
the bounded retention deadline. The Go reference now provides a reusable,
bbolt-backed `WorkerTaskStore` with atomic claim/replay, active and terminal
transitions, exact `GetTask`, capacity backpressure, expiry-index cleanup, and
startup corruption auditing. It does not start or recover model execution.
`tos-ai` must reconcile retained `ACCEPTED/RUNNING` records with an idempotent
runtime job or durable supervisor. Therefore `NOT_FOUND` remains evidence only
of that Worker's current bounded store, not proof that a prior process never
executed the task, and automatic invocation retry remains disabled. See
[`docs/worker-task-store.md`](../../docs/worker-task-store.md).

Edge's journal stores only the digest, not the potentially sensitive
invocation payload. Recovery therefore starts from an authenticated replay or
a deterministic profile mapping that reproduces the exact request. The
persisted claim and `BindInvocationRequest` reject any changed reconstruction.
For paid restart recovery, the payment transaction also preserves a bounded
semantic copy of the verified quote, payment authorization, and negotiated
profile selector. This permits deterministic reconstruction after the quote's
acceptance window expires without treating the expired quote as authority for
new work. The caller still supplies the exact intent bytes; Edge recomputes the
intent commitment before mapping. A durable `running` request can only call
read-only `GetTask`, while a durable terminal request can only replay the
receipt already committed in the journal. Reorganization blocks nonterminal
recovery before the Worker is contacted.

The generic Edge mapping boundary is deterministic and fail closed. It first
recomputes `tos.request-intent.v1` over the negotiated profile ID, version and
extension set, operation, and exact intent bytes, then compares it with the
signed quote.
Only after that check does the selected profile mapper receive a defensive
copy. The mapper may return only a model selector and Worker payload. Edge
itself supplies the paid request, quote, service and operation IDs, quoted
output limit and deadline, external-service priority, journal retention, and
a deterministic task ID bound to the complete payment scope. Mapper errors,
panics, cancellation, invalid selectors, or output outside the concrete
Worker client's configured policy fail before the journal moves to `running`.
An exact mapping replays the existing execution claim across restart; mapping
drift conflicts with its stored private request digest.

Production orchestration MUST select mappers from startup-reviewed static
configuration. The reference registry contains at most 128 entries and is
immutable after construction. Each entry matches the complete profile ID,
canonical semantic version, canonical extension set, and operation. Duplicate
entries, typed-nil implementations, invalid selectors, and excess capacity
fail startup. There is no wildcard, closest-version, extension-subset, or
default fallback. A missing exact registration fails before mapping or
execution state changes.

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
Internet caller, authorize payment, supply any vertical profile mapper,
attest worker code, or prove executor isolation. Those checks remain
independently mandatory.
