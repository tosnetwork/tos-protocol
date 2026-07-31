# Durable Worker task store

`pkg/localrpc.WorkerTaskStore` is the reusable server-side idempotency and
recovery table for a vertical Worker such as `tos-ai-worker`. It complements
the Edge request journal; it does not replace it.

```text
Edge request journal                      Worker task store

paid request + exact invocation digest -> ClaimTask(request)
                                            |
                                            +-- claimed: executor may start once
                                            +-- replay: executor MUST NOT start again
                                            |
                                      ACCEPTED -> RUNNING
                                            |         |
                                            +---------+
                                                 |
                         SUCCEEDED / FAILED / CANCELED / TIMED_OUT
                                                 |
                                  exact GetTask and terminal replay
```

## Properties

The store uses a separate mode-`0600`, current-user-owned, non-symlink bbolt
database under a mode-`0700`, current-user-owned, non-symlink directory and
provides:

- one atomic task-ID claim for the deterministic protobuf request;
- exact replay and conflicting task-ID/request rejection;
- durable `ACCEPTED`, `RUNNING`, and terminal states;
- deterministic request and result encoding with unknown-field rejection;
- defensive request/result copies;
- exact request ID, task ID, digest, and retention matching;
- protocol-defined terminal error codes without raw diagnostic persistence;
- count, message-size, invocation-duration, retention, priority, and cleanup
  limits;
- an expiry index for bounded cleanup without a full-database scan;
- startup auditing of records, payloads, results, expiry entries, and counts;
- atomic concurrent claim and terminal replay behavior.

The task database is bounded by `MaxTasks`. Each request and successful result
is independently bounded by `MaxMessageBytes`; metadata is capped separately.
The implementation adds no task-index mirror, waiter list, per-task goroutine,
or per-task timer in process memory.

`Stats` exposes only the O(1) logical task count, configured capacity, and
remaining slots. It never exposes the database path, task identities,
payloads, results, or retention timestamps. A vertical Worker uses this
snapshot for advisory readiness and Quote routing; `ClaimTask` remains the
only authoritative admission operation under concurrency.

## Worker integration

A Worker `Invoke` handler should follow this order:

1. Call `ClaimTask` before starting a container, model, or device operation.
2. Start work only when the disposition is `TaskClaimed`.
3. Obtain the callback binding from `StoredWorkerTask.Identity`, then optionally
   call `MarkTaskRunning` after the executor has durably accepted ownership.
4. Finish through `CompleteTaskSuccess` or `CompleteTaskFailure`.
5. Return the stored result for an exact succeeded replay. Never start work for
   `TaskReplay`; active and failed replays are observed through `GetTask`.
6. Implement WorkerService `GetTask` by delegating to the store's `GetTask`.
7. Run bounded `Cleanup` periodically and during controlled shutdown/startup.

The Edge and Worker configuration must agree on maximum message bytes,
invocation duration, task retention, and allowed priorities. A more restrictive
Worker policy is allowed but fails the request before execution.

## Crash semantics

The store closes the local duplicate-admission gap, but persistence alone does
not make an arbitrary executor exactly once.

- A crash before `ClaimTask` commits leaves no Worker task; Edge retains its
  `running` claim and observes `NOT_FOUND`, which is not automatic retry
  permission.
- A crash after claim but before executor ownership leaves `ACCEPTED`.
- A crash after executor ownership but before terminal persistence leaves
  `RUNNING`.
- A crash after terminal persistence replays the exact terminal outcome.

`tos-ai` must therefore reconcile retained `ACCEPTED/RUNNING` tasks with its
executor on startup. Safe options include an idempotent runtime job ID equal to
the TOS task ID, a transactional local outbox, or a sandbox supervisor with its
own durable job registry. It must never infer that an absent process means the
work did not run, and it must never resubmit solely because Edge reports a
timeout or the Worker store reports `NOT_FOUND`.

## Trust boundary

The task store is private Worker infrastructure. It does not verify Internet
clients, TOS sessions, quotes, payments, manifests, or receipts. Edge performs
those checks and derives the immutable Worker request. The Worker store still
validates the private request digest and local resource policy so corruption or
a compromised local caller cannot silently replace a retained task.

Because recovery requires the exact private request and successful result,
these payloads remain on disk until retention expires. Deployments should use
owner-controlled encrypted storage, avoid backups that outlive retention, and
keep payloads out of logs and metrics. Mode `0600` protects against unrelated
local users but is not a substitute for disk encryption or host integrity.
