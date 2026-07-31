# Error and retry model

Errors use `error.schema.json` and the retry classes implemented in
`pkg/protocol`.

| Retry class | Client behavior |
|---|---|
| `never` | Do not repeat the request unchanged |
| `safe` | The same idempotency key may be queried or retried |
| `after-delay` | Retry only after `retryAfterMillis` |
| `after-reauthorize` | Obtain a fresh session or authorization |
| `after-payment` | Resolve or replace payment state before retry |
| `after-state-change` | Re-resolve manifests, revisions, or chain state |

`safe` means application-level exactly-once handling exists; it does not mean
an arbitrary non-idempotent HTTP request may be replayed.

Services MUST return `REPLAY_DETECTED` for a valid identifier reused with
different content. Capacity pressure SHOULD return `RESOURCE_EXHAUSTED` or
`ADMISSION_REJECTED`, not accept unbounded queued work. A chain reorganization
that invalidates payment uses `PAYMENT_REORGANIZED`; the service MUST follow
its signed settlement/refund policy and MUST NOT silently charge again.

Error messages and details are diagnostic and untrusted. Clients MUST branch
on the registered code and retry class, not parse human text. Implementations
MUST redact credentials, private prompts, object content, physical-site data,
and internal stack traces.
