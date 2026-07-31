# Live TOS chain adapters

`pkg/toschain` is the bounded, read-only production composition for the three
chain-authoritative decisions used by Edge Core:

```text
                 strict majority (for example 2 of 3)
                         ┌───────────────┐
tos-protocol ----------->│ TOS JSON-RPC 1│
       │                 │ TOS JSON-RPC 2│
       │                 │ TOS JSON-RPC 3│
       │                 └───────┬───────┘
       │                         │ finalized public state
       ├─ authority <────────────┤ Agent Account code + getter
       ├─ client key <───────────┤ current controller key
       └─ payment <──────────────┘ exact inbound transaction BOC
```

The adapter never opens validator databases and never uses discovery metadata
as authority. Each endpoint must be an independently trusted/self-operated
read-only JSON-RPC observer in production. A strict majority is mandatory;
at least three and at most eight unique endpoint URLs and endpoint authorities
(host plus port) are required. Remote observers require HTTPS; plaintext HTTP
is accepted only for `localhost` or a numeric loopback address.

## Authority mapping

A protocol service references a canonical raw Agent Account address such as
`0:<64-lowercase-hex>`. At one pinned consensus masterchain seqno the adapter:

1. reads `getAddressInformation` and requires an active account;
2. hashes the decoded TVM code cell as
   `tvm-cell-sha256:<representation-hash>`;
3. runs `get_agent_account_data` at the same masterchain seqno;
4. maps the current controller key to `ed25519:<64-lowercase-hex>`; and
5. maps `service_endpoint_hash` to the canonical manifest commitment
   `sha256:<64-lowercase-hex>`.

This is an explicit **TOS Protocol Agent Account v0.1 profile**: an account
used as a service authority MUST put its canonical `tos.manifest.v1` digest in
`service_endpoint_hash`. The native `metadata_hash` field retains its existing
`AgentCapabilityMetadataBundle` meaning and is not silently reinterpreted.
The protocol manifest contains the service endpoints as well as their complete
authorization/profile commitments, making it the stricter endpoint bundle for
this profile. A future contract revision should expose a separately named
manifest field if both endpoint commitment formats must coexist on one
account.

The higher-level `authorization.ChainResolver` still requires a bounded local
allowlist of reviewed Agent Account code hashes. A code hash learned from the
same request must never be added automatically. Agent Accounts without a
manifest digest fail closed. The Service Actor response-attestor key is not
reinterpreted as manifest authority.

## Client-key mapping

The root client key ID is self-describing and canonical:

```text
tos:agent-key:v1:<workchain>:<agent-account-hex>:<controller-public-key-hex>
```

The adapter reads the named Agent Account through quorum and accepts the key
only while it equals that account's current controller. This supports any
number of independently owned clients without a server-side address map or a
request-controlled cache. Controller rotation immediately invalidates the old
key ID. Each observation produces a short configurable lease (five minutes by
default); authorization freshness and caller masterchain high-water checks
still apply. `FormatAgentClientKeyID` creates the canonical ID. A client Agent
Account does not need a service manifest commitment; only accounts used as
service authorities do.

The current Agent Account does not carry an on-chain delegated-key revocation
list. Delegation revocation remains enforced by the signed session/delegation
layer, while controller replacement revokes the root key through chain state.

## Native TOS payment mapping

A payment authorization uses this canonical reference:

```text
tos:tx:v1:<workchain>:<payee-account-hex>:<logical-time>:<transaction-hash-hex>
```

The payer and payee in the signed payment authorization must also use raw
canonical addresses. The adapter asks a quorum of nodes for that exact payee
transaction, bounds every response, verifies the response transaction ID,
decodes the original transaction BOC, recomputes its TVM cell hash, and
requires a positive, non-bounced inbound internal message to the named payee.
The actual source address and nanotomi value are returned to the existing
payment observer, which compares them to the authenticated quote and payment
authorization.

TOS finalized history does not reorganize. A quorum-confirmed missing
transaction is returned as `Confirmed=false`, not fabricated as a
reorganization. The adapter performs a second consensus read after
`getTransactions`, because that RPC method has no historical seqno parameter;
the returned masterchain high-water mark therefore cannot predate a newly
observed transaction.

Authorization ID, quote ID, and request ID are off-chain signed bindings to
the unique transaction reference. Global durable reference uniqueness in Edge
Core prevents one transaction from being applied to multiple requests.

## Runtime assembly

`tos-edge` accepts a strict, duplicate-key-rejecting JSON configuration through
`-tos-chain-config`. See `examples/tos-chain.json`. The production shape is:

```json
{
  "version": "1",
  "network": "tos-mainnet",
  "endpoints": [
    "https://rpc-1.example/jsonRPC",
    "https://rpc-2.example/jsonRPC",
    "https://rpc-3.example/jsonRPC"
  ],
  "quorum": 2,
  "queryTimeoutMillis": 5000,
  "maxResponseBytes": 4194304,
  "clientKeyLeaseSeconds": 300,
  "readinessMaxAgeSeconds": 120,
  "allowedServiceCodeHashes": [
    "tvm-cell-sha256:<reviewed-agent-account-code-hash>"
  ],
  "paymentQueryTimeoutMillis": 3000,
  "paymentMaxObservationAgeSeconds": 300,
  "allowOverpayment": false
}
```

The descriptor `network` must match this file, and its `controller` must be the
raw canonical Agent Account address. Startup fails closed unless a recent
strict-majority view is available and that Agent Account is active, uses a
locally allowlisted code hash, and exposes the required service manifest
commitment. Code hashes must be obtained from reviewed deployment artifacts;
they must never be learned and trusted from the same RPC preflight.

The resulting bundle exposes `Authority`, `ClientKeys`, and `Payments` over
one chain adapter. `/healthz` remains a local liveness check so an external
chain outage does not create a restart storm. `/readyz` checks the request
journal and the fresh TOS quorum and returns `503` without leaking endpoint
details when either is unavailable. Its fixed one-entry, one-second cache and
single-flight gate permit at most one chain readiness probe at a time; they do
not create request-keyed state or a waiter queue. This startup composition
still does not add a public invocation route.

When `-request-journal` is present with `-tos-chain-config`, `tos-edge` also
starts the existing durable payment reconciliation loop. Defaults are one
count-bounded page of eight records after one minute with a 30-second batch
timeout. A chain-level error or any failed entry doubles the single scheduler
interval up to 15 minutes; the next wholly successful batch resets it to one
minute. Operators may tune these bounded values with:

```text
-payment-reconciliation-interval
-payment-reconciliation-max-interval
-payment-reconciliation-timeout
-payment-reconciliation-batch
```

A chain or individual reconciliation failure degrades `/readyz`, while
`/healthz` remains tied to the local process, journal, and cleanup lifecycle.
The health snapshot exposes the next interval and the saturated count of
consecutive failed batches. Backoff owns one timer only: it creates no
per-payment goroutines, timers, cache entries, or waiter queue.
Cursor advancement is compare-and-swap and occurs only after the complete
bounded page was attempted, so a crash replays the same idempotent page rather
than skipping records.

## Local three-node rehearsal

Each local validator may expose a loopback-only read surface:

```text
--json-rpc-address 127.0.0.1:8011 --json-rpc-readonly
--json-rpc-address 127.0.0.1:8012 --json-rpc-readonly
--json-rpc-address 127.0.0.1:8013 --json-rpc-readonly
```

The opt-in integration test requires a deployed Agent Account and optionally
one real native transfer:

```sh
TOS_CHAIN_RPC_ENDPOINTS=http://127.0.0.1:8011,http://127.0.0.1:8012,http://127.0.0.1:8013 \
TOS_CHAIN_AGENT_ACCOUNT=0:<agent-account-id> \
TOS_CHAIN_PAYMENT_PAYER=-1:<payer-account-id> \
TOS_CHAIN_PAYMENT_PAYEE=0:<payee-account-id> \
TOS_CHAIN_PAYMENT_REFERENCE=tos:tx:v1:0:<payee-account-id>:<lt>:<tx-hash> \
go test -run TestLiveThreeNodeAdapters -v ./pkg/toschain
```

After replacing the descriptor controller and reviewed code hash, the complete
binary startup path is:

```sh
go run ./cmd/tos-edge \
  -listen 127.0.0.1:8080 \
  -descriptor ./examples/tos-service.json \
  -catalog ./examples/ai-catalog.json \
  -request-journal /absolute/private/path/requests.db \
  -tos-chain-config ./examples/tos-chain.json

curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/readyz
```

Unit tests additionally cover a disagreeing third observer, missing
transactions, malformed transaction BOCs, high-water rollback, missing service
commitments, stale readiness, strict startup decoding and authority preflight,
TOS-specific JSON-RPC success/error envelopes, controller mismatch, and
strict-majority configuration.

## Memory and failure bounds

There is no request-controlled service, key, transaction, or negative-result
cache. Parallel work is bounded by the configured endpoint count. HTTP bodies
default to 4 MiB and are capped at 16 MiB, calls have bounded timeouts, and
malformed BOC panics are converted to errors. Random address and transaction
probes therefore cannot create an unbounded anonymous RSS growth path in this
adapter.
