# TaskEscrow Key-Custody Publisher

`tos-task-escrow-publisher` is the private signing and submission sidecar for
ATOS contract-backed economics. It serves only an owner-private Unix socket:

```text
GET  /healthz
POST /v1/economic/task-escrow/action
POST /v1/economic/task-escrow/action/resolve
```

The sidecar owns access to the configured `tosctl` vault. `tos-protocol` never
receives wallet seeds, private keys, or vault credentials. The receipt returned
by the sidecar is only a candidate transaction reference; the Economic Driver
independently verifies the exact transaction, TaskEscrow code hash, contract
state transition, payout/refund outputs, strict-majority observation, and TOS
finality.

## Durable idempotency

Before invoking `tosctl`, the sidecar persists the immutable action digest,
deterministic contract address, and the contract's previous transaction cursor
in bbolt. The same `actionId` with different stable fields is rejected. A retry
of the same action first searches the TaskEscrow transaction history for the
original successful transaction. A bounded lookup miss never proves absence:
the pending action remains uncertain and the sidecar does not submit it again.

`expiresUnixMillis` is a freshness window and is deliberately excluded from the
stable action identity. All economic fields remain part of the identity.

## Exact atomic amounts

The publisher requires a `tosctl` build supporting:

```text
--permission-hash
--budget-nanotos
--amount-nanotos
--payout-nanotos
```

This avoids passing escrow budgets and payouts through floating-point values.

## Wallet bindings

The configuration maps each canonical raw TOS address to one `tosctl` wallet
profile. At readiness, the sidecar executes `tosctl wallet ls --format json`
and refuses to start unless every configured profile resolves to the exact
address.

Action-to-key selection is fixed:

```text
deploy / cancel / dispute -> creator wallet
accept / result / reject  -> provider wallet
settle / resolve          -> verifier wallet
timeout                   -> configured executor wallet
```

## Deployment

1. Install `tosctl` and `tos-task-escrow-publisher`.
2. Create a private runtime directory owned by the service account.
3. Store the sidecar config as an owner-private regular file.
4. Enroll the journal exactly once with the final network and policy:
   `TOS_TASK_ESCROW_PUBLISHER_CONFIG=/absolute/config.json tos-task-escrow-publisher init-journal`.
   Enrollment binds the journal identity, schema, network, wallet/spending
   policy and code-hash allowlist. Normal startup rejects missing, substituted
   or configuration-mismatched journal state. Before creating the journal,
   readiness builds a side-effect-free TaskEscrow StateInit and requires its
   normalized code hash to match the enrolled allowlist exactly.
5. Configure `TOS_ATOS_RPC_ECONOMIC_CONFIG` to use the same Unix socket.
6. Start the publisher before `tos-atos-rpc`.

See `examples/tos-task-escrow-publisher.json` and
`deploy/systemd/tos-task-escrow-publisher.service`.

The file-vault example is for local or controlled deployments. Production key
custody should use the TOS vault/HSM integration appropriate to the operator's
risk model; no secret should be placed in the ATOS RPC configuration.
