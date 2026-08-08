# ATOS Chain-Backed Authority

`cmd/tos-atos-rpc` supports two explicit Authority backends:

```text
local  -> Managed-only, synthetic `tos-local` references
chain  -> finalized TOS transaction references verified by strict-majority readers
```

Select the backend with:

```text
TOS_ATOS_RPC_AUTHORITY=local|chain
```

Chain mode additionally requires:

```text
TOS_ATOS_RPC_AUTHORITY_CONFIG=/absolute/path/atos-chain-authority.json
```

There is no automatic fallback from `chain` to `local`. Invalid config, stale
chain consensus, an unavailable publisher, a substituted transaction, or an
unfinalized transaction prevents startup or fails the commitment.

## Security boundary

`tos-atos-rpc` does not load a treasury, contract, or wallet private key. A
same-user private Unix-socket sidecar implements the narrow
`chain.ActionPublisher` contract:

```text
POST /v1/chain/action
GET  /healthz
```

The sidecar receives an immutable, idempotent action and returns one exact TOS
transaction reference. The sidecar is not trusted to declare finality.
`tos-protocol` independently verifies the exact transaction through the
existing `pkg/toschain` strict-majority adapter, including:

- network;
- transaction reference;
- payer;
- payee;
- amount;
- purpose-specific inbound message comment;
- minimum finalized masterchain position;
- current service authority/code commitment.

The canonical comment is:

```text
atos:v1:<sha256(version, network, service, anchor-kind,
                commitment-kind, object-id, object-digest,
                payer, payee, amount)>
```

The deterministic Action ID is derived from the same domain-separated stable
semantics. `expiresUnixMillis` is only a local freshness window and may be
refreshed by a retry; it is not part of the Action identity. A publisher must
return the original transaction for the same Action ID, reject any change to
the stable fields, and never publish a second transaction merely because the
freshness window changed.

## Example config

```json
{
  "version": "1",
  "chain": {
    "version": "1",
    "network": "tos-mainnet",
    "endpoints": [
      "https://rpc-1.example/jsonRPC",
      "https://rpc-2.example/jsonRPC",
      "https://rpc-3.example/jsonRPC"
    ],
    "quorum": 2,
    "allowedServiceCodeHashes": [
      "tvm-cell-sha256:<reviewed-code-hash>"
    ]
  },
  "serviceAddress": "0:<atos-service-agent-account>",
  "serviceId": "atos-gateway",
  "minimumMasterSeqno": 0,
  "publisherSocket": "/run/tos/atos-chain-publisher.sock",
  "publisherTimeoutMillis": 15000,
  "publisherMaxMessageBytes": 262144,
  "publisherMaxConcurrent": 8,
  "anchorPayer": "0:<treasury-account>",
  "anchorPayee": "0:<anchor-account>",
  "anchorAmountNanoTOS": 1,
  "authorityCallTimeoutMillis": 30000,
  "anchorLifetimeSeconds": 300
}
```

All addresses must use raw canonical TOS form. The publisher socket and its
parent directory must be owned by the current process user and deny group/other
access.

## Trust-mode boundary

The v1 chain-backed Authority proves finalized **non-economic commitment
anchors**. Managed `escrow`, `escrow-release`, and `settlement` transitions keep
explicit `tos-local` references and are never published as TOS anchors; a chain
transaction in those fields would misleadingly imply custody or payment
finality. Therefore the Authority currently advertises:

```text
managed  -> supported
verified -> fail closed
native   -> fail closed
```

This distinction is mandatory. Activating `tos_verified_v1` requires a
contract-backed economic driver that independently verifies reserve, release,
provider settlement, and refund transitions. A generic transaction anchor is
not a substitute for those guarantees.

The next economic extension should reuse the same pattern:

```text
private key/contract sidecar
          +
exact transaction or contract-state reference
          +
strict-majority TOS observation
          +
finality and semantic transition verification
```

No wallet seed or private key should cross the ATOS RPC boundary.
