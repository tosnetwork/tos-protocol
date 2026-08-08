# ATOS Contract-Backed Economic Driver

`cmd/tos-atos-rpc` can activate the `tos_verified_v1` economic path by
combining two independent backends:

```text
finalized commitment Authority
              +
contract-backed Economic Driver
              =
ATOS Verified transaction path
```

The commitment Authority proves identity, capability, Quote, signer,
Execution Receipt, and Proof-of-Service anchors. The Economic Driver proves
that the client funds are controlled by a TOS smart contract and that reserve,
refund, provider payout, and dispute transitions reached finalized TOS state.
A generic transfer or a commitment anchor is not treated as escrow.

## Canonical contract

The v1 driver targets the Task Escrow contract already maintained in
`tosnetwork/tos`:

```text
crypto/smartcont/task-escrow.tlb
crypto/smartcont/task-escrow-code.fc
tosctl/src/node-control/contracts/src/task_escrow.rs
```

The reviewed contract code hash must be supplied explicitly in the driver
configuration. `tos-protocol` does not accept an arbitrary account merely
because its data happens to decode like Task Escrow state.

The contract states are:

```text
0 open
1 accepted
2 result_submitted
3 settled
4 cancelled
5 expired
6 rejected
7 disputed
```

The supported operation opcodes are:

```text
0x54415301 accept
0x54415302 submit result
0x54415303 settle
0x54415304 cancel
0x54415305 timeout
0x54415306 reject
0x54415308 dispute
0x54415309 resolve
```

## Service composition

Enable the two backends separately:

```text
TOS_ATOS_RPC_AUTHORITY=chain
TOS_ATOS_RPC_AUTHORITY_CONFIG=/etc/tos/atos-chain-authority.json

TOS_ATOS_RPC_ECONOMIC_DRIVER=task-escrow
TOS_ATOS_RPC_ECONOMIC_CONFIG=/etc/tos/atos-task-escrow.json
```

There is no fallback from `task-escrow` to local accounting. Invalid
configuration, an unavailable private publisher, stale chain consensus, a
wrong contract code hash, a substituted transaction, an unexpected sender,
an incorrect payout, or a non-final transition causes startup or the operation
to fail closed.

The local Authority cannot be paired with the contract driver. The Authority
and Economic Driver must also report the same TOS network.

## Key-custody boundary

`tos-protocol` does not load creator, provider, verifier, treasury, or wallet
private keys. A private Unix-socket sidecar implements:

```text
GET  /healthz
POST /v1/economic/task-escrow/action
```

The sidecar receives one immutable `chain.TaskEscrowAction` and returns one
`chain.TaskEscrowActionReceipt` containing the exact contract address and TOS
transaction reference. The sidecar is responsible for:

- deploying the reviewed Task Escrow code and exact initial data;
- selecting the correct signing account for the requested transition;
- durable Action ID deduplication before broadcasting;
- exact replay of the original transaction reference after a lost response;
- refusing a different action that reuses an existing Action ID;
- never publishing a second transaction merely because the request freshness
  window changed.

The expected signing account is:

| Action | Contract authority |
|---|---|
| deploy, cancel, dispute | creator |
| accept, result, reject | assigned agent/provider |
| settle, resolve | configured verifier |
| timeout | permissionless configured executor |

The sidecar cannot declare a transition valid or finalized. `tos-protocol`
independently verifies it with the strict-majority readers in `pkg/toschain`.

## Exact action identity

The stable Action ID binds:

```text
protocol version
network
operation
ATOS escrow ID
contract address, when known
creator
agent
verifier
original budget
funding amount
contract deadline
review period
settlement-policy commitment
permission commitment
query ID
result commitment
evidence commitment
dispute commitment
provider payout
exact TVM message-body hash
```

`expiresUnixMillis` is a bounded local freshness window and is deliberately
excluded from the stable identity. A retry can refresh that window without
creating a second economic action.

## Independent chain verification

For every deployment or operation, `pkg/toschain` verifies a strict-majority
view of:

- the finalized masterchain high-water mark;
- the exact contract transaction reference;
- transaction BOC hash and logical time;
- successful non-aborted VM and action phases;
- inbound sender and contract destination;
- operation opcode, query ID, and exact message-body cell hash;
- exact provider payout;
- minimum creator refund;
- the finalized post-transition Task Escrow state;
- the allowlisted Task Escrow code hash.

The post-state decoder verifies all v1 fields, including creator, assigned
agent, verifier, budget, deadline, status, result/evidence hashes, settlement
policy, permission commitment, review period/deadline, dispute commitment, and
attestor state. The first driver version requires an assigned agent, a distinct
verifier, and no contract attestor key; execution-receipt authorization remains
verified by the ATOS Trust/Proof services before the verifier submits the
contract settlement.

## ATOS lifecycle mapping

```text
CreateEscrow
  -> deploy Task Escrow with client creator, provider agent, verifier,
     exact reserve, deadline, policy hash, and permission hash

SubmitJob
  -> accept Task Escrow before Worker dispatch

SettleJob
  -> bind the verified Execution Receipt output/evidence commitments
  -> submit result if recovery finds it missing
  -> settle the exact requested provider payout
  -> independently verify provider and creator outputs

ReleaseEscrow
  -> cancel while open
  -> timeout after an accepted task deadline
  -> preserve disputed/result-submitted funds until a valid dispute resolution
```

The internal driver also exposes `OpenDispute`, `ResolveDispute`,
`RefundPrincipal`, and `ReadEconomicState`. The public ATOS v0.2 Settlement RPC
still has only Create/Release/Settle methods; a richer end-user dispute API is a
separate protocol addition and must not be simulated through an unverified
refund.

## Crash and retry behavior

A process can lose a response after the contract transition is finalized but
before the local bbolt transaction commits. Recovery is based on the stable
Action ID:

```text
same Action ID + same stable action
  -> sidecar returns original transaction reference
  -> tos-protocol re-observes exact finalized transition
  -> local state commits once

same Action ID + different stable action
  -> sidecar rejects
```

Terminal settlement, dispute resolution, cancellation, timeout, and rejection
paths replay the original action rather than trusting terminal state alone.
This prevents a different payout from being accepted after the local response
was lost.

## Example configuration

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
      "tvm-cell-sha256:<reviewed-agent-account-code-hash>"
    ]
  },
  "allowedTaskEscrowCodeHashes": [
    "tvm-cell-sha256:<reviewed-task-escrow-code-hash>"
  ],
  "verifierAddress": "0:<independent-verifier-account>",
  "publisherSocket": "/run/tos/atos-task-escrow-publisher.sock",
  "publisherTimeoutMillis": 20000,
  "publisherMaxMessageBytes": 524288,
  "publisherMaxConcurrent": 8,
  "fundingOverheadNanoTOS": 50000000,
  "reviewPeriodSeconds": 3600,
  "driverCallTimeoutMillis": 30000,
  "actionLifetimeSeconds": 300
}
```

All TOS account values use canonical raw addresses. The verifier must be
different from both client and provider. Funding overhead must cover deployment
and outgoing-message fees without reducing the contract's promised reserve.
The publisher socket and parent directory must be owned by the service user and
must deny group/other access.

## Current trust-mode boundary

With both chain Authority and Task Escrow Economic Driver configured:

```text
managed  -> supported
verified -> supported for contract-backed TOS escrow and settlement
native   -> fail closed
```

Native remains unavailable because global resolution, independent registry
reconstruction, gateway federation, and cross-gateway proof portability are
separate requirements. The existence of a finalized contract transition does
not by itself provide those network-ownership guarantees.
