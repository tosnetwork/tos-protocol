# Local three-node AI Edge M1 evidence — 2026-08-01

Status: local M1 integration rehearsal passed; external production
certification remains open

## Scope

This rehearsal exercised the production `tos-ai-edge` composition, private
Worker and purpose-fixed signer sockets against three live local TOS service
nodes. The Worker used explicit development mock mode because this host has no
NVIDIA terminal or production model runtime. The result proves protocol,
authority, payment, persistence and recovery integration; it does not certify
GPU performance, hardware isolation, model quality, public TLS ingress, HSM
custody or long-duration leak freedom.

## Live chain and identities

- Network: `tos-local`
- RPC endpoints: `127.0.0.1:8011`, `:8012`, `:8013`; quorum `2`
- Service Agent Account:
  `-1:cca7c3159d0f52e674024bc13e81d6ea04642eb5a76d9e82146a364ad1d90b5c`
- Client Agent Account:
  `-1:f737d9c5afaa265df7ce09f2e66ab499e6f8a88a34a57ae189b7d94e7d5706f8`
- Payment destination:
  `0:ec0298b71068c44b1a495e6e95b0297becf0f5e11fbfefc54362c79c573bca6c`
- Sampled node state after the rehearsal: all three endpoints reported
  masterchain seqno `306106` and the same root hash.

Private seeds and request credentials remain in owner-only local state and are
not part of this record.

## Discovery-to-Receipt result

The opt-in `TestLiveThreeNodeDiscoveryToReceipt` performed all of the
following through production boundaries:

1. validated the descriptor and ARD catalog served by `tos-ai-edge`;
2. resolved and verified the controller manifest through 2-of-3 current chain
   authority;
3. issued purpose-bound session and Worker-capacity-bound Quote envelopes
   through private signer sockets;
4. resolved the real client Agent Account controller key;
5. observed an exact finalized 1 TOS native payment sent by that Agent Account;
6. executed the immutable text-generation mapper through the private Worker;
7. returned a signed successful Receipt; and
8. replayed the identical request without a second invocation or signature.

Result:

```text
first paid action:   succeeded, receipt present
exact replay:        succeeded, receipt present
receipt fingerprint: sha256:abdbfcd9c0917a022f9cef56bdec9df54c5f283789bc62fbcc08bc219505bc2a
```

The rehearsal exposed and fixed a real cross-repository defect: direct
`Invoke` used Edge RPC receive time while retained `GetTask` used Worker
completion time, causing a successful terminal replay to conflict by a few
milliseconds. Worker v0.1 now carries one durable
`InvokeResponse.completed_unix_millis`; direct Invoke, task storage and
GetTask validate and repeat exactly that value.

## Restart and fault injection

- The exact signed request and successful response were captured privately.
- Worker and Edge were both restarted.
- Replaying the captured request returned `succeeded` and the same signed
  response byte-for-byte. Both response files had SHA-256
  `88726a2afa308002df9eba5821177afda4e6afc59e72c5bde6ce30bc554ea2a6`.
- With one configured RPC endpoint unreachable, a second Edge instance passed
  startup and `/readyz` returned `200` through the remaining 2-of-3 quorum.
- With two endpoints unreachable, startup exited `1` with `quorum not reached`.
- Stopping the Receipt signer changed readiness to `503` with component
  `receipt-signer`; restoring it returned `200`.
- Stopping the Worker changed readiness to `503` with component `worker`;
  restoring it returned `200`.

## Bounded anonymous-input sample

The running Edge received 5,000 malformed anonymous Action requests with 32
concurrent clients. After a five-second settle:

| Metric | Before | After |
|---|---:|---:|
| Edge `VmRSS` | 32,808 KiB | 31,992 KiB |
| OS tasks | 22 | 23 |
| File descriptors | 7 | 7 |
| Edge journal | 262,144 bytes | 262,144 bytes |
| Worker task DB | 65,536 bytes | 65,536 bytes |

This closes the short M1 bounded-input regression check. It is not a substitute
for the long-duration RSS/heap/goroutine/slow-client certification listed in
the production gates.

## Automated verification

Both repositories passed on the candidate working tree:

```text
tos-protocol: make fmt-check
tos-protocol: go vet ./...
tos-protocol: go test -race -count=1 ./...
tos-ai:       gofmt clean
tos-ai:       go vet ./...
tos-ai:       go test -race -count=1 ./...
```

The systemd templates parse successfully; verification reports only expected
missing target-host binaries/unit dependencies in the development checkout.

## Production-gate status

This dated report is immutable evidence of the local M1 rehearsal, not the
living backlog for later deployment work. Current status, remaining evidence
and last-verification dates are maintained only in
[`non-streaming-v0.1-production-gates.md`](non-streaming-v0.1-production-gates.md).
