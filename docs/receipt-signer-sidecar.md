# Receipt signer sidecar contract

Status: bounded client, software-key sidecar, and identity-bound Edge startup
wiring implemented; HSM integration, key rotation orchestration, and
deployment remain operator responsibilities.

`pkg/localrpc.ReceiptSignerClient` implements the Edge
`authorization.ReceiptSigner` boundary without loading a receipt private key
into `tos-edge` or a Worker. It sends exactly one request to a private local
Unix socket and never retries signing.

## Transport

- HTTP/1.1 or HTTP/2 over a local Unix stream socket.
- `POST /v1/receipt/sign`.
- `GET /healthz` returns the fixed startup identity
  `{"status":"ready","keyId":"...","publicKey":"..."}` and never signs or
  mutates key state. `publicKey` is the unpadded base64url encoding of the
  32-byte Ed25519 public key.
- Socket path must be absolute and clean.
- The socket directory must be a non-symlink directory owned by the current
  effective user with no group or other permissions.
- The socket must be owned by the current effective user, have socket type,
  and have no group or other permissions.
- Request timeout and request/response byte limits are mandatory and bounded.
- Active signing requests are limited by a fixed startup semaphore (default
  16, hard maximum 128); waiting callers honor cancellation and no background
  goroutine is created for them.
- Accepted live HTTP connections are independently capped at the same fixed
  value, so idle or partial same-user clients cannot create unbounded
  process-side connection state.
- Redirects are not followed and failed calls are not retried.

The JSON request is:

```json
{
  "version": "1",
  "payload": "base64-encoded canonical receipt CBOR",
  "issuedUnixMillis": 1800000000000,
  "expiresUnixMillis": 1800000060000
}
```

The response is the JSON representation of `identity.Envelope`. It must use
domain `tos.receipt.v1`, repeat the payload and exact millisecond validity
interval, contain a structurally valid nonce and Ed25519 signature encoding,
and fit the configured response limit. Duplicate keys, unknown fields,
trailing JSON, an incorrect media type, and any changed request material are
rejected.

The client intentionally cannot decide whether the returned key is currently
authorized. After signing, `VerifiedManifest.IssueReceipt` immediately
verifies the envelope with the exact current manifest key carrying the
`receipt` role and checks the original payment and quote binding. A sidecar
using a stale, wrong, or revoked key therefore cannot create an accepted
receipt.

## Included software sidecar

`cmd/tos-receipt-signer` implements this contract without opening a TCP
listener. It accepts an absolute socket path, a manifest receipt-role key ID,
and an absolute seed file containing one base64url-encoded 32-byte Ed25519
seed. The seed must be a current-user-owned, non-symlink, regular mode-0600
file in a current-user-owned private directory. The final file is opened with
`O_NOFOLLOW`; its content is bounded and seed buffers are cleared after key
expansion. The private key remains process memory, so this software baseline
does not claim HSM-grade extraction resistance.

The socket directory follows the same ownership and privacy rules. Startup
refuses to remove or replace an existing path, creates a mode-0600 Unix
socket, and performs graceful bounded shutdown. The daemon fixes the domain
and key ID at startup, strictly decodes bounded JSON, limits concurrent calls,
sets `no-store`, and does not log request bodies, payloads, keys, or
signatures.

Example (the operator creates both private directories first):

```sh
go run ./cmd/tos-receipt-signer \
  -socket /run/user/$(id -u)/tos-receipt-signer/signer.sock \
  -seed-file /etc/tos-protocol/receipt.seed \
  -key-id receipt-key-2026-08
```

Edge requires the socket and expected signer identity as one indivisible
startup policy:

```sh
tos-edge \
  -receipt-signer-socket /absolute/private/signer.sock \
  -receipt-signer-key-id receipt-key-2026-08 \
  -receipt-signer-public-key BASE64URL_ED25519_PUBLIC_KEY \
  # plus the required descriptor and catalog flags
```

It performs one bounded, no-retry health preflight before it opens the public
listener and includes signer availability in `/readyz`. Startup fails if the
reported key ID or public key differs from operator policy. A failed probe
returns only the stable `receipt-signer` component label; sidecar details are
not exposed. The identity probe prevents accidentally connecting Edge to the
wrong local sidecar, but it is not manifest authorization. Every signing
response must repeat the configured key ID and verify with the same startup
public key before it can leave the private client. It is then verified again
against the current manifest `receipt` role and revocation state. This second
check remains authoritative when a key is removed or revoked. Paid
invocation/receipt routes remain disabled and no public request can ask Edge
to sign merely because these flags are present.

## Sidecar requirements

A production sidecar must:

- hold only purpose-specific receipt keys, never wallet owner keys;
- select a key that is currently present in the service manifest with the
  `receipt` role;
- enforce the request and response limits independently;
- sign only the fixed receipt domain and never accept a caller-selected
  domain or key ID;
- avoid logging payloads, signatures, private keys, or raw request bodies;
- honor request cancellation and deadlines;
- expose no TCP listener;
- use an HSM, operating-system keystore, or a private mode-0600 key source
  according to deployment policy;
- support operational key rotation without retaining request-indexed state.

Rotation is deliberately fail closed and coordinated: provision the new
manifest receipt key, start a sidecar exposing that exact identity, and
restart Edge with the matching expected key ID and public key. Edge does not
silently accept a health identity change during process lifetime. Removing or
revoking the manifest key still invalidates its signatures even if the local
startup identity continues to match.

The software daemon closes the first deployable Edge-to-key-custody process
boundary. It does not provide HSM integration, automatic manifest-aware key
rotation, or a public receipt route.
