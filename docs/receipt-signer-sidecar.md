# Quote and receipt signer sidecar contract

Status: bounded purpose-fixed clients and software-key sidecars implemented;
receipt identity-bound Edge startup wiring is implemented. HSM integration,
quote-route composition, key rotation orchestration, and
deployment remain operator responsibilities.

`pkg/localrpc.ReceiptSignerClient` and `QuoteSignerClient` implement the Edge
`authorization.ReceiptSigner` and `QuoteSigner` boundaries without loading
either private key into `tos-edge` or a Worker. Each sends exactly one request
to its own private local Unix socket and never retries signing.

## Transport

- HTTP/1.1 or HTTP/2 over a local Unix stream socket.
- `POST /v1/receipt/sign` for a receipt-only daemon, or
  `POST /v1/quote/sign` for a quote-only daemon. One process never exposes
  both operations.
- `GET /healthz` returns the fixed startup identity
  `{"status":"ready","keyId":"...","publicKey":"...","domain":"...","path":"..."}`
  and never signs or mutates key state. The client requires the exact purpose
  domain and path as well as the key identity. `publicKey` is the unpadded
  base64url encoding of the 32-byte Ed25519 public key.
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
the daemon's fixed `tos.receipt.v1` or `tos.quote.v1` domain, repeat the payload and exact millisecond validity
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

`cmd/tos-receipt-signer` and `cmd/tos-quote-signer` implement this contract
without opening a TCP listener. Each accepts an absolute socket path, the
matching manifest role key ID,
and an absolute seed file containing one base64url-encoded 32-byte Ed25519
seed. The seed must be a current-user-owned, non-symlink, regular mode-0600
file in a current-user-owned private directory. The final file is opened with
`O_NOFOLLOW`; its content is bounded and seed buffers are cleared after key
expansion. The private key remains process memory, so this software baseline
does not claim HSM-grade extraction resistance.

The socket directory follows the same ownership and privacy rules. Startup
refuses to remove or replace an existing path, creates a mode-0600 Unix
socket, and performs graceful bounded shutdown. Each daemon fixes one domain,
path, and key ID at startup, strictly decodes bounded JSON, limits concurrent calls,
sets `no-store`, and does not log request bodies, payloads, keys, or
signatures. Graceful shutdown stops new signatures, waits for an active
signature to leave the key critical section, clears the in-process software
private-key buffer, and permanently marks the handler unavailable. Process
memory and language/runtime copies still do not provide HSM-grade erasure.
The Edge-side client is also explicitly closed: it rejects new calls, cancels
active bounded Unix-socket requests, waits for them to return, and closes idle
HTTP transports before Edge exits.

Example (the operator creates both private directories first):

```sh
go run ./cmd/tos-receipt-signer \
  -socket /run/user/$(id -u)/tos-receipt-signer/signer.sock \
  -seed-file /etc/tos-protocol/receipt.seed \
  -key-id receipt-key-2026-08

go run ./cmd/tos-quote-signer \
  -socket /run/user/$(id -u)/tos-quote-signer/signer.sock \
  -seed-file /etc/tos-protocol/quote.seed \
  -key-id quote-key-2026-08
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

A production purpose signer must:

- hold only one purpose-specific quote or receipt key, never wallet owner keys;
- select a key that is currently present in the service manifest with the
  matching `quote` or `receipt` role;
- enforce the request and response limits independently;
- sign only its fixed quote or receipt domain and never accept a caller-selected
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
