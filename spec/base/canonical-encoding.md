# Canonical encoding and commitments

Public TOS Service Protocol documents use UTF-8 JSON. Signatures, hashes, and
cross-language commitments use RFC 8949 Core Deterministic CBOR over the
equivalent constrained JSON data model.

## Data model

Version 0.1 permits:

- null, booleans, UTF-8 strings
- signed 64-bit and unsigned 64-bit integers
- arrays
- maps whose keys are strings

It forbids floating-point values, byte strings in a typed protocol value,
non-string map keys, tags, indefinite-length objects, duplicate map keys,
invalid UTF-8, and non-shortest encodings. Implementations MUST enforce the
size, nesting, collection, and total-item limits before application use.

JSON numbers containing a decimal point or exponent are invalid, even if their
mathematical value is integral. Binary data in a protocol schema is encoded as
an explicitly specified base64url string.

Time fields are RFC 3339 strings. Producers SHOULD emit UTC with `Z` and the
minimum fractional precision needed. A verifier signs and compares the exact
string value; it MUST NOT silently rewrite an already signed timestamp.

## Algorithm

1. Validate the typed value and its JSON Schema.
2. Convert it to the constrained JSON data model without converting integers
   through IEEE-754.
3. Encode it with RFC 8949 Core Deterministic CBOR.
4. Reject the value if decoding and deterministic re-encoding does not produce
   exactly the received bytes.

The reference implementation is `pkg/codec`. Fixed positive and negative
vectors are in `test-vectors/canonical-v0.1.json`.

## Commitment hash

The v0.1 commitment is:

```text
SHA-256(
  UTF8("TOS-PROTOCOL-CBOR") ||
  0x00 ||
  uint16_be(len(domain)) ||
  UTF8(domain) ||
  canonical_cbor(value)
)
```

A domain is a lowercase, bounded `tos.*` label. Implementations MUST use the
message's registered domain and MUST NOT reuse a signature or commitment under
another domain.

Initial labels are:

| Value | Domain |
|---|---|
| service descriptor | `tos.descriptor.v1` |
| service manifest | `tos.manifest.v1` |
| terminal manifest | `tos.terminal-manifest.v1` |
| session grant | `tos.session.v1` |
| delegation | `tos.delegation.v1` |
| profile request intent | `tos.request-intent.v1` |
| quote | `tos.quote.v1` |
| payment authorization | `tos.payment-authorization.v1` |
| receipt | `tos.receipt.v1` |
| evidence bundle | `tos.evidence.v1` |
| private Worker task identity | `tos.private-worker-task.v1` |
| execution receipt identity | `tos.execution-receipt-id.v1` |

The profile request-intent commitment is the deterministic CBOR encoding of
`version`, `profileId`, `profileVersion`, the sorted negotiated
`profileExtensions`, `operation`, and the exact opaque `payload` bytes. The
profile ID comes from the quote, while the negotiated version and extensions
come from its runtime-signed session. A quote MUST use this digest for an
execution path that uses the generic Edge mapping boundary. This prevents the
same bytes from being replayed under another profile version, extension set,
or operation. The vertical profile still owns canonical decoding and semantic
validation of its opaque payload.

The private Worker task identity additionally commits the network, service,
profile, session, operation, request, intent, authorization, and quote IDs.
Edge renders the resulting SHA-256 value as `task-` followed by 64 lowercase
hex digits. This identifier is internal recovery state, not a public request
intent or payment commitment.

The execution receipt identity commits the version, network, service, request,
private Worker task ID and request digest, payment authorization ID, and quote
ID. Edge renders it as `receipt-` followed by 64 lowercase hexadecimal digits.
It deliberately excludes outcome fields: an inconsistent second terminal
observation for the same durable execution must conflict with the first rather
than acquire a different receipt ID.

## Signed envelope

`pkg/identity` signs an envelope containing the version, domain, key ID,
millisecond timestamps, a random 128-bit nonce, and SHA-256 of the canonical
payload. The envelope format itself uses explicit length prefixes. In its JSON
representation, `nonce` and `signature` are unpadded base64url; `payload` is
standard padded base64, matching Go's JSON representation for `[]byte`.
Envelope verification and canonical payload decoding are both required.
