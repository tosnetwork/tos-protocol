# Security considerations

The protocol crosses public discovery, chain state, payment, local runtimes,
and potentially physical equipment. No single document is authoritative for
all of them.

## Required separations

- ARD and Registry results are untrusted discovery hints.
- A descriptor is not a live service manifest.
- A manifest capability claim is not admission or proof.
- A quote is not payment.
- Payment is not permission to violate owner, site, privacy, or safety policy.
- A receipt proves only what its signer, schema, digest, and evidence policy
  actually bind.

Clients MUST re-resolve controller and revocation authority, verify a fresh
manifest and runtime role, negotiate critical extensions, and bind session,
quote, authorization, execution, and receipt identifiers and revisions.

## Bounded state

Every connection, parser, redirect, lookup, federation edge, session, nonce,
idempotency record, quote, watcher, queue, stream, journal, artifact, log, and
cache needs a size, count, lifetime, and cleanup owner. Backpressure MUST occur
before expensive allocation or runtime dispatch. Failure, timeout,
cancellation, payment rejection, and restart paths MUST release RAM, disk,
accelerator memory, file descriptors, reservations, and watchers.

Do not allocate using a remote uint64 limit without checking it against a
smaller local policy and the host integer range.

## Parsing and transport

Reject unknown fields in security-sensitive typed values, duplicate JSON or
CBOR keys, floats, tags, indefinite CBOR, invalid UTF-8, excessive nesting,
oversized compressed bodies, and ambiguous value-or-reference objects.
Remote fetching requires SSRF controls covering DNS rebinding, redirects,
private/link-local ranges, URL credentials, decompression, content type,
timeouts, and total fan-out.

Transport encryption does not replace signed object verification. RLDP and
relay endpoints are subject to the same authority and replay checks as HTTPS.

## Keys and updates

Runtime and update keys are distinct. Rotation must overlap safely, honor
revocation, and fail closed for unknown critical policy. Private keys, wallet
keys, model credentials, and sensor credentials are never placed in ARD,
manifests, receipts, logs, or vertical worker payloads.

## Vertical execution

Profiles define isolation, cancellation, metering, privacy, and cleanup beyond
this base. A physical AI profile additionally requires disconnected local
operation, independent safety interlocks, signed model/update rollback,
real-time local priority, raw-I/O denial, and bounded fleet control. A generic
network authorization MUST NOT directly command an actuator.

This draft has not received an independent security audit and MUST NOT be
represented as production-ready.
