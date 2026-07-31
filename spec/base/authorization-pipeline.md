# Manifest-backed authorization pipeline

The reference authorization boundary is implemented in `pkg/authorization`.
It connects current TOS service authority to Edge Core admission without
treating discovery or transport identity as authorization.

```text
approved chain or local policy resolver
             |
             v
fresh AuthoritySnapshot
  controller key + current manifest digest + revoked runtime keys
             |
             v
controller-signed canonical ServiceManifest
             |
             v
current runtime key + required role + exact domain
             |
             v
canonical runtime envelope + semantic payload validation
             |
             v
AuthorizedEnvelope bound to session / operation / request / intent
             |
             v
Edge Core atomic nonce + request-journal admission
```

## Authority snapshot

An authority resolver is a security-sensitive adapter backed by an approved
TOS chain view or an explicit local trust policy. Its result includes:

- active status, network, service ID, and current controller
- the controller Ed25519 public key
- the canonical `tos.manifest.v1` digest currently registered for the service
- a bounded set of revoked runtime key IDs
- the observed masterchain sequence and observation time

The verifier rejects inactive, stale, excessively future-dated, malformed, or
oversized results. The default maximum snapshot age is five minutes and is
operator-configurable only within the implementation ceiling. ARD, DNS,
HTTPS, RLDP, relays, and Registry entries cannot act as authority resolvers.

The Go reference `ChainResolver` additionally requires an exact local
contract-code-hash allowlist, a bounded query timeout, response/reference
matching, and finalized state by default. A caller may carry its last accepted
masterchain sequence as `MinimumMasterSeqno`; an older response is rejected
without adding a process-global service cache. Returned public keys and
revocation sets are defensively copied and remain bounded by authorization
policy.

The current TOS chain exposes the required facts through more than one
component: Service Actor or Capability Registry state supplies active status
and metadata commitments, while the current manifest-signing controller key
may belong to an Agent Account or another explicitly approved authority.
Production adapters must compose and verify those sources. The Service
Actor's optional response-attestor key is not silently reinterpreted as the
manifest controller key.

## Manifest verification

The controller envelope MUST:

1. use the exact `tos.manifest.v1` domain
2. name the current controller as its key ID
3. verify under the resolved controller public key
4. contain canonical CBOR that decodes strictly as `ServiceManifest`
5. bind the resolved network, service ID, and controller
6. hash to the current registered manifest digest
7. cover the complete validity interval declared by the manifest

A signed envelope carries millisecond timestamps, so containment comparisons
normalize manifest and runtime-key boundaries to that same precision.

A controller rotation or manifest replacement therefore invalidates an old
manifest even when its original signature and local expiry remain valid.

## Runtime envelope verification

The runtime envelope MUST use a key present in the verified manifest. The key
must not be revoked, must contain the required role, and must be active at
verification time. The envelope signature uses the exact expected domain, and
its issue and expiry times must remain inside the runtime-key interval.

The payload must be canonical CBOR before any application callback runs. A
message-specific validator then checks its typed semantics, profile policy,
and request bindings. A nil or failed semantic validator never produces an
authorization result.

## Admission binding

The successful result is an opaque `AuthorizedEnvelope`. It records:

- network, service ID, and runtime authority
- session ID, operation, request ID, and request-intent digest
- the verified signed envelope
- the earliest authority, manifest, runtime-key, or envelope deadline

Edge Core rechecks every binding and deadline before atomically claiming the
nonce and creating or replaying the request journal record. A zero value,
expired result, altered scope, altered intent, or result copied to another
request is rejected before durable state changes.

## Revalidation and recovery

Authorization is not a permanent capability. New requests require a fresh
enough authority snapshot. Restart recovery of nonterminal journal records
must re-resolve current controller, manifest replacement, runtime-key
revocation, payment, and local policy before continuing.

This library does not by itself enable a public session or invocation route.
The bootstrap server still exposes discovery only. A production route must
wire a real authority resolver, typed payload policy, the concrete TOS payment
adapter and watcher schedule, profile-specific Worker mapping, execution
isolation, production receipt key custody, failure policy, and authenticated
receipt delivery.

Runtime requests such as quotes and receipts can use the opaque
`AuthorizedEnvelope` path directly. Client actions additionally require a
runtime-signed session grant, fresh client or delegated keys, and atomic
cumulative usage admission. That continuation is specified in
[session-authorization.md](session-authorization.md).

Quotes and payment authorizations use a narrower typed continuation: the
quote must be signed by a current `quote` runtime key and match the current
manifest/session; the client authorization must bind the exact destination
and cannot expand session/delegation budgets. A strict observer then requires
an exact, fresh, high-water, final chain response before producing another
opaque result. See [payment-observation.md](payment-observation.md).

Receipts use another typed continuation. The current manifest key must have
the `receipt` role, and the canonical signed receipt must validate against the
original opaque quote/payment authorization. The opaque result repeats the
complete request, quote, authorization, revisions, charge, usage, and signed
envelope binding immediately before atomic terminal persistence.

For successful private Worker calls, the reference continues this boundary
without exposing raw response objects: an opaque validated result retains its
request binding, limits, deadline, usage, revisions, completion time, and
output. Edge Core requires the corresponding paid request to remain running,
constructs only payment-bound canonical receipt bytes, delegates signing to a
purpose-specific custody interface, and immediately runs the normal manifest
receipt verifier before persistence.

The same issuer handles non-success without trusting arbitrary error objects.
It accepts only `failed`, `canceled`, or `timed_out`, emits zero charge, an
empty usage array and no result digest, and derives the durable error code from
that status. Timeout is rejected before the quote deadline. This is the base
fail-closed policy; profiles may specify a separately reviewed partial-work
and refund policy.
