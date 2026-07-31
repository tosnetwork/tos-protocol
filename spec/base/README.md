# TOS Service Protocol v0.1 base package

This directory contains the draft normative base specification:

- [protocol.md](protocol.md) — roles, documents, flow, limits, and trust
  boundaries
- [canonical-encoding.md](canonical-encoding.md) — deterministic CBOR,
  commitments, and domain labels
- [authentication.md](authentication.md) — controller/runtime/session key
  hierarchy, replay, and bounded delegation
- [authorization-pipeline.md](authorization-pipeline.md) — fresh authority
  resolution, controller manifest verification, runtime roles, revocation,
  semantic validation, and Edge Core admission
- [session-authorization.md](session-authorization.md) — exact profile session
  grants, client-key resolution, signed delegation chains, and atomic
  cumulative budget admission
- [terminal-resources.md](terminal-resources.md) — privacy-preserving
  readiness, capacity, owner reservations, evidence, and quote limits
- [ard-handoff.md](ard-handoff.md) — ARD publisher provenance and safe
  transition to TOS controller authority
- [transport-http.md](transport-http.md) and
  [transport-rldp.md](transport-rldp.md) — transport-equivalent discovery and
  transaction bindings
- [payment-and-settlement.md](payment-and-settlement.md) — destination
  binding, chain observation, reorganization, refunds, and receipts
- [request-journal.md](request-journal.md) — atomic nonce/request admission,
  durable idempotency, request transitions, retention, and bounded crash
  recovery
- [private-worker-rpc.md](private-worker-rpc.md) — owned Unix-socket
  transport, bounded local RPC, response validation, priority separation, and
  retry ownership
- [versioning.md](versioning.md) — exact profile negotiation and critical
  extension behavior
- [errors.md](errors.md) — error codes and retry safety
- [security-considerations.md](security-considerations.md) — parser, state,
  transport, execution, and cleanup requirements
- `*.schema.json` — Draft 2020-12 machine-readable JSON contracts
- [test-vectors/canonical-v0.1.json](test-vectors/canonical-v0.1.json) —
  fixed positive and negative cross-language encoding vectors

The adjacent Go implementation is in `pkg/protocol`, `pkg/codec`, and
`pkg/identity`. CI compiles every schema, validates representative Go values,
checks unknown-field rejection, and verifies fixed canonical vectors.

This package is a draft foundation, not a complete network implementation.
Remote Registry crawling, authenticated public sessions, paid execution,
settlement reconciliation, transport profiles, terminal isolation, and
vertical conformance remain separate milestones.
