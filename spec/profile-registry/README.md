# TOS profile registry

This directory is the reviewable registry for stable TOS Service Protocol
profile and extension identifiers. Registration does not certify a product,
issuer, implementation, benchmark, evidence claim, or regulatory status.

A registration MUST include:

- globally unique identifier and maintainer
- current semantic version and required base versions
- normative schema and canonical test-vector digests
- operations, events, legal state transitions, and terminal states
- quote, receipt, evidence, and discovery mappings
- critical extensions and unknown-extension behavior
- maximum sizes, timeouts, resource dimensions, and cleanup rules
- privacy, retention, provenance, license, and evidence semantics
- compatibility, deprecation, and migration policy

The `tos.ai.*` namespace is owned by the `tos-ai` repository. AI profile
schemas and business logic are deliberately not copied into this base
repository.
