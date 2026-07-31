# Pinned ARD baseline

The bootstrap targets:

- ARD specification: `v0.9` Draft
- `ai-catalog.json` `specVersion`: `1.0`
- Registry OpenAPI document version: `0.5.0`
- reviewed upstream commit:
  `5fa2f5aef790b478319f6a3b43adf4661b0ed0e0`

Authoritative upstream:
<https://github.com/ards-project/ard-spec>

The upstream schemas are not copied into this repository yet. Before claiming
full conformance, CI must fetch this exact commit, verify its digest, and run
the upstream conformance tool against the publisher and Registry binaries.
Local validation in `pkg/ard` enforces the safety-relevant structural subset;
it is not a replacement for the authoritative JSON Schema.
