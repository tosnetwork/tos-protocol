# Versioning and extensions

The base wire version is `0.1`. A change that alters field meaning, canonical
encoding, signature input, authority, required state transition, or security
property requires a new base version.

Profile versions use canonical `MAJOR.MINOR.PATCH` numbers with no leading
zeros, prerelease labels, or build metadata in v0.1. Negotiation selects the
highest exact version present in both the client and service lists. It does
not infer compatibility from a shared major version.

An extension has an identifier, content digest, optional HTTPS definition,
and `critical` flag:

- unknown advisory extensions MAY be ignored but MUST be preserved when a
  signed object is relayed unchanged
- an unknown critical extension MUST abort negotiation before quote,
  authorization, or execution
- an implementation MUST NOT remove an unknown critical field and then verify
  or re-sign the remaining object

Profile and extension identifiers MUST never be reassigned to incompatible
semantics. A profile registration records its owner, schemas, canonical test
vectors, base-version requirements, operations, error mappings, limits,
privacy classes, and migration policy.

Old manifests and quotes remain governed by the exact revisions they signed.
An update MUST NOT retroactively change their interpretation.
