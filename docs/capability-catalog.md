# Derived Capability catalog

`pkg/capabilitycatalog` provides the bounded storage and validation core for
Gate E discovery. Its set of known Capability IDs is gateway-local and may be
incomplete. It never answers a listing from cached Native state: every returned
Capability is freshly resolved from finalized TOS state and checked against the
configured network and Registry code hash.

Providers publish the exact canonical software-work manifest CBOR with its
Capability ID. Admission resolves that Capability and requires an active
version whose version string and manifest digest match the bytes. The store
accepts only the deterministic CBOR representation, writes by SHA-256 digest,
and rejects alternate or corrupted bytes.

The catalog directory must be absolute, owner-owned, and mode `0700`. Records
are bounded owner-only regular files. A persistent per-Capability checkpoint
fence rejects finalized-state rollback and same-checkpoint conflicts. Listing
is deterministic, bounded to 100 discovered IDs per request, excludes a
freshly tombstoned Capability, and returns a continuation token that denotes
the last scanned ID rather than completeness.

The protobuf exposes this derived boundary as a separate
`CapabilityDiscoveryService`:

- `PublishSoftwareWorkManifest` admits manifest bytes only after finalized
  Capability verification;
- `ListCapabilities` returns freshly resolved typed Native states from an
  explicitly incomplete discovery set; and
- `SearchCapabilities` scans the local set in Capability-ID order, returning
  fresh finalized state and chain-selected version/digest separately from
  explicitly gateway-local manifest metadata and match score; and
- `GetSoftwareWorkManifest` retrieves immutable canonical CBOR by digest.

Consumers must compare retrieved manifest bytes with the exact digest in a
fresh Capability resolution or Accepted Quote. Discovery order, inclusion,
availability, and search ranking are never protocol facts.
