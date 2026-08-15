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

`pkg/gatewayfederation` composes two or more public catalog clients without a
shared database. It preserves source Gateway identity, validates the finalized
Capability envelope and selected active version, isolates malformed or
unavailable peers, and retrieves manifests only when the exact SHA-256 digest
matches. Its merged order remains a presentation detail, not consensus.

## Public-interface example

`cmd/tos-service-discovery` exercises the catalog exclusively through its
public Connect API. It has no catalog-directory flag and cannot edit gateway
storage. The bearer credential is read only from `TOS_SERVICE_TOKEN`, keeping
it out of shell history and process arguments.

After the provider SDK has finalized the Capability and written its reviewed
canonical CBOR, publish it through the relay-scoped endpoint:

```bash
export TOS_SERVICE_TOKEN='<relay token>'
go run ./cmd/tos-service-discovery publish \
  --gateway 'https://gateway.example' \
  --caller-id 'agent_<provider>' \
  --capability-id 'cap_<id>' \
  --manifest-cbor '/absolute/provider/publication/manifest.cbor' \
  --idempotency-key 'provider-publication-001'
```

Then switch to a read-scoped credential and discover or retrieve the same
digest without any operator database change:

```bash
export TOS_SERVICE_TOKEN='<read token>'
go run ./cmd/tos-service-discovery search \
  --gateway 'https://gateway.example' \
  --caller-id 'buyer-discovery' \
  --query 'deterministic test'

go run ./cmd/tos-service-discovery get \
  --gateway 'https://gateway.example' \
  --caller-id 'buyer-discovery' \
  --manifest-digest 'sha256:<digest>'
```

For loopback development only, use an `http://127.0.0.1` URL with
`--insecure`. Public use remains HTTPS by default. Search output places the
fresh finalized Registry envelope under `capability`; only manifest projection
and score appear under `gateway_local`.
