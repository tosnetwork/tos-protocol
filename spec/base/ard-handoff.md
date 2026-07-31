# ARD to TOS handoff

ARD is the protocol-neutral public discovery layer. A TOS service entry uses
the exact media type:

```text
application/vnd.tos.service+json
```

and contains exactly one ARD `url` or embedded `data` value. Public URL
handoffs require HTTPS. The reference structural implementation is
`pkg/ard.ParseServiceHandoff`.

## Authority separation

ARD publisher identity and TOS service authority are separate:

1. verify the `urn:air` publisher component using the pinned ARD trust model
2. retain the catalog URL, publisher, Registry source, and all derived-field
   provenance
3. fetch or decode the TOS descriptor under bounded parsing and fetch policy
4. require the descriptor's `ardIdentifier` to equal the selected ARD entry
5. resolve the expected TOS controller through an approved chain or local
   policy
6. verify the controller-signed operational manifest and runtime key
7. obtain a fresh live quote before payment or execution

The back-reference prevents accidental entry substitution. It does not prove
that the ARD FQDN and TOS controller are owned by the same legal or physical
party. Clients display both identities and their evidence.

`name.tos` and a raw ADNL address may appear as signed TOS metadata, but neither
is conventional ARD FQDN proof. An operator without public DNS uses an
approved HTTPS gateway namespace or a private Registry with an explicit
`.tos` trust policy.

## Fetch policy

A Registry or client fetching a descriptor MUST bound total bytes, redirects,
DNS answers, resolution time, response time, decompression, nested references,
concurrent fetches, retries, and cache lifetime. It MUST reject URL
credentials, fragments, unsupported schemes, private/link-local destinations
unless explicitly approved, and DNS rebinding across every redirect.

Registry health, price, availability, ranking, inferred tags, or evidence
labels remain advisory and retain source provenance. They are never copied
into a controller-signed manifest or quote as if the provider signed them.
