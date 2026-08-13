# ATOS Phase 4D production admission

The normative contract is
[`atos-spec/docs/PHASE4D_PRODUCTION_GATE.md`](https://github.com/tosnetwork/atos-spec/blob/main/docs/PHASE4D_PRODUCTION_GATE.md).
This repository provides the read-only gate implementation.

## Run

Prepare a root/operator-controlled manifest from
`examples/phase4d-production-gate.example.json`. Replace every placeholder;
the example deliberately cannot pass unchanged. Keep the manifest free of
bearer tokens and private keys. Put the read-only verifier token in a separate
owner-only file.

For a production run the manifest file and every parent directory must be
root-owned, non-symlink and non-group/world-writable. The loopback flag relaxes
root ownership only for local acceptance and cannot enable remote plaintext.

```sh
tos-phase4d-gate \
  --manifest /etc/tos/phase4d-production-gate.json \
  --protocol-token-file /run/secrets/tos-proof-observer-token
```

The command prints one JSON report. Exit code `0` means every check passed,
`1` means a gate check failed, and `2` means configuration or local execution
was invalid. `--allow-loopback` exists only for local acceptance; it does not
permit plaintext traffic to a remote host.

The gate has no chain publisher, TaskEscrow publisher or economic mutation
client. A proof check uses only the read-only protocol observer.

## Evidence preparation

The evidence producer writes the strict evidence JSON (see
`examples/phase4d-evidence.example.json`), computes its SHA-256
and signs the exact deployment-bound message
defined in the normative contract. Signing should use the separately governed
audit/release key. Make the evidence files read-only before running the gate.
The manifest is the trust root for the evidence public key and must be reviewed
through the production configuration/change-control process.

Evidence must cover, at minimum:

- current reconciliation with no unresolved Verified operation;
- backup completion and independently verified retained copies;
- a restore into an isolated environment with data/proof checks;
- a failover/incident drill with detected outage, fail-closed behavior,
  recovery and post-incident reconciliation;
- each production key ceremony, including identity, purpose, access policy,
  rotation/revocation and unavailable-key behavior.

## Rollout sequence

1. Deploy protocol replicas and verify `/readyz` on each.
2. Deploy ATOS replicas and verify `/readyz` on each.
3. Exercise one external-client Verified transaction to a finalized outcome.
4. Retrieve the canonical portable proof from a different ATOS replica.
5. Generate current reconciliation, custody and DR evidence.
6. Run the gate from an independent verification host.
7. Admit traffic only after a passing report; remove a deployment from service
   when a required live check or evidence freshness window no longer passes.

Do not commit production manifests, bearer tokens, private keys or production
evidence into this repository.
