# Local host engineering closeout — 2026-08-02

Status: passed for the locally executable non-streaming v0.1 engineering
scope; external deployment certification remains open.

This report records the final local coding, MOCK, packaging, update and real
CPU-runtime work performed after the 2026-08-01 closure matrix. The candidate
source is the `tos-protocol` and `tos-ai` commit that contains this report and
the corresponding roadmap updates. Development started from:

- `tos-protocol` `77cbbcbf0cfe7551df6dcf4e9af28c9c74dc292d`;
- `tos-ai` `06a0a08b64fa284731cad648cab8d89deee58779`.

The host was Linux `6.8.0-124-generic` x86-64 with Go `1.24.0`, containerd
`2.2.1`, and runc `1.3.4`. No NVIDIA device or `nvidia-smi` was available.

## Closed local items

### Deterministic release artifacts

Both repositories now build complete deterministic tar/gzip release bundles.
The bundles contain all repository commands, release metadata, the GPL license
and the applicable normative specifications or deployment material. Every
regular file is covered by an internal SHA-256 manifest and the compressed
bundle has an external SHA-256 record.

The verifier enforces compressed-size and entry-count ceilings, safe relative
paths, one top-level directory, regular-file/directory-only entries, no
duplicate paths, a safe complete checksum manifest, every internal digest, and
an optional detached Ed25519 signature. The gate builds twice and requires
byte identity, accepts a valid ephemeral signature, and rejects a changed
signature, an unchecksummed file and a symbolic-link entry.

### Software release lifecycle

`tos-ai/pkg/softwareupdate` implements exactly two private release slots. It
verifies the existing signed update manifest and artifact stream, stages only
to the inactive slot, fsyncs atomic state, bounds state and manifest reads,
cleans interrupted temporary files, and advances the security revision only
after candidate health confirmation.

The restart protocol distinguishes the first intended candidate boot from a
candidate crash: the first opener after activation receives a durable health
window; a subsequent opener without confirmation automatically returns to the
last known-good slot. The staging process cannot confirm its own candidate.
Tests cover first install, repeated replacement, manual and automatic rollback,
power loss, anti-rollback, cancellation, concurrent staging, exclusive
ownership, residue cleanup and artifact tampering.

### Administrator control and history

`tos-ai/pkg/admincontrol` verifies canonical, domain-separated Ed25519
activation, health-confirmation and rollback envelopes. Commands bind an exact
terminal, command identifier, action, validity window and expected active slot.
The mode-`0600` bbolt journal is exclusively owned and count-, byte- and
retention-bounded. Exact retries return the durable result; identifier
conflicts, panics and uncertain post-claim crash outcomes never re-execute. A
newest-first bounded history view contains no payload, key, signature,
fingerprint or raw error.

Race tests cover authentication failures, terminal and state binding, exact
concurrent replay, restart replay, failure and panic replay, uncertain outcome,
capacity reclamation, file permissions, lock contention, history bounds, and a
full controller-to-real-two-slot-manager activation/boot/confirmation flow.

### Real containerd CPU lifecycle

The opt-in `TestContainerdBackendLiveConformance` suite ran against the host's
real containerd/runc with a dedicated private socket bind, namespace, FIFO
directory and digest-qualified BusyBox `1.36.1` fixture. All subtests passed:

- readiness;
- successful execution and cleanup;
- cancellation and cleanup;
- duplicate execution identity rejection;
- concurrent execution and cleanup.

This run found and fixed a real SDK composition defect: the OCI spec was being
created before a runnable snapshot, and a read-only snapshot view was then used
for a task. The corrected order creates a private writable snapshot before the
spec while retaining `root.readonly` in the OCI contract. The test namespace,
image references, snapshot/content data, socket mount and runtime directories
were removed after the clean run.

This result is real local runtime evidence. It is not target-kernel, LSM,
reboot, adversarial-resource, or NVIDIA device-isolation certification.

### NVIDIA-dependent behavior

Because the host has no NVIDIA device, only deterministic MOCK claims were
closed. Existing fake NVML and Worker tests cover locally observed GPU/VRAM
projection, temperature and power degradation, invalid/exhausted VRAM,
device-loss admission shutdown, retained-result availability while degraded,
recovery, and zero resource leakage. The CPU containerd backend continues to
reject GPU requests. No test in this report claims that a real GPU was assigned
exclusively or hidden from an unassigned workload.

## Commands and results

The final candidate passed:

```sh
cd /home/tomi/tos-protocol && make local-gates
cd /home/tomi/tos-ai && make local-gates
cd /home/tomi/tos-ai && go test -race -count=20 \
  ./pkg/softwareupdate ./pkg/admincontrol
```

`make local-gates` includes format, vet, full repository race tests,
byte-identical command builds, deterministic release bundle/signature/tamper
tests, and rejects module/workspace substitution through the existing
independent-module gates. The only compiler output of note was deprecation
warnings emitted by the pinned NVIDIA NVML C headers; tests and vet passed.

## Remaining boundary

The local engineering work does not create a signed v0.1 tag, conduct an
offline release-key or production key-custody ceremony, choose a public
authentication policy, install on the selected NVIDIA terminal, certify GPU
device isolation, run a target-host reboot/disk-full/long-duration soak, expose
an administrator listener, or approve a release. Those are deliberately kept
in the canonical production-gate ledger as deployment or external evidence.

Streaming v0.2, remote ARD federation, additional runtime activators, physical
actuator safety and fleet control are later versioned milestones, not missing
non-streaming v0.1 local gates.
