# Local GPU CDI execution closeout — 2026-08-02

Status: production code path and real-containerd MOCK device injection passed;
physical NVIDIA certification not run because this host has no NVIDIA device.

## Scope

This closeout covers the locally executable part of PG-06 and PG-07 after the
`tos-ai` containerd backend was connected to its exclusive GPU lease boundary.
It deliberately separates three evidence levels:

1. unit/fault tests of alias mapping, capacity and cleanup;
2. a real containerd/runc workload using a harmless MOCK CDI specification;
3. a physical NVIDIA CDI run, which requires a target GPU terminal and remains
   external to this host.

## Implemented boundary

The operator configuration fixes a privacy-safe alias-to-qualified-CDI map.
Remote Worker requests cannot provide an alias, CDI name, UUID, serial number,
device node or runtime endpoint. The fixed capability determines the device
count. Before OCI creation, the production factory leases distinct aliases,
translates only those aliases through the immutable local map, refreshes the
operator-owned CDI registry with background refresh disabled, and injects the exact
qualified devices. Unknown/duplicate devices, count mismatches, exhausted
capacity and CDI refresh/injection failures fail closed. Leases are released
synchronously after success, error, cancellation or panic.

## Automated results

The following commands passed on 2026-08-02:

```sh
go test -race -count=1 \
  ./pkg/executor/containerdbackend \
  ./executor/gpuisolation \
  ./internal/operatorconfig

go test -race -count=10 \
  ./pkg/executor/containerdbackend \
  ./executor/gpuisolation \
  ./internal/operatorconfig
```

Coverage includes defensive configuration copies, exact alias translation,
duplicate alias/CDI rejection, missing assignment, pool exhaustion, concurrent
lease exclusion, cancellation/panic release, and direct CDI-library edits to
an OCI specification.

The live run used the existing local containerd/runc installation, an isolated
test namespace, a preloaded digest-qualified BusyBox 1.36.1 image, an owner-
private socket/FIFO boundary, and an isolated temporary CDI directory. The
MOCK CDI device added a fixed environment marker and the harmless `/dev/null`
character device. Both of these tests passed:

```text
TestContainerdBackendLiveMockCDIConformance
TestContainerdBackendLiveConformance
```

The reusable lifecycle suite covered readiness, success, cancellation,
duplicate execution identity, bounded concurrency and synchronous cleanup.
After the run, inspection found no managed container, task or snapshot; the
temporary namespace, proxy socket, image record, CDI data and FIFO directory
were removed.

## Physical target gate

`tos-ai/scripts/run-nvidia-certification.sh` and `make
nvidia-certification` provide the exact physical test entry point. It requires
an operator-private containerd socket/namespace/FIFO directory, a preloaded
digest-qualified image, and one exact
`TOS_AI_CONTAINERD_TEST_NVIDIA_CDI_DEVICE`. It refuses to run without
`nvidia-smi` and a host-visible device. The container test must see exactly one
GPU and return `nvidia-cdi-ok` before the exclusive lease is released.

This host has neither an NVIDIA GPU nor `nvidia-smi`, so no physical result is
claimed. The MOCK-CDI run proves the production software plumbing through real
OCI execution; it does not prove NVIDIA driver compatibility, inference
performance, thermals, power behavior, cross-process ownership, or target-
kernel isolation.
