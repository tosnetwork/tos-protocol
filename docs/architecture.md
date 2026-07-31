# Bootstrap architecture

This bootstrap turns the repository boundary in the TOS design documents into
code without claiming that the full protocol is implemented.

```text
Internet
   |
   | HTTPS / TOS Sites (discovery only in bootstrap)
   v
tos-edge ------------------> TOS chain adapter
   |
   | private versioned ConnectRPC, Unix socket 0600
   v
vertical worker (for example tos-ai-worker)
   |
   +--> bounded scheduler
   +--> approved runtime adapter
   +--> isolated executor (next milestone)
```

The public process must eventually enforce authentication, signed live quotes,
payment authorization, invocation binding, receipt signing, bounded replay,
and settlement before it forwards paid work. Those operations are absent from
the bootstrap public server, so it exposes no invocation route.

## Dependency decisions

| Concern | Baseline | Bootstrap status |
|---|---|---|
| Language | Go 1.24+ | implemented |
| Local process API | ConnectRPC + Protobuf | implemented |
| Public discovery | ARD v0.9 Draft | structural model and bounded Registry implemented |
| Distributed Registry backend | AGNTCY Directory | adapter planned; no fork |
| Chain access | TOS JSON-RPC/lite APIs | bounded generic JSON-RPC client and interface implemented |
| Policy | OPA | adapter planned after policy vocabulary is normative |
| Workload identity | SPIFFE | adapter planned |
| Artifacts | ORAS + Cosign + TUF | interfaces planned; AI repository starts manifest verification |

The Registry accepts only local operator-approved catalogs in this milestone.
Remote crawling is withheld until DNS rebinding, redirect, IP range,
decompression, recursion, federation, retry, and per-publisher limits are all
enforced.
