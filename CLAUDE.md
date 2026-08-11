# Testing Lessons Shared Across the TOS Repos

This file tracks recurring bug classes found across the TOS stack
(`atos`, `tos-protocol`, `tos`, `atos-spec`) whose lesson generalizes beyond
the single repo they were found in — kept here so this repo's own future
work builds the practice in from the start rather than rediscovering it.
The canonical, more detailed log lives in `atos/CLAUDE.md` (Phase 4A's
10-round review retrospective); this file mirrors only the entries relevant
to `tos-protocol`'s own surface (canonicalization/`pkg/codec`, atomic reads
over its own stores) plus anything found directly in this repo.

## 1. Hardcoded golden/vector test values transcribed incorrectly at commit time

Found in `atos/internal/financial`'s V2 batch golden CBOR test vector, but
directly relevant here since `tos-protocol` owns the canonicalization engine
(`pkg/codec.Marshal`/`Digest`) that produces every such vector across the
stack. The vector was wrong from the moment it was hardcoded — reproducing
the test at the exact commit that set it showed it never matched the code's
own output, which is stable and deterministic across repeated runs. Not a
later regression; a transcription error at commit time that nothing caught
because the test only ever compares against itself.

**Root cause:** whoever wrote the vector most likely computed or copied it
by hand (or from a slightly different run) instead of pasting in the exact
string the test itself printed on a passing run.

**Practice:** never hand-write a golden/vector expected value for anything
that goes through `pkg/codec` (or any other deterministic-encoding path in
this repo). Run the code, capture its actual printed/logged output, and
paste that in verbatim. When a "vector changed" assertion starts failing,
don't assume the vector was ever correct — reproduce the failure at the
exact commit that last touched the vector before concluding something
regressed after it.

## 2. Two independently-locked reads composed to test (or serve) one atomic write

Found in `atos/internal/service`'s dispute-resolution test suite, but the
lesson applies to any of `tos-protocol`'s own store-backed RPCs that write
more than one row/field together (e.g. identity-binding operations,
capability manifest + ownership projections, signer-authorization state):
a test (or a real caller) polled two related pieces of state via two
separate, independently-locked `Get`-style calls. The underlying write of
both was atomic, but two independent reads are never atomic with respect to
each other regardless of how well-locked the write is — the writer's entire
critical section can land completely between the two reads. This produced
an observable torn state in roughly 15-20% of runs in the case where it was
found.

**Root cause:** an atomic multi-field/multi-row write does not make two
*separately locked* reads of that state atomic with each other. This is a
structural property, not something a faster or better-implemented write can
fix.

**Practice:** whenever a test (or a real caller) needs a consistent view of
two-or-more fields/rows that one write updates together, provide and use a
genuinely combined atomic read (one critical section, or one `REPEATABLE
READ` transaction so every `SELECT` inside it sees one snapshot) — never
compose two independently locked reads and assume the pair is consistent.
