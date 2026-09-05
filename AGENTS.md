# Working on tos-service-protocol

## Instruments lie by staying silent

A measurement that returns nothing is not an answer. Before trusting silence,
prove the instrument speaks.

This repository defines a wire boundary. Its failure mode is not a crash — it is
two implementations that both believe they agree, and a test suite that agrees
with whichever one it was generated from.

### A test that cannot fail is not evidence

Before believing a new test, **remove the thing it tests and watch it go red.**
If it stays green, it is measuring nothing.

Codec tests are the worst offenders: encode-then-decode round-trips pass for
every encoding, including a wrong one, as long as the same code does both
halves. A round-trip proves self-consistency, never conformance.

### Golden vectors that regenerate on mismatch test nothing

A golden test that rewrites its expected file when the bytes differ will agree
with any change you make, forever, silently. It is worse than no test, because
it reports coverage it does not have.

Goldens are regenerated **deliberately**, in their own commit, with the diff
read line by line. If a golden moved and you did not intend it to move, that is
the finding — do not accept it and continue.

### Cross-language agreement is the property; one language is not

The frozen contracts here require Go, Rust and FunC to produce identical bytes
for the same logical value. A Go test that passes proves Go agrees with Go.
Until a vector has been checked against the other implementations, "the codec
is correct" is a statement about one implementation's opinion of itself.

The failure this prevents is specific and nasty: a canonical-encoding
divergence does not look like a codec bug in production. It looks like a quorum
that never forms, or a signature that never verifies — a liveness symptom with
a serialization cause, and it is expensive to diagnose from that end.

### Local traps

**A field added to a struct is a wire change.** Adding, reordering or widening a
field changes the digest of everything containing it. Old entries' fields,
order, domain separators and golden bytes must stay byte-for-byte unchanged;
new semantics get a new entry version, never an edit to an existing one.

**Unknown input must fail closed, and that must be tested.** An unknown kind,
an unknown version, a trailing byte, an extra ref — each needs a test asserting
rejection. A parser that ignores what it does not understand will accept an
attacker's addendum just as happily as a future version's.

**Skipped tests are silent holes.** Anything gated on a fixture, a network, or
a sibling repository skips when absent and leaves the run green. Where a suite
is meant to be authoritative, make the missing dependency an error.

## Conventions

- One protocol, one authority model: finalized typed state in a TOS account.
  Off-chain databases and exchange encodings are caches and projections, never
  authority.
- Errors are handled explicitly and carry enough context to act on.
- Do not reference external project names or issue trackers in comments or
  commit messages. Comments explain intent, not history.

`CLAUDE.md` is a symlink to this file, so Codex and Claude Code read the same
instructions.
