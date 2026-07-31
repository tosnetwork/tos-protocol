# Worker result streaming RFC

Status: proposed for v0.2; intentionally absent from the v0.1 wire contract

## Decision

WorkerService v0.1 remains unary. Streaming cannot be represented safely by
adding an unstructured bytes field or by repeatedly invoking the unary RPC.
Implementations must return one bounded final result until this RFC is
approved and implemented end to end.

## Required wire semantics

A future streaming method must specify at least:

- an immutable request ID, task ID, request digest, quote, model revision, and
  runtime revision binding for the entire stream;
- monotonically increasing chunk sequence numbers starting at zero;
- a bounded chunk size, bounded total output, bounded buffered bytes, and
  explicit transport backpressure;
- whether chunks are provisional display data or independently chargeable
  partial results;
- one terminal success, failure, cancellation, or timeout state;
- deadline propagation and cancellation acknowledgement;
- behavior after disconnect, including a bounded resume cursor and retention;
- duplicate, missing, reordered, and conflicting chunk rejection;
- idempotent recovery that never starts a second model execution;
- final usage accounting and a digest committing to the ordered chunk stream;
  and
- receipt rules that bind final usage, output digest, and terminal status.

## Safety constraints

The receiver must control demand. Neither endpoint may allocate memory in
proportion to an untrusted declared chunk count or hold an unbounded waiter,
chunk, retry, or resume map. Partial output must never be treated as final
success, and a transport close is not a terminal task result.

Cancellation acceptance remains nonterminal until a later authenticated task
observation. Resume cannot mean re-execute. If the worker cannot prove that a
cursor belongs to the same retained task and output commitment, it must fail
closed.

## Work needed before acceptance

The protocol change requires protobuf design, private-client validation,
durable worker storage, Edge journal integration, settlement rules, and
fault-injection tests covering disconnect at every chunk boundary. It may be
promoted into v0.1 only through an explicit compatibility review before the
v0.1 tag; otherwise it remains a v0.2 feature.

