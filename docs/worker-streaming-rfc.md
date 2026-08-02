# Worker result streaming RFC

Status: implemented local v0.2 candidate; separate from the v0.1 wire contract

## Decision

WorkerService v0.1 remains unary. `WorkerStreamService` is a separate v0.2
service, so adding it does not change the v0.1 handler interface. Streaming cannot be represented safely by
adding an unstructured bytes field or by repeatedly invoking the unary RPC.
Implementations must return one bounded final result until this RFC is
approved and implemented end to end.

## Required wire semantics

The implemented streaming methods enforce:

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

## Implemented recovery and settlement rule

`InvokeStream` enters the existing durable Invoke state machine exactly once.
The worker completes and retains the bounded result before emitting chunks;
therefore these are provisional transport chunks, not independently billable
token events. A client disconnect does not cancel or duplicate that execution.
`ResumeStream` reads only the retained task, and requires its exact request,
task and request-digest binding, next sequence, byte offset, and final stream
digest.

The stream digest is SHA-256 over the complete concatenated output. The final
event repeats the durable completion time, model/runtime revisions and final
usage. The validated client reconstructs the bounded output and returns the
same opaque `ValidatedInvocation` used by unary Invoke. Existing Receipt
issuance therefore binds the final output digest and usage; partial chunks can
never produce a Receipt.

Connect server-stream sends provide receiver-driven transport backpressure.
No server-side chunk list, waiter map, retry map or resume map is retained.
The only retained object is the already bounded task result in the existing
quota-controlled task store.

## Acceptance evidence

The protobuf service, private-client validation, durable worker integration,
receipt rule and cross-repository Connect/Unix-socket tests are implemented.
Fault tests reject duplicate/missing offsets, reordered sequences, binding and
digest conflicts, oversized chunks, nonterminal disconnects and incorrect
resume prefixes. The feature remains v0.2 and is not promoted into v0.1.
