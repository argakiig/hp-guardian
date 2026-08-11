# Implementation Plan: Policy Simulator and Trace Format

## Architecture

Add a runtime-private parsed simulation policy that retains a validated engine
and SHA-256 identity. A pure simulator validates all JSONL events into
normalized calls, evaluates each policy, and creates report records without
touching audit or adapter code. Thin Python and Rust CLIs load files, call the
pure API, and write JSONL only after successful validation.

## Slices

1. Define versioned trace/report fixtures and stable trace errors.
2. Implement the Python pure API plus CLI with focused API and subprocess
   tests.
3. Implement the equivalent Rust API plus standalone binary in parallel from
   the shared fixtures.
4. Verify cross-runtime byte equivalence, no-partial-output failure behavior,
   and no-side-effect boundaries.

## Risks

- Python and Rust JSON parsing differ: require exact types and normalized call
  values at the trace boundary, then test common fixtures.
- A malformed later line leaks partial review data: validate the whole trace
  before emitting any report.
- Report data leaks secrets: retain arguments/context only in memory and omit
  them structurally from output types.
- Future stateful policy features make ordering ambiguous: require consecutive
  sequences now but prohibit stateful simulation in this version.
- CLI parsing obscures library behavior: keep argument parsing dependency-free
  and test the pure API separately.

## Verification

Run focused Python and Rust simulator tests after each implementation slice,
then `make check` and `git diff --check`. Compare serialized shared-fixture
reports byte-for-byte across both runtimes.
