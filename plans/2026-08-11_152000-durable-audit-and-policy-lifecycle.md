# Implementation Plan: Durable Audit and Explicit Policy Lifecycle

## Architecture

Add an `AuditedPolicyStore` in each runtime. It owns one active immutable
snapshot and an append-only `AuditLog`. `reload(policy_text)` validates a new
snapshot and writes its activation event before replacing the old snapshot.
`authorize(call)` writes an authorization event before returning a decision.
`record_outcome` is separate because tool execution remains out of scope.

## Slices

1. Add shared audit-envelope fixtures and error/snapshot models.
2. Implement Python audit writer, snapshot store, and deterministic tests.
3. Implement the equivalent Rust writer and snapshot store in parallel.
4. Add rotation, combined conformance, security review, and full verification.

## Risks

- Audit files leak tool input: omit arguments and context by construction.
- Failed reload changes enforcement: parse and write activation before swapping.
- Rotation loses the active file: rotate before an append that would exceed the
  size limit; retain bounded numbered files and age-prune deterministically.
- No executor exists: make authorization return an error on failed logging and
  document that a future adapter may execute only after success.

## Verification

Run focused Python/Rust audit tests after each slice, then `make check` and
`git diff --check`.
