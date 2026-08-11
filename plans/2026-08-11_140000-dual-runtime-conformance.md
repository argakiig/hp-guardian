# Plan: Dual-runtime policy conformance

## Overview

Implement Policy Language v1 as a shared contract, then make Python and Rust
independent conforming runtimes.

## Tasks

1. Define the v1 contract and JSON fixture format.
   - Acceptance: strict surface, precedence, error codes, and boundaries are
     written and fixture-ready.
   - Verify: documentation review and fixture parsing tests.

2. Bring the Python parser, engine, matcher, conditions, and audit entry to v1.
   - Acceptance: Python rejects unsupported policies and agrees with Rust on
     the v1 semantics.
   - Verify: `PYTHONPATH=src python -m pytest tests`.

3. Add shared fixtures and runners in both runtimes.
   - Acceptance: every fixture asserts a decision or stable error code in both
     suites.
   - Verify: Python and Rust conformance tests.

4. Document the operator workflow and run the complete verification matrix.
   - Acceptance: one command sequence is sufficient for a contributor to check
     both runtimes.
   - Verify: all commands in the specification.

## Dependencies

Task 1 precedes Tasks 2 and 3. Tasks 2 and 3 may proceed in parallel once the
fixture shape is fixed. Task 4 follows both.

## Risks

- Python and Rust regex engines differ. Mitigation: portable subset and shared
  cases.
- Existing docs advertise unimplemented stateful fields. Mitigation: v1 rejects
  them and documentation distinguishes deferred capabilities.
