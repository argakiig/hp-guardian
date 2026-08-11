# Tasks: Boolean and Temporal Conditions

- [ ] Define boolean/time conformance fixtures and stable error expectations.
  - Verify: fixture runners in Python and Rust.
- [ ] Implement Python AST validation and clock-injected evaluation from
  failing tests.
  - Verify: focused Python condition/parser tests.
- [ ] Implement Rust parity from the shared fixtures.
  - Verify: focused Rust condition/parser tests.
- [ ] Run compatibility, boundary, resource-limit, and full checks.
  - Verify: `make check` and `git diff --check`.
