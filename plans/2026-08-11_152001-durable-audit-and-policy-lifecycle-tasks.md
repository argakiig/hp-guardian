# Tasks: Durable Audit and Explicit Policy Lifecycle

- [ ] Define shared audit record expectations and add SHA-256 support in Rust.
  - Verify: focused model/fixture tests.
- [ ] Implement Python `AuditLog` and `AuditedPolicyStore` with failing tests
  first.
  - Verify: `pytest tests/test_audit.py`.
- [ ] Implement Rust equivalents from the same contract.
  - Verify: `cargo test --test test_audit`.
- [ ] Add deterministic rotation and reload-failure regressions in both
  runtimes.
  - Verify: `make check` and `git diff --check`.
