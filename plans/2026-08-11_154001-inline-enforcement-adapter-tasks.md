# Tasks: Inline Enforcement Adapter

- [ ] Define shared inline-adapter fixtures and audit metadata expectations.
  - Acceptance: requests cover allow, deny, expired deadline, invalid call,
    and repeated correlation; reports contain no raw args/context.
  - Verify: focused fixture tests in both runtimes.
  - Files: `conformance/cases/inline_adapter_v1.json`, adapter/audit tests.

- [ ] Extend the Python audit-store internal authorization path.
  - Acceptance: supplied correlation, caller ID, and deadline persist in the
    authorization/outcome metadata without changing existing callers.
  - Verify: `PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_audit.py`.
  - Files: `src/hp_guard/audit.py`, `tests/test_audit.py`.

- [ ] Implement the Python inline adapter from failing tests.
  - Acceptance: strict request validation, deadline rejection before audit,
    effect only for allow, and no executor interface.
  - Verify: `PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_adapter.py`.
  - Files: `src/hp_guard/adapter.py`, package exports, `tests/test_adapter.py`.

- [ ] Implement Rust audit metadata and adapter from the shared fixture.
  - Acceptance: serialized response and audit metadata match Python's contract.
  - Verify: `cargo test --test test_adapter`.
  - Files: `src/audit.rs`, `src/adapter.rs`, `src/lib.rs`, adapter/audit tests.

- [ ] Complete cross-runtime and no-execution regressions.
  - Acceptance: all failures return no effect, repeated correlation IDs are
    preserved, and no adapter code path can invoke a host executor.
  - Verify: `make check` and `git diff --check`.
  - Files: conformance and adapter test files only.
