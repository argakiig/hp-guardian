# Tasks: Policy Simulator and Trace Format

- [ ] Define shared v1 trace/report fixtures and stable trace-error expectations.
  - Acceptance: fixtures cover allow, deny, expected-decision match,
    two-policy change, malformed JSON, invalid sequence, and invalid call.
  - Verify: focused fixture-runner tests in both runtimes.
  - Files: `conformance/cases/simulator_v1.json`, simulator tests.

- [ ] Implement the Python pure simulator API from failing tests.
  - Acceptance: validates complete JSONL input, reports one normalized decision
    per event, and omits raw args/context.
  - Verify: `PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_simulator.py`.
  - Files: `src/hp_guard/simulator.py`, `src/hp_guard/models.py`,
    `tests/test_simulator.py`.

- [ ] Add the Python JSONL CLI.
  - Acceptance: supports baseline plus optional candidate policy and produces
    no stdout for an invalid trace.
  - Verify: focused CLI subprocess tests.
  - Files: `src/hp_guard/simulate.py`, `tests/test_simulator.py`.

- [ ] Implement the Rust pure simulator API and binary from the same fixtures.
  - Acceptance: report serialization matches Python and invalid input uses the
    specified stable code.
  - Verify: `cargo test --test test_simulator`.
  - Files: `src/simulator.rs`, `src/lib.rs`, `src/bin/hp-guard-simulate.rs`,
    `tests/test_simulator.rs`.

- [ ] Run cross-runtime and side-effect regressions.
  - Acceptance: report bytes match, no tool/audit/state API is reachable, and
    malformed input cannot yield partial stdout.
  - Verify: `make check` and `git diff --check`.
  - Files: conformance and simulator test files only.
