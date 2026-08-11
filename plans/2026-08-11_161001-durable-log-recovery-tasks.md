# Tasks: Durable Local Audit-Log Recovery

## Task 1: Define shared crash-state cases

**Acceptance:** `durable_log_recovery_v1.json` specifies file layouts,
operation state, expected recovered layouts, and stable error codes for tail,
corruption, lock, and rotation cases.

**Verify:** Focused fixture runners fail before the implementations exist.

**Files:** `conformance/cases/durable_log_recovery_v1.json`,
`tests/test_durable_log_recovery.py`, `tests/test_durable_log_recovery.rs`,
`conformance/README.md`.

## Task 2: Add exclusive Unix writer leases

**Acceptance:** both runtimes acquire one no-follow `0600` lock file, retain
the lease for log lifetime, expose `close()`, and fail closed on contention or
unsupported platforms.

**Verify:** focused Python/Rust process-contention, symlink, permission, and
closed-log tests.

**Dependencies:** Task 1.

**Files:** `src/hp_guard/audit.py`, `src/audit.rs`,
`tests/test_durable_log_recovery.py`, `tests/test_durable_log_recovery.rs`.

## Task 3: Implement Python prefix validation and tail recovery

**Acceptance:** Python validates active/backups while holding the lease,
truncates only the specified torn suffix, syncs it, and leaves ambiguous or
interior-corrupt files untouched while returning stable errors.

**Verify:** `PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_audit.py tests/test_durable_log_recovery.py`.

**Dependencies:** Tasks 1-2.

**Files:** `src/hp_guard/audit.py`, `tests/test_durable_log_recovery.py`.

## Task 4: Implement Rust prefix validation and tail recovery

**Acceptance:** Rust produces the same recovered layouts and stable failures
as Python for every shared prefix case.

**Verify:** `cargo test --test test_audit --test test_durable_log_recovery`.

**Dependencies:** Tasks 1-2.

**Files:** `src/audit.rs`, `tests/test_durable_log_recovery.rs`.

## Checkpoint: Prefix recovery

- [ ] Tasks 1-4 pass in both runtimes.
- [ ] Shared fixtures produce identical layouts/errors.
- [ ] `git diff --check` is clean.

## Task 5: Implement Python manifest rotation recovery

**Acceptance:** Python syncs a versioned manifest, stages files under the
specified names, completes interrupted rotations on open, and prunes only
after transaction completion.

**Verify:** focused Python recovery tests cover all interruption phases.

**Dependencies:** Task 3.

**Files:** `src/hp_guard/audit.py`, `tests/test_durable_log_recovery.py`.

## Task 6: Implement Rust manifest rotation recovery

**Acceptance:** Rust matches Python's manifest, staging, and final retained
layout for every shared rotation state.

**Verify:** focused Rust recovery tests cover all interruption phases.

**Dependencies:** Task 4.

**Files:** `src/audit.rs`, `tests/test_durable_log_recovery.rs`.

## Task 7: Integrate, document, and adversarially review

**Acceptance:** adapter/store failures remain fail-closed, public docs explain
Unix-only recovery and close semantics, and an independent review finds no
path, lock, recovery, or retention regression.

**Verify:** `make check`, `git diff --check`, and recorded review result.

**Dependencies:** Tasks 5-6.

**Files:** `README.md`, `spec/2026-08-11-durable-audit-and-policy-lifecycle.md`,
`tests/test_adapter.py`, `tests/test_adapter.rs`.
