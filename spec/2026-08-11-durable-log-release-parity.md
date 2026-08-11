# Spec: Durable-Log Release Parity

**Status:** Approved for implementation.

## Objective

Close the remaining gaps in the durable local audit-log feature before it is
declared cross-runtime complete. This slice adds only parity, verification, and
documentation around the approved recovery contract; it does not widen the
policy language or begin the deferred product roadmap.

## Contract

- Python and Rust must contend for the same Unix `flock` sidecar lease. A
  Python holder blocks Rust and a Rust holder blocks Python with
  `audit_lock_unavailable`.
- `AuditLog`, `AuditedPolicyStore`, and `InlineEnforcementAdapter` expose the
  same explicit close semantics in both runtimes. A closed boundary is
  fail-closed and adapters continue to map storage details to
  `audit_write_failed`.
- Manifest and lock reads/writes use the same no-follow regular-file discipline
  as active audit data. Directory metadata is synced after creating, replacing,
  truncating, or removing any managed file.
- Public documentation identifies the shared crash-state fixture, Unix-only
  recovery guarantee, and retained single-writer lease.

## Testing Strategy

Write regressions first for cross-runtime lock contention, close parity,
symlinked lock/manifest rejection, and parent-sync failure propagation. Run the
same shared crash-state fixture in both runtimes, then execute `make check` and
a security review of every filesystem transition.

## Boundaries

- **Always:** fail closed on any lock, path, manifest, or sync failure.
- **Ask first:** Windows recovery support, shared writer service, remote logs,
  encryption, or tamper-evident audit records.
- **Never:** weaken the lease, follow a managed-file symlink, or report the
  feature complete without cross-runtime contention evidence.

## Success Criteria

- Cross-runtime lease contention is exercised in CI on Unix.
- Python and Rust expose equivalent close behavior.
- Managed metadata paths receive no-follow validation and directory-sync tests.
- Documentation and conformance guidance match the shipped implementation.
