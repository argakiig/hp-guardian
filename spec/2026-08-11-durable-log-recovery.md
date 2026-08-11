# Spec: Durable Local Audit-Log Recovery

**Status:** Proposed for implementation.

## Objective

Replace the current best-effort local audit writer with a Unix host-local
durable-log boundary. It must retain an exclusive writer lease, recover a
provably torn final JSONL record without discarding earlier valid history, and
complete an interrupted rotation deterministically before another policy
decision can be authorized.

The existing audit envelope, policy lifecycle, adapter semantics, and public
`AuditLog`/`AuditedPolicyStore` roles remain unchanged. This specification
strengthens their storage implementation; it does not make the audit log a
multi-writer, replicated, encrypted, or tamper-evident service.

## Contract

### Writer ownership

- Each configured audit path has a companion `&lt;audit path&gt;.lock` regular file.
  `AuditLog` acquires an exclusive advisory `flock` lease before activation or
  its first direct append, retains it for its lifetime, and releases it on an
  explicit `close()` or process exit.
- A second process or runtime that cannot acquire that lease fails closed with
  stable `audit_lock_unavailable`; it must not inspect, recover, rotate, or
  append the log.
- The lock, manifest, active log, backups, and staging files must all be
  regular files. On Unix they are opened without following symlinks and created
  with mode `0600`.
- This release supports the recovery guarantee on Unix only. A platform that
  cannot provide the required no-follow open, owner-only permissions, advisory
  lock, and directory sync must fail closed with `audit_recovery_unsupported`.

### JSONL recovery

- Before its first append after acquiring the lease, the log validates the
  active file and every numbered backup. Every complete line must be one UTF-8
  JSON object.
- If a file ends in a non-empty suffix after its last newline, and all earlier
  lines are valid JSON objects, recovery truncates exactly that suffix, syncs
  the file, and syncs its parent directory. This is the only automatic data
  removal.
- An invalid complete line, invalid UTF-8, an empty line, an unexpected file,
  or a parseable final object lacking its newline is `audit_corrupt` and blocks
  authorization. The implementation must not infer intent or silently repair
  those states.
- Recovery writes an `audit_recovered_tail` diagnostic only through the host's
  error/reporting path, never into the audit file itself. Audit history remains
  the recovered valid prefix rather than a newly invented event.

### Crash-transactional rotation

- Rotation uses a regular-file manifest at `&lt;audit path&gt;.rotation.json`. It
  contains a format version, opaque transaction ID, configured backup count,
  operation `rotate`, a phase (`staging` or `installing`), and the occupied
  source slots captured before rotation. The manifest is encoded as compact UTF-8 JSON,
  written to a temporary sibling, synced, atomically renamed, and followed by
  a parent-directory sync before any managed file is renamed.
- For transaction ID `T`, staging names are exactly
  `&lt;audit path&gt;.rotation.T.active` and
  `&lt;audit path&gt;.rotation.T.backup.&lt;index&gt;`. A manifest whose ID, names, or
  backup count do not match that grammar is corrupt; it is never guessed or
  adopted.
- A transaction first moves the active file and every existing numbered backup
  into transaction-specific staging names. It then installs the new numbered
  backups from staging, drops only the old backup beyond the retention count,
  and removes the manifest. Every file rename/removal is followed by a
  parent-directory sync.
- On open, while holding the lease, a present manifest is recovered by
  completing its declared rotation. The result is one active path (possibly
  absent until the pending append creates it), backups numbered `1..N`, no
  staging files, and no manifest. If the on-disk state cannot be reconciled
  with the manifest, recovery fails closed with `audit_recovery_failed`.
- Age pruning happens only after manifest recovery and a completed rotation.
  A crash during pruning may retain extra expired backups, but must not remove
  a valid non-expired record outside the configured retention policy.

### Durability ordering

For every successful authorization append the runtime must:

1. hold the exclusive lease and finish recovery;
2. complete any required rotation transaction;
3. append exactly one newline-terminated JSON object;
4. sync the audit file before returning an authorization; and
5. sync the parent directory after creating, renaming, truncating, or removing
   any managed file.

An abrupt kill can still lose the in-progress record. On restart the valid
prefix is retained and only a malformed, unterminated tail may be removed.
No success response is returned until its complete audit record has been
synced.

## API and Error Model

- `AuditLog` retains its existing construction and append surface, but its
  creation/first use may now raise/return `audit_lock_unavailable`,
  `audit_corrupt`, `audit_recovery_failed`, or
  `audit_recovery_unsupported`.
- Add explicit `close()` in Python and Rust. Calls after close fail with
  `audit_closed`; normal process shutdown still releases the OS lease.
- `AuditedPolicyStore` and `InlineEnforcementAdapter` remain fail-closed: any
  durable-log error prevents activation, authorization, an effect response, or
  an outcome append. Adapter callers continue to receive the stable
  `audit_write_failed` boundary error rather than storage internals.
- Direct-store authorization IDs remain unchanged; adapter-provided correlation
  IDs remain authoritative.

## Commands

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_audit.py tests/test_durable_log_recovery.py
cargo test --test test_audit --test test_durable_log_recovery
make check
```

## Project Structure

- `src/hp_guard/audit.py` and `src/audit.rs`: durable-log lifecycle and audit
  integration.
- `conformance/cases/durable_log_recovery_v1.json`: equivalent recovered and
  fail-closed on-disk states.
- `tests/test_durable_log_recovery.py` and
  `tests/test_durable_log_recovery.rs`: materialize fixture layouts and assert
  recovery, lock contention, and rotation completion.
- `tests/test_adapter.py` and `tests/test_adapter.rs`: retain end-to-end
  fail-closed coverage through the adapter boundary.

## Testing Strategy

The shared fixture must cover:

- a torn active tail that is truncated to its valid prefix;
- a malformed complete line, invalid UTF-8, empty line, and a parseable
  unterminated final object, each rejected without mutation;
- an interrupted rotation before staging, during staging, during installation,
  and before manifest removal, each recovering to the same retained sequence;
- stale staging files without a manifest, and a malformed or incompatible
  manifest, each rejected without mutation; and
- active/backups that include raw-call secrets, proving recovery never rewrites
  or emits them.

Each runtime also needs a process-level exclusive-lock test and Unix
regular-file, symlink, permissions, and directory-sync failure regressions.
The two runtimes must use identical lock and manifest names so a Python process
and a Rust process contend for the same lease.

## Boundaries

- **Always:** acquire the lease before touching managed files; validate every
  complete line; preserve the valid prefix; sync file and directory metadata in
  the stated order; and fail closed on ambiguity.
- **Ask first:** Windows support, multi-writer logging, remote persistence,
  encryption, signed/tamper-evident records, alternate recovery policies, or
  a retention-policy change.
- **Never:** repair interior corruption, follow a symlink, steal or break a
  live lease, overwrite another transaction's manifest/staging files, or emit
  an authorization after a recovery/storage error.

## Success Criteria

- A killed append preserves every valid preceding line and removes only a
  malformed unterminated tail.
- All supported interrupted rotation states converge to one deterministic file
  layout without losing retained records.
- A second writer cannot append, rotate, or recover while the first holds the
  lease, including when the writers use different runtimes.
- Corrupt or ambiguous state fails closed without filesystem mutation.
- Python and Rust pass the same recovery fixture and the full `make check`
  gate.
