# Spec: Durable Audit and Explicit Policy Lifecycle

**Status:** Approved.

## Objective

Provide a host-local audit boundary that records an authorization before a
future adapter may execute a tool, records the correlated outcome afterward,
and activates policy changes only through an explicit validated reload.

## Contract

- A policy snapshot contains its integer version, SHA-256 digest of the exact
  UTF-8 policy text, and parsed engine.
- Reload parses and validates a candidate before it replaces the active
  snapshot. If validation or the required activation audit write fails, the
  previous snapshot remains active.
- Authorization resolves a call with the active snapshot, durably appends an
  `authorization` record, then returns the decision. A write failure returns an
  audit error and no decision; a future tool adapter must not execute.
- An outcome record uses the authorization correlation ID and contains only a
  bounded outcome status and optional bounded detail.
- JSON Lines records contain timestamp, event, correlation ID where relevant,
  policy version/digest, agent, tool, user, decision, and matched-rule indices.
  Raw arguments and context are omitted by default.
- Records append to a host-local file with owner-only permissions where the OS
  supports them. Rotation is configurable by maximum bytes and maximum age.
- One `AuditLog` writer owns each audit path. The runtimes serialize calls
  through one in-process store/log instance, but do not coordinate independent
  stores or processes that point at the same file.
- Each successful append is synced before authorization returns. This is not a
  write-ahead log: abrupt process or power loss can leave a torn final JSONL
  record, and multi-file rotation is not crash-transactional. Consumers that
  require crash recovery, tamper evidence, or shared writers need a separate
  durable-log service or an explicitly designed recovery protocol.
- On Unix-like systems, writers reject symlink/non-regular audit paths and
  create files with mode `0600`. On platforms without equivalent no-follow or
  owner-mode facilities, the audit boundary has only the platform's ordinary
  filesystem protections.
- The initial release relies on filesystem permissions, not encryption at rest
  or signed policy artifacts.

## Tech Stack and Commands

Use existing Python standard-library hashing and JSON support. Rust adds the
small `sha2` crate for SHA-256; JSON uses existing `serde_json`.

```bash
make check
```

## Project Structure

- `src/hp_guard/audit.py` and `src/audit.rs`: audit writer and lifecycle API.
- `src/hp_guard/models.py` and `src/models.rs`: snapshot, record, and error
  types.
- `tests/test_audit.py` and `tests/test_audit.rs`: deterministic file and
  lifecycle tests.

## Testing Strategy

Test authorization-before-return, raw-data omission, snapshot rollback on
invalid reload or audit failure, outcome correlation, digest equality, and
size/age rotation. Exercise adapter authorization through the real audit file
and assert that its returned policy identity and decision match the persisted
authorization record. Run equivalent JSON-shape fixtures in both runtimes.

## Boundaries

- **Always:** validate policy before activation, use atomic replacement in
  memory, omit raw arguments/context, and fail closed on required audit writes.
- **Ask first:** remote storage, encryption/key management, signed policies,
  automatic file watching, or an execution adapter.
- **Never:** execute a tool in this slice, silently continue after an audit
  write failure, or log secrets/raw arguments by default.

## Success Criteria

- Both runtimes produce a SHA-256-identified snapshot and append equivalent
  authorization records without raw call arguments.
- Failed reload keeps the previously active snapshot.
- Failed authorization logging returns an error rather than a decision.
- Size and age rotation are deterministic and covered by tests.
