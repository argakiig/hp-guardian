# Spec: Rust policy-engine safety repair

## Objective

Make the Rust policy engine safe to use for declarative enforcement. A policy
that requests denial, approval, or an unsupported constraint must never be
silently treated as an allow decision.

This repair is approved from the 2026-08-11 review. It applies only to the new
Rust implementation; the existing Python implementation is not changed.

## Tech Stack

Rust 2021, `serde_yaml` for policy decoding, `regex` for `args_match`, and
the standard library for lexical path-glob matching.

## Commands

```bash
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo build
```

## Project Structure

- `src/models.rs` — public rule, decision, audit, and error types.
- `src/parser.rs` — strict YAML validation and policy-to-engine conversion.
- `src/engine.rs` — deterministic resolution and configured fallback action.
- `src/conditions.rs` — validated condition matching.
- `src/logging.rs` — typed audit entries.
- `tests/` — unit and integration regression coverage.

## Contract

- `PolicyParser::parse(&str)` returns `Result<Engine, PolicyError>`; no policy
  error may panic or silently downgrade an action.
- `global.default_action` supplies the engine fallback. Omission preserves the
  existing `allow` default.
- A policy action must be one of the declared `Action` values. Unknown actions,
  unknown target fields, unknown conditions, invalid regexes, and malformed
  YAML return `PolicyError`.
- Rules support `args_match`, `path_pattern`, and explicit `user` plus
  `context` targets. A nested rule may not override its enclosing agent/tool
  scope.
- `path_pattern` is lexical matching of a tool-call argument; `*` matches any
  character sequence. It does not claim filesystem canonicalization or
  sandboxing.
- A matching `Deny` takes priority across scopes. Otherwise, a more-specific
  rule wins, then action priority is `RequireApproval`, `Throttle`, `Redirect`,
  `Allow`, `Log`. Ties retain policy order.
- `Decision.matched_rules` records every rule that matched targets and
  conditions; the selected action is determined independently.
- `AuditLogger::log` returns a typed audit entry, so argument and rule-index
  arrays remain arrays when serialized.

## Code Style

Use explicit enums and `Result` at the YAML boundary; do not use `unwrap` or
`expect` for caller-controlled policy data.

```rust
let policy: PolicyFile = serde_yaml::from_str(yaml)?;
let action = policy.global.default_action.unwrap_or(Action::Allow);
```

## Testing Strategy

Add small regression tests first for each reviewed failure: global deny,
invalid action/regex, path matching, targets, action conflicts, all matched
rule indices, and typed audit serialization. Run the full Rust suite after
each vertical slice.

## Boundaries

- Always: validate policy input at parsing, run the commands above, preserve
  fail-closed behavior for invalid policy.
- Ask first: new dependencies, stateful rate limiting, executing redirect, or
  changing the Python implementation.
- Never: silently ignore an enforcement-relevant field, log a policy argument
  differently from its serialized value, or weaken a configured deny.

## Success Criteria

- A `default_action: deny` policy denies an unknown call.
- Every invalid or unsupported policy component returns `PolicyError`.
- `/etc/*` matches `/etc/passwd` and denies when the policy says so.
- Conflict resolution is deterministic and covered by tests.
- All test, formatting, lint, and build commands pass.

## Tasks

1. Add the fallible parser/default-action contract and its red tests.
2. Add strict targets and conditions, including lexical path matching.
3. Make precedence and matched-rule auditing conform to this contract.
4. Return typed audit entries and update the demo/tests.
