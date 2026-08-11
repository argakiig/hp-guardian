# Changelog

All notable changes to this source-first repository are documented here.

## [0.1.0] - 2026-08-11

### Added

- A shared YAML policy language implemented natively in Python and Rust.
- Strict version-1 parsing, deterministic rule resolution, and executable
  cross-runtime conformance fixtures.
- Target matching for agent, tool, user, and context plus portable
  `args_match` and lexical `path_pattern` conditions.
- Bounded `all`, `any`, and `not` conditions and absolute UTC
  `[start, end)` `time_window` conditions.
- An offline JSON Lines policy simulator with optional baseline/candidate
  comparison.
- Host-local durable JSON Lines audit storage, policy SHA-256 identity,
  explicit validated reloads, and bounded rotation.
- A data-only inline enforcement adapter with caller identity, correlation ID,
  deadline validation, required authorization audit, and allow-only effects.

### Security and compatibility notes

- The policy engine is not a sandbox, proxy, executor, or stateful rate-limit
  system.
- `throttle`, `log`, `require_approval`, and `redirect` resolve as policy
  decisions, but their host-side execution semantics are deferred.
- v0.1 is source-only: Python and Rust package publication is intentionally
  deferred.

### Deferred

- Stateful/rate-limit conditions, recurring schedules and local timezones,
  redirect execution, multi-action rules, memory, scripting, remote audit
  storage, signing/encryption, automatic policy watching, and transport
  adapters.

See the [deferred capability roadmap](plans/2026-08-11_150000-deferred-capabilities-roadmap.md)
for the approved follow-on plan.
