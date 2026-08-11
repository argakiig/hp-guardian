# Spec: Policy Language v2 Fixed-Window Rate Limits

**Status:** Implemented.

## Objective

Add the first stateful policy feature without changing Policy Language v1: a
host-local fixed-window quota on a v2 `allow` rule. A call that wins such a
rule consumes one atomic quota slot; an exhausted quota returns `throttle`.
This creates an enforceable decision, not a sleep, retry, or tool execution.

## Assumptions

- The first key is the normalized `(agent, user, tool)` call identity. Missing
  identity components are represented explicitly, never merged with strings.
- State is process-local, ephemeral, and bounded to 10,000 active identity
  keys by default. Restart clears quotas; distributed or durable quota storage
  is deliberately out of scope.
- Production uses a monotonic clock. An injected clock that moves backwards
  fails closed instead of resetting a window.

## Policy Contract

Only `version: 2` policies may use the optional `rate_limit` rule field:

```yaml
version: 2
rules:
  - action: allow
    target:
      agent: research-bot
      tool: search
    rate_limit:
      max_calls: 10
      window_seconds: 60
```

- A v2 policy otherwise preserves the v1 top-level, target, condition,
  specificity, declaration-order, and static action-priority rules.
- `rate_limit` is permitted only on an `allow` rule. It has exactly positive
  integer `max_calls` and `window_seconds` fields, each at most `86_400`.
- Static `deny`, `require_approval`, `throttle`, `redirect`, and `log`
  selection happens before quota consumption. Only a winning `allow` rule with
  `rate_limit` consumes a slot.
- The selected rule consumes one slot atomically. Within a fixed window
  `[floor(now / window_seconds) * window_seconds, next_window)`, the first
  `max_calls` selected calls return `allow`; later selected calls return
  `throttle`. The decision retains the normal matching rule indices.
- State-store error or monotonic-clock regression fails closed at the stateful
  resolver with stable `state_unavailable`; no effect request is returned.
- The pure `Engine` remains stateless and is not a public v2 entry point. The
  general `PolicyParser` continues to accept only v1; v2 parsing and stateful
  resolution are available only through `RateLimitedPolicyStore` using an
  injected `RateLimitStore` and monotonic clock.

## Public APIs

Python:

```python
store = InMemoryRateLimitStore()
limited = RateLimitedPolicyStore(policy_text, store, now_monotonic_seconds=clock)
decision = limited.resolve(call)
```

Rust:

```rust
let limited = RateLimitedPolicyStore::with_clock(policy, state_store, clock)?;
let decision = limited.resolve(&call)?;
```

Both runtimes expose `StateError` / `StateError`-equivalent with the stable
code `state_unavailable`. A later adapter integration is a separate approval
gate; this slice does not make the existing inline adapter execute throttling.

## Conformance and Tests

Add `conformance/cases/rate_limits_v2.json`. Both runtimes must exercise:

1. v1 rejects `rate_limit`; v2 accepts a valid limit.
2. Fixed-window allow, exhaustion-to-throttle, and boundary reset behavior.
3. Independent `(agent, user, tool)` keys and missing identity components.
4. Static deny and higher-priority non-allow actions do not consume quota.
5. Invalid limits and clock regression fail with stable errors.
6. Concurrent callers cannot exceed the configured quota.
7. State-capacity exhaustion fails closed.

Tests are written RED before each implementation slice. `make check` remains
the release gate.

## Boundaries

- **Always:** preserve v1 unchanged, consume quota atomically, use a monotonic
  clock, and audit failures before any host-owned effect.
- **Ask first:** persistent/distributed state, custom policy-selected keys,
  waiting/retry behavior, or throttle execution.
- **Never:** silently reset quota on clock rollback, let a state error allow a
  call, or treat this host-local store as a distributed limiter.

## Success Criteria

- Python and Rust pass the same v2 rate-limit fixture and retain v1 fixtures.
- The quota cannot be exceeded by concurrent calls in either runtime.
- State is touched only by the final selected v2 `allow` rule.
- `make check`, formatting, Clippy, and a security review pass.
