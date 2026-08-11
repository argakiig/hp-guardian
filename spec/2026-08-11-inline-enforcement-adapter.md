# Spec: Inline Enforcement Adapter

**Status:** Approved.

## Objective

Provide a host-local inline library boundary that validates an enforcement
request, rejects stale work, resolves it against the active audited policy, and
returns a non-executing response. The host remains solely responsible for
executing an effect after it receives an `allow` response.

## Contract

- `EnforcementRequest` contains exactly an opaque `caller_id`, a retry-stable
  opaque `correlation_id`, an integer `deadline_unix_ms`, and a normalized
  `PolicyCall`. Caller and correlation IDs are non-empty UTF-8 strings of at
  most 256 bytes; the deadline is a Unix timestamp in milliseconds in the
  inclusive range `0` through `2^64 - 1`.
- The adapter uses an injected millisecond clock in tests and the system clock
  in production. It rejects a request with `deadline_unix_ms <= now` using the
  stable `deadline_exceeded` error before policy evaluation or audit writing.
- The request boundary validates the complete call shape: agent, tool, and
  user are strings or null; args is an array of strings; and context is a
  string-to-string map. Invalid request fields use `invalid_request`.
- The adapter authorizes the normalized call through `AuditedPolicyStore` with
  the caller-supplied correlation ID, caller ID, and deadline. A failed required
  audit write returns `audit_write_failed` and no response.
- The response always contains caller ID, correlation ID, deadline, policy
  version/digest, decision, and matched-rule indices. It contains an
  `EffectRequest` only when the decision is `allow`.
- `EffectRequest` is the normalized original call plus caller ID, correlation
  ID, deadline, policy identity, decision, and matched rules. It is data only;
  the adapter has no executor callback or tool import.
- `deny`, `throttle`, `log`, `require_approval`, and `redirect` return an
  audited response with no effect. Their host-side semantics remain deferred.
- The authorization audit record includes caller ID and deadline as metadata;
  raw args and context remain absent. Reusing a correlation ID records another
  authorization attempt. This release deliberately performs no deduplication.

An allowed response has this exact shape; a non-allow response omits `effect`:

```json
{"caller_id":"host-a","correlation_id":"req-allow","deadline_unix_ms":1001,"policy":{"version":1,"sha256":"962576725e71c685450a6655397168e28716aee2af6f15c41a0f4df1c2cc43d6"},"decision":"allow","matched_rules":[],"effect":{"caller_id":"host-a","correlation_id":"req-allow","deadline_unix_ms":1001,"policy":{"version":1,"sha256":"962576725e71c685450a6655397168e28716aee2af6f15c41a0f4df1c2cc43d6"},"decision":"allow","matched_rules":[],"call":{"agent":"bot","tool":"shell","args":["echo","hello"],"user":null,"context":{}}}}
```

## Tech Stack and Commands

Use existing Python and Rust standard-library time support plus the existing
audited-policy stores. No transport, executor, or dependency is added.

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_adapter.py
cargo test --test test_adapter
make check
```

## Project Structure

- `src/hp_guard/adapter.py` and `src/adapter.rs`: request/response types and
  inline authorization boundary.
- `src/hp_guard/audit.py` and `src/audit.rs`: internal metadata-aware
  authorization and caller/deadline audit fields.
- `conformance/cases/inline_adapter_v1.json`: shared request and response
  fixtures.
- `tests/test_adapter.py` and `tests/test_adapter.rs`: deadline, auditing,
  effect, and invalid-request regressions.

## Code Style

Make the execution boundary obvious: authorization returns data, never invokes
an effect.

```python
response = adapter.authorize(request)
if response.effect is not None:
    host_executor(response.effect)
```

## Testing Strategy

Start with shared fixtures for `allow`, denied/non-allow decisions, an expired
deadline, invalid request data, and reused correlation IDs. Test audit metadata
and failure closure in both runtimes. Use a deliberately side-effecting host
callable only to prove the adapter does not receive or invoke it.

## Boundaries

- **Always:** validate at the request boundary, reject expired work, audit
  before returning, preserve the supplied correlation ID, and return effects
  only for `allow`.
- **Ask first:** executor callbacks, deduplication storage, transport, remote
  callers, non-Unix deadline formats, or host semantics for non-allow actions.
- **Never:** execute a tool, invoke a callback, turn `log` or `throttle` into
  an implicit allow, or silently proceed after an audit failure.

## Success Criteria

- Python and Rust return equivalent responses from shared request fixtures.
- A valid `allow` produces an explicit effect request only after durable audit.
- Expired, invalid, and audit-failing requests return no effect.
- Reused correlation IDs remain visible as separate audited attempts without
  changing their value.
