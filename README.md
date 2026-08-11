# Hardpoint Guardian

Hardpoint Guardian is a source-first, dual-runtime policy engine for agentic
tool calls. It evaluates a declarative YAML policy before a host application
performs an effect. Python and Rust implement the same policy contract; neither
runtime is the reference implementation.

This v0.1 repository is ready to integrate from source. It does not publish a
Python package or a Rust crate, run a hosted service, or execute tools on a
host's behalf.

## What it provides

- Strict YAML policy validation and deterministic decision resolution.
- Native Python and Rust runtimes checked against shared conformance fixtures.
- Bounded boolean conditions and absolute UTC time windows.
- An explicit, host-local v2 fixed-window rate-limit resolver.
- A JSON Lines simulator for replaying a trace against one or two policies.
- Host-local, durable JSON Lines authorization auditing with explicit policy
  reloads and bounded rotation.
- An inline enforcement adapter that returns data for an allowed host effect;
  it never calls the tool itself.

The normative contracts are [Policy Language v1](spec/policy-language-v1.md)
and [v2 Fixed-Window Rate Limits](spec/2026-08-11-v2-fixed-window-rate-limits.md).
The executable [conformance cases](conformance/README.md) are the cross-runtime
release gate.

## Prerequisites

- Git
- [uv](https://docs.astral.sh/uv/) and Python 3.10 or later
- A current stable [Rust toolchain](https://www.rust-lang.org/tools/install)
- `make`

All commands below run from the repository root.

## Quick start

Clone the repository, then run the complete local release gate:

```bash
git clone <repository-url> hp-guard
cd hp-guard
make check
```

`make check` runs the Python and Rust test suites, shared conformance runners,
Rust formatting, Clippy with warnings denied, and a Rust build.

Evaluate a policy directly in Python:

```bash
PYTHONPATH=src uv run --with pyyaml python - <<'PY'
from hp_guard import PolicyCall, PolicyParser

policy = """
version: 1
rules:
  - id: deny-shell-removal
    action: deny
    target: {tool: shell}
    condition: {args_match: "^rm .*"}
"""

engine = PolicyParser.parse(policy)
decision = engine.resolve_call(PolicyCall(tool="shell", args=["rm", "-rf", "/tmp/demo"]))
print(decision.action.value)  # deny
PY
```

Use the Rust runtime from another local workspace with a path dependency until
crate publication is approved:

```toml
[dependencies]
hp-guard = { path = "../hp-guard" }
```

```rust
use hp_guard::{PolicyCall, PolicyParser};

let policy = r#"
version: 1
global: {default_action: deny}
"#;
let engine = PolicyParser::parse(policy)?;
let decision = engine.resolve_call(&PolicyCall::default());
assert_eq!(decision.action.as_str(), "deny");
```

## Write a policy

Version 1 policies may have top-level rules and nested agent/tool rules. All
unknown enforcement fields are rejected.

```yaml
version: 1
global:
  default_action: deny

rules:
  - id: allow-research-read
    action: allow
    target:
      agent: research-bot
      tool: read_file
    condition:
      all:
        - path_pattern: "/workspace/*"
        - not:
            path_pattern: "/workspace/.env"

  - id: release-window-only
    action: allow
    target:
      tool: deploy
    condition:
      time_window:
        start: "2026-08-11T09:00:00Z"
        end: "2026-08-11T17:00:00Z"
```

Supported actions are `allow`, `deny`, `throttle`, `log`,
`require_approval`, and `redirect`. Matching `deny` rules win; otherwise
specificity, action priority, and declaration order resolve ties
deterministically.

Conditions can use `args_match`, lexical `path_pattern`, `time_window`, and
bounded `all`, `any`, and `not` composition. A time window is UTC and matches
`start <= now < end`. `path_pattern` is lexical: it does not canonicalize a
path, resolve symlinks, or sandbox filesystem access. `args_match` uses the
portable pattern grammar defined in the policy specification, not a host regex
engine.

## Rate-limit a v2 policy

Version 2 is intentionally available only through `RateLimitedPolicyStore`.
It uses an in-memory, process-local fixed-window quota keyed by agent, user,
and tool. A selected `allow` rule consumes a quota slot; exhaustion returns
`throttle`. This is a decision only—the host does not sleep, retry, or execute
a tool on its own.

```python
from hp_guard import InMemoryRateLimitStore, PolicyCall, RateLimitedPolicyStore

policy = """
version: 2
rules:
  - action: allow
    target: {tool: search}
    rate_limit: {max_calls: 10, window_seconds: 60}
"""

limited = RateLimitedPolicyStore(policy, InMemoryRateLimitStore())
assert limited.resolve(PolicyCall(tool="search")).action.value == "allow"
```

Restarting the process clears quota state. The in-memory store accepts at most
10,000 identity keys by default and fails closed when full. Persistent or
distributed limits, custom keys, and host-side throttle execution remain out
of scope.

## Integrate enforcement

The inline adapter is the intended host boundary. It validates the complete
request, rejects an expired deadline, writes the required authorization record,
then returns an effect only for an `allow` decision. The host chooses whether
and how to execute that effect.

```python
import time

from hp_guard import (
    AuditLog,
    AuditedPolicyStore,
    EnforcementRequest,
    InlineEnforcementAdapter,
    PolicyCall,
)

policy_text = """
version: 1
global: {default_action: allow}
"""
store = AuditedPolicyStore(policy_text, AuditLog("var/hp-guard/audit.jsonl"))
adapter = InlineEnforcementAdapter(store)

request = EnforcementRequest(
    caller_id="my-host",
    correlation_id="request-42",  # preserve this value when retrying
    deadline_unix_ms=time.time_ns() // 1_000_000 + 5_000,
    call=PolicyCall(tool="read_file", args=["README.md"]),
)
response = adapter.authorize(request)

if response.effect is not None:
    # The host owns execution. Hardpoint Guardian has no executor callback.
    host_execute(response.effect)
else:
    handle_terminal_policy_decision(response.decision)
```

Every adapter request needs a non-empty caller ID, retry-stable correlation ID,
and absolute Unix-millisecond deadline. Audit failure is fail-closed: the
adapter returns no effect. Authorization records omit raw arguments and context
by default; the initial audit design relies on local filesystem permissions,
not encryption at rest or signed policy artifacts.

See [Inline Enforcement Adapter](spec/2026-08-11-inline-enforcement-adapter.md)
and [Durable Audit and Explicit Policy Lifecycle](spec/2026-08-11-durable-audit-and-policy-lifecycle.md)
for the complete boundary and error contracts.

## Simulate a policy change

The simulator replays JSON Lines traces without executing tools, writing audit
records, or mutating policy state. Give it a baseline policy and optionally a
candidate policy; it emits one JSON Lines report per input event and omits raw
arguments and context from reports.

```bash
PYTHONPATH=src uv run --with pyyaml python -m hp_guard.simulate \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml

cargo run --bin hp-guard-simulate -- \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml
```

Each trace event requires `version: 1`, a consecutive positive `sequence`, and
a normalized `call`. The full JSONL format and stable trace errors are in
[Policy Simulator and Trace Format](spec/2026-08-11-policy-simulator-and-trace-format.md).

## Supported scope and limitations

Hardpoint Guardian is an authorization decision component, not a complete
security perimeter.

- It does not sandbox a process, canonicalize filesystem paths, or protect a
  tool that bypasses the integration boundary.
- The adapter never executes effects. A host must execute an allowed effect and
  define host-side handling for `throttle`, `log`, `require_approval`, and
  `redirect` decisions.
- v2 provides only process-local fixed-window rate limits. It does not provide
  persistent or distributed state, redirect execution, multi-action rules,
  policy memory, or scripts.
- It has no proxy/sidecar transport, remote audit storage, encryption/key
  management, signed policies, automatic policy watching, telemetry, or hosted
  service.
- On Unix-like hosts, an audit path has one exclusive, cross-process writer
  lease. The local JSONL audit syncs completed appends and recovers a torn
  final record or an interrupted bounded rotation according to the shared
  [durable-log recovery fixture](conformance/cases/durable_log_recovery_v1.json).
  It is not a write-ahead log, replicated store, or tamper-evident record: a
  crash can still lose the in-flight record, and every writer must use this
  boundary. Managed audit and rotation files use no-follow regular-file checks
  and owner-only modes. Durable recovery is intentionally unsupported on
  non-Unix platforms.
- Time windows use the local UTC wall clock. They do not compensate for clock
  skew or supply a trusted/distributed time source.
- The source contract is version 1 only. Future language versions require a
  separate parser dispatch and conformance fixture.

The deferred capability roadmap is maintained in
[Deferred Capabilities Roadmap](plans/2026-08-11_150000-deferred-capabilities-roadmap.md).

## Verification and development

```bash
make test    # Python, Rust, and shared conformance tests
make check   # test plus format, Clippy, and build
```

Public behavior changes follow this order:

1. Update the normative specification.
2. Add a shared conformance case.
3. Implement and test both runtimes.
4. Run `make check`.

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup and contribution guidance,
[SECURITY.md](SECURITY.md) for private vulnerability reporting, and
[CHANGELOG.md](CHANGELOG.md) for v0.1 release notes.

## License

Hardpoint Guardian is licensed under [Apache-2.0](LICENSE).
