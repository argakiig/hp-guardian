# Hardpoint Guardian

Hardpoint Guardian is a declarative policy engine for agentic tool calls. It
provides two native runtimes that implement a shared policy contract:

- Python for Python agents: `src/hp_guard/`
- Rust for Rust agents: `src/*.rs`

Neither runtime is the reference implementation. [Policy Language v1](spec/policy-language-v1.md)
and the executable [conformance cases](conformance/README.md) define the
normative behavior.

## v1 capabilities

- Validates policy YAML strictly and rejects unknown enforcement fields.
- Resolves `allow`, `deny`, `throttle`, `log`, `require_approval`, and
  `redirect` decisions using deterministic precedence.
- Supports `args_match`, lexical `path_pattern`, and agent, tool, user, and
  context targets.
- Returns the selected action and the index of every matching rule.
- Produces typed audit records that serialize to natural JSON values.

v1 is stateless. It rejects rate limits, redirect execution, multi-action
rules, memory rules, scripting, and boolean condition combinators until both
runtimes support them.

## Policy example

```yaml
version: 1
global:
  default_action: allow

agents:
  research-bot:
    tools:
      write_file:
        rules:
          - id: deny-system-writes
            action: deny
            condition:
              path_pattern: /etc/*
```

`path_pattern` is lexical: it does not canonicalize paths or enforce a
filesystem sandbox. `args_match` uses a small, language-native pattern matcher
shared by both runtimes. Groups, character classes, look-arounds, and
backreferences are rejected.
Ambiguous YAML scalar-looking identifiers such as `yes`, `2026-08-11`, or
`012` are rejected so that both loaders behave deterministically.

## Python

Run from the repository root:

```python
from hp_guard.models import PolicyCall, PolicyError
from hp_guard.parser import PolicyParser

policy = """
version: 1
rules:
  - action: deny
    target:
      tool: shell
    condition:
      args_match: "^rm .*"
"""

try:
    engine = PolicyParser.parse(policy)
except PolicyError as error:
    print(error.code)
    raise

decision = engine.resolve_call(PolicyCall(tool="shell", args=["rm", "-rf", "/tmp/x"]))
assert decision.action.value == "deny"
```

Run the Python test suite through `uv`, which provides the required
dependencies without a global installation:

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests
```

## Rust

```rust
use hp_guard::{PolicyCall, PolicyParser};

let policy = r#"
version: 1
global:
  default_action: deny
"#;
let engine = PolicyParser::parse(policy)?;
let decision = engine.resolve_call(&PolicyCall::default());
assert_eq!(decision.action.as_str(), "deny");
```

`PolicyParser::parse` returns `Result<Engine, PolicyError>`. Use
`PolicyError::code()` when a caller requires a stable, language-neutral error
code.

## Offline policy simulation

The simulator replays JSON Lines tool-call traces without executing tools,
writing audit records, or mutating policy state. It accepts one baseline policy
and an optional candidate policy, then emits one JSON Lines report per trace
event. Reports omit raw arguments and context.

```bash
PYTHONPATH=src uv run --with pyyaml python -m hp_guard.simulate \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml

cargo run --bin hp-guard-simulate -- \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml
```

Trace events require `version: 1`, consecutive positive `sequence` values, and
a normalized `call` object. The complete format, stable errors, and shared
examples are defined in [Policy Simulator and Trace Format](spec/2026-08-11-policy-simulator-and-trace-format.md).

## Inline enforcement

The inline adapter validates a host request, rejects an expired deadline,
writes the required authorization audit record, and returns data for the host
to execute. It never invokes a tool itself. Only an `allow` response contains
an effect; every other policy decision is terminal for this release.

Requests require a caller ID, a retry-stable correlation ID, a Unix-millisecond
deadline, and a normalized policy call. The complete API and error contract are
defined in [Inline Enforcement Adapter](spec/2026-08-11-inline-enforcement-adapter.md).

## Verification

```bash
make test     # Python suite, Rust suite, and shared fixture runners
make check    # test plus Rust format, lint, and build checks
```

The shared cases in `conformance/cases/` are a release gate. A policy semantic
may change only after both runtimes pass the corresponding new fixture.

## Development contract

1. Change [Policy Language v1](spec/policy-language-v1.md) before changing a
   public behavior.
2. Add a shared conformance case first.
3. Implement and test it in both runtimes.
4. Run `make check` before merging.
