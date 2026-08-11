# Hardpoint Guardian

Hardpoint Guardian is a declarative policy engine for agentic tool calls. It
ships two native runtimes with one shared contract:

- Python for Python agents: `src/hp_guard/`
- Rust for Rust agents: `src/*.rs`

Neither runtime is the reference implementation. [Policy Language v1](spec/policy-language-v1.md)
and the executable [conformance cases](conformance/README.md) define behavior.

## What v1 does

- Strictly validates policy YAML and rejects unknown enforcement fields.
- Applies `allow`, `deny`, `throttle`, `log`, `require_approval`, and `redirect`
  decisions with deterministic precedence.
- Supports `args_match`, lexical `path_pattern`, and agent/tool/user/context
  targets.
- Returns the selected action and every matching rule index.
- Produces typed audit records that serialize to natural JSON values.

v1 is stateless. Rate limits, redirect execution, multi-action rules, memory
rules, scripting, and boolean condition combinators are intentionally rejected
until both runtimes support them.

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
filesystem sandbox. `args_match` uses a small language-native matcher shared
by both runtimes; groups, character classes, look-arounds, and backreferences
are rejected.
Ambiguous YAML scalar-looking identifiers such as `yes`, `2026-08-11`, or
`012` are rejected to keep both loaders deterministic.

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

Run the test suite through `uv`; it supplies the Python dependencies without
requiring a global installation:

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

`PolicyParser::parse` returns `Result<Engine, PolicyError>`; use
`PolicyError::code()` when a caller needs a stable language-neutral error code.

## Verification

```bash
make test     # Python suite, Rust suite, and shared fixture runners
make check    # test plus Rust format, lint, and build checks
```

The shared cases in `conformance/cases/` are a release gate: a policy semantic
changes only after both runtimes pass its new fixture.

## Development contract

1. Change [Policy Language v1](spec/policy-language-v1.md) before changing a
   public behavior.
2. Add a shared conformance case first.
3. Implement and test it in both runtimes.
4. Run `make check` before merging.
