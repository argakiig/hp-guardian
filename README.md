# Hardpoint Guardian (hp-guard)

A declarative policy engine for agentic guardrails and enforcement. It reads YAML policy files, evaluates tool calls against typed rules, and returns decisions with matched rules — stateless, fast, and auditable.

## TL;DR

```python
from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall

POLICY = """
agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
"""

engine = PolicyParser.parse(POLICY)
call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "http://example.com"])
decision = engine.resolve_call(call)
print(decision.action)  # → Action.DENY
```

## Installation

```bash
pip install pyyaml  # only production dependency
```

Requires **Python 3.14+**.

## Quick Start

### 1. Write a policy file (`policy.yaml`)

```yaml
global:
  rate_limit: 100/min
  log_all: true
  default_action: allow

agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
      write_file:
        rules:
          - action: deny
            condition:
              path_pattern: "/etc/*"
```

### 2. Parse and enforce

```python
from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall
from hp_guard.logging import AuditLogger

with open("policy.yaml") as f:
    engine = PolicyParser.parse(f.read())

call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "http://x.com"])
decision = engine.resolve_call(call)

logger = AuditLogger()
entry = logger.log(call, decision)
print(entry)
# {
#   "timestamp": "2026-08-10T12:00:00+00:00",
#   "agent": "research-bot",
#   "tool": "curl",
#   "args": ["--delete", "http://x.com"],
#   "decision": "deny",
#   "matched_rules": [0]
# }
```

## Architecture

hp-guard has four modules:

| Module | Responsibility |
|--------|----------------|
| `models` | Typed dataclasses — `Rule`, `PolicyCall`, `Decision`, and the `Action` enum |
| `matching` | Target-field matching — rules are ANDed across specified fields |
| `conditions` | Conditional evaluation — e.g. `args_match` regex on tool arguments |
| `engine` | Rule resolution — finds the best matching rule using precedence |
| `parser` | YAML policy → `Engine` conversion |
| `logging` | Audit log entries with timestamp, call details, and decision |

### Precedence Model

When multiple rules match:

1. **Specificity wins** — rules with more target fields (agent + tool) beat broader ones (agent only)
2. **Deny overrides allow** — among rules at the same specificity level, a deny beats an allow
3. **Conditions must also pass** — `args_match`, etc. are evaluated before a rule is considered

If no rules match, the call defaults to `allow`.

## API Reference

### `Action` Enum

| Value | Behavior |
|-------|----------|
| `ALLOW` | Permit the call (default) |
| `DENY` | Block the call |
| `THROTTLE` | Allow but reduce rate limit |
| `LOG` | Allow and log (informational) |
| `REQUIRE_APPROVAL` | Pause for human decision |
| `REDIRECT` | Redirect to a different tool |

### `Rule`

```python
@dataclass
class Rule:
    action: Action
    target: Dict[str, Any]        # fields like "agent", "tool", "user"
    condition: Dict[str, Any]     # e.g. {"args_match": ".*--delete.*"}
    rule_index: int               # assigned by parser
```

### `PolicyCall`

```python
@dataclass
class PolicyCall:
    agent: str | None = None
    tool: str | None = None
    args: list = field(default_factory=list)
    user: str | None = None
    context: Dict[str, Any] = field(default_factory=dict)
```

### `Engine`

```python
engine = Engine(rules=[rule1, rule2, ...])
decision: Decision = engine.resolve_call(call)
```

### `Decision`

```python
@dataclass
class Decision:
    action: Action
    matched_rules: list[int]  # indices of all rules that matched
```

### `PolicyParser`

```python
engine = PolicyParser.parse(yaml_string)
```

### `AuditLogger`

```python
logger = AuditLogger()
entry: dict = logger.log(call, decision)
```

## Running Tests

```bash
python -m pytest tests/ -v
```

### Test Coverage

| Module | Tests |
|--------|-------|
| `models` | Rule/PolicyCall construction, enum values, defaults |
| `matching` | Target field matching, specificity, empty targets |
| `conditions` | `args_match` regex, no-conditions passthrough |
| `engine` | No-rules default, single rule, specificity precedence |
| `parser` | YAML → Engine conversion, multi-agent policies |
| `logging` | Audit entry fields, timestamp, args inclusion |
| `integration` | Full policy lifecycle end-to-end |

## Policy Language

Policies are YAML with two top-level sections:

- **`global`** — defaults (rate limits, logging, default action)
- **`agents`** — per-agent tool configurations with rules

### Target Fields

All target fields are **ANDed**. If a rule specifies `{"agent": "bot"}`, it matches any tool. If it specifies `{"agent": "bot", "tool": "curl"}`, it only matches curl calls from that agent.

### Conditions

Conditions are evaluated before a rule is considered a match. Currently supported:

| Condition | Description |
|-----------|-------------|
| `args_match` | Regex against concatenated tool arguments |

More conditions are planned: `path_pattern`, `time_window`, `rate_threshold`, `state_match`, and boolean combinators (`and`/`or`/`not`).

## Example Policies

### Block destructive operations

```yaml
agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
```

### Log all file writes

```yaml
agents:
  general-purpose:
    tools:
      write_file:
        rules:
          - action: log
```

### Multi-agent isolation

```yaml
agents:
  bot-a:
    tools:
      read_memory:
        rules:
          - action: deny
            target:
              user: "bot-b"
```

## Roadmap (post v0.1)

- [ ] `path_pattern` condition
- [ ] Global default action support in parser
- [ ] Multi-action rules (e.g. `deny` + `log`)
- [ ] Boolean condition combinators (`and`/`or`/`not`)
- [ ] Policy simulator (test against call traces without executing)
- [ ] Stateful enforcement (rate limits, call depth tracking)
- [ ] Hot-reload policy files at runtime
- [ ] CLI entry point (`main.py`)

## License

Unlicense / Public Domain.
