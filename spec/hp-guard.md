# Hardpoint Guardian — Product Vision v0.1

> This document records the broad product vision. The currently implemented,
> normative contract for both runtimes is [Policy Language v1](policy-language-v1.md).
> Fields described here that are absent from v1, including rate limits, memory
> policy, scripting, and multi-action rules, are deferred capabilities and must
> not be accepted silently by a v1 runtime.

## Overview

Hardpoint Guardian (hp-guard) is a policy engine for agentic guardrails and enforcement. It provides declarative rule definitions with programmatic extensions, enforcing constraints on model input/output, tool calls, memory access, environment, and resource consumption.

## Goals

- **Declarative policy language** that is human-readable and auditable
- **Hybrid enforcement** — declarative rules with a scripting layer for context-aware logic
- **Stateless-first** — simple, correct enforcement for single calls; stateful as an optional extension
- **Clear precedence** — rules that combine predictably without edge cases
- **Simulation mode** — test policies against tool calls without running real agents
- **Minimal trust assumptions** — enforcement at a layer the agent cannot bypass

## Non-Goals

- Agent runtime (this is the guardrail, not the agent)
- Model training or fine-tuning
- Security scanning or vulnerability assessment
- Full sandboxing or isolation (blast radius containment only)

## Architecture

### Policy Engine Components

1. **Rule Parser** — reads policy definitions, converts to internal representation
2. **Enforcement Layer** — applies rules at runtime, logs violations, blocks calls
3. **Policy Simulator** — tests rules against tool call traces without executing them
4. **Audit Logger** — records all decisions, violations, and policy changes

### Enforcement Modes

The engine supports multiple enforcement patterns:

| Mode | Description | Trust Model |
|------|-------------|-------------|
| Proxy | Everything routes through the enforcement gateway | Trust minimal — agent doesn't see enforcement |
| Sidecar | Enforcement lives alongside the agent process | Trust low — separate process, coordinated |
| Inline | Enforcement is embedded in the agent | Trust moderate — agent is modified |

Mode selection determines how the engine integrates with the agent. The policy language and rule engine are mode-agnostic.

## Policy Language

### Policy Structure

Every policy consists of three parts:

- **Target** — what the rule applies to (agent, tool, user, context)
- **Action** — what to do when the rule matches
- **Condition** — when the rule applies

### Rule Format

```yaml
rules:
  - target:
      agent: "research-bot"
      tool: "curl"
    action: "deny"
    condition:
      args_match: ".*--delete.*"
```

### Rule Fields

#### Target

The target specifies which resources the rule applies to.

- `agent` — agent identifier (optional, defaults to global)
- `tool` — tool identifier or pattern (optional)
- `user` — user or role identifier (optional)
- `context` — context key-value pairs (optional)

All target fields are ANDed. If only some are specified, the rule applies to all values of unspecified fields.

#### Action

The action determines what happens when the rule matches.

| Action | Behavior |
|--------|----------|
| `allow` | Permit the call (default if no rules match) |
| `deny` | Block the call |
| `throttle` | Allow but slow down (reduce rate limit) |
| `log` | Allow and log (informational only) |
| `require_approval` | Pause and await human decision |
| `redirect` | Redirect the call to a different tool |

Multiple actions can be combined: `allow + log` means allow and log.

#### Condition

The condition specifies when the rule applies.

- `args_match` — regex pattern matching tool arguments
- `path_pattern` — path pattern matching for file operations
- `time_window` — time range when rule is active
- `rate_threshold` — only applies when rate exceeds threshold
- `state_match` — only applies when previous call state matches
- `and` / `or` / `not` — boolean combination of conditions

Conditions without `and`/`or`/`not` are ANDed.

### Precedence Model

Rules are evaluated in this order:

1. **Scope precedence** — agent > tool > global (more specific wins)
2. **Action priority** — deny > require_approval > throttle > allow
3. **Specificity** — rules with more target fields match first

When conflicting rules exist:
- A specific deny overrides a global allow
- A global deny cannot be overridden by a specific allow
- A specific allow overrides a specific deny (but not a specific deny from a higher scope)

### Global Defaults

```yaml
global:
  rate_limit: 100/min
  log_all: true
  default_action: allow
```

Global defaults apply when no rules match.

## Policy Example

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
        rate_limit: 20/min
      read_file:
        rules:
          - action: allow
            condition:
              path_pattern: "/tmp/*"
      write_file:
        rules:
          - action: deny
            condition:
              path_pattern: "/etc/*"
    memory:
      read: { scope: "own" }
      write: { scope: "own" }

  general-purpose:
    tools:
      execute:
        rules:
          - action: deny
            condition:
              args_match: ".*rm -rf.*"
    memory:
      read: { scope: "own", "shared" }
      write: { scope: "own" }
```

## Enforcement API

### Inputs

The enforcement layer receives:

```json
{
  "agent": "research-bot",
  "tool": "curl",
  "args": ["--delete", "http://example.com/api"],
  "user": "user-123",
  "context": {
    "phase": "prompt",
    "rate": 5
  },
  "memory_scope": "own"
}
```

### Outputs

The enforcement layer returns:

```json
{
  "decision": "deny",
  "matched_rules": [
    {
      "rule_index": 0,
      "action": "deny",
      "condition": { "args_match": ".*--delete.*" }
    }
  ],
  "log_entry": {
    "timestamp": "2026-08-10T12:00:00Z",
    "agent": "research-bot",
    "tool": "curl",
    "decision": "deny",
    "matched_rules": [0]
  }
}
```

### Edge Cases

The engine handles these edge cases explicitly:

- **Nested tool calls** — inner call inherits outer agent's policy; inner policy overrides if specified
- **Recursive execution** — prevented by tracking call depth and enforcing max depth limit
- **Cross-agent communication** — each agent's memory access is bounded by its own policy
- **Dynamic tool discovery** — unknown tools default to `default_action`
- **Policy hot reload** — new rules applied after processing current call

## Simulation Mode

The policy simulator tests rules against tool call traces without executing them.

### Inputs

- Policy file
- Tool call trace (JSON array)

### Outputs

- For each call in the trace: decision, matched rules, would-have-been output

### Use Cases

- Validate rules before deploying
- Test edge cases without running real agents
- Compare policy versions
- Audit historical behavior

## Testing Requirements

- **Unit tests** — test each rule type and condition separately
- **Integration tests** — test rule combinations and precedence
- **Simulator tests** — test against traces for edge cases
- **Performance tests** — test enforcement latency under load

## Future Extensions

- **Stateful enforcement** — track state across calls for rate limits, multi-hop reasoning
- **Scripting layer** — extend conditions with Python/JavaScript for context-aware logic
- **Multi-agent state** — enforce boundaries across shared memory
- **Temporal policies** — rules that change over time
- **Granularity** — token-level enforcement (beyond tool call level)

## Next Steps

1. Implement rule parser (YAML → internal representation)
2. Implement basic enforcement layer (stateless, deny/allow/throttle)
3. Implement policy simulator
4. Add scripting layer for condition extensions
5. Add stateful enforcement
6. Write integration tests
