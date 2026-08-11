# Hardpoint Guardian Policy Language v1

## Objective

Hardpoint Guardian has one policy language with two native runtimes: Python
for Python agents and Rust for Rust agents. This document, not either runtime,
is the normative source of behavior.

## Supported v1 Surface

Policies are YAML mappings with an optional `global` mapping, an optional
top-level `rules` sequence, and an optional `agents` mapping. Every mapping
field not defined here is an error.

```yaml
version: 1
global:
  default_action: allow
rules:
  - action: deny
    target:
      tool: shell
    condition:
      args_match: "^rm .*"
agents:
  research-bot:
    tools:
      write_file:
        rules:
          - action: deny
            target:
              context:
                phase: prompt
            condition:
              path_pattern: "/etc/*"
```

`version` is required and currently must be the integer `1`.

To avoid YAML 1.1/1.2 resolver differences, v1 rejects ambiguous scalar-looking
values in string fields: boolean/null words, timestamp-like values, and numeric
forms such as sexagesimal, leading-zero, hexadecimal, octal, or exponent
notation. Use an unambiguous identifier instead; quoting does not alter this
v1 validation rule.

### Rule fields

- `id` — optional stable policy-author-supplied identifier. It must be unique
  when present. It is recommended for audit correlation.
- `action` — required: `allow`, `deny`, `throttle`, `log`,
  `require_approval`, or `redirect`.
- `target` — optional mapping containing `agent`, `tool`, `user`, and/or
  `context`. Target values are strings. `context` is a mapping of string keys
  to string values.
- `condition` — optional mapping containing `args_match` and/or
  `path_pattern`. Conditions are ANDed.

Nested agent/tool rules inherit their enclosing `agent` and `tool` targets.
They may repeat those values but may not override them.

`path_pattern` is lexical, not filesystem-aware: `*` matches any sequence of
characters, including `/`. It does not resolve links, normalize paths, or act
as a sandbox boundary.

`args_match` is a v1 portable pattern language, not either runtime's native
regex. It supports literals, `.`, `*` applied to the preceding literal or `.`,
the boundary anchors `^` and `$`, and escaping `\\`, `.`, `*`, `^`, or `$`.
`.` matches every Unicode code point, including newlines. Character classes,
groups, alternation, `+`, `?`, look-around assertions, and backreferences are
errors. New constructs require a fixture proving equal results in both
runtimes before they enter the contract.

### Resolution

1. All rules whose target and conditions match are recorded in declaration
   order.
2. A matching `deny` wins across scopes.
3. Otherwise, the rule with the most target fields wins.
4. Equal-specificity rules use this action priority:
   `require_approval`, `throttle`, `redirect`, `allow`, `log`.
5. Remaining ties retain YAML declaration order.
6. If no rule matches, `global.default_action` applies; if omitted it is
   `allow`.

Actions are mutually exclusive in v1. Rate limiting, execution of redirects,
boolean condition combinators, memory policy, and multi-action rules are not
v1 behavior and must be rejected instead of ignored.

## Decision and Audit Contract

Both runtimes expose a decision with an action and all matching rule indices.
Each runtime may use its idiomatic error transport (`Result` in Rust,
`PolicyError` exception in Python), but failures must have one of these stable
codes:

- `invalid_yaml`
- `invalid_field`
- `invalid_action`
- `invalid_target`
- `conflicting_target`
- `invalid_condition`
- `invalid_regex`
- `unsupported_version`

Audit entries serialize `timestamp`, `agent`, `tool`, `args`, `decision`, and
`matched_rules` using their natural JSON types. A future compatible change may
add `policy_version`, `policy_sha256`, and `rule_ids`.

## Conformance

`conformance/cases/*.json` are the executable contract. Every supported
runtime must produce the fixture's decision, matching rules, or error code.

## Commands

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests
cargo test
cargo fmt --check
cargo clippy -- -D warnings
```

## Boundaries

- Always: add a shared conformance case before changing semantics in either
  runtime.
- Ask first: introduce a dependency, a stateful policy feature, or a v2 policy
  construct.
- Never: make one runtime the implicit reference implementation or accept an
  unsupported enforcement field.

## Success Criteria

- Python and Rust execute the same shared cases.
- Their successful decisions and matched-rule ordering agree.
- Their policy failures map to the same stable error code.
- Language-local unit tests continue to cover implementation details.
