# Spec: Policy Simulator and Trace Format

**Status:** Approved.

## Objective

Provide a host-local, deterministic simulator that replays recorded tool-call
inputs against one or two validated policies. It must help an operator review a
policy change without executing tools, invoking an adapter, writing an audit
event, or mutating runtime state.

## Contract

- A trace is UTF-8 JSON Lines. Blank lines are ignored; JSON arrays and a
  header record are not supported.
- Each non-blank line is a trace event with an exact integer `version: 1`, a
  positive `sequence` that is consecutive from `1`, and a normalized `call`.
  `event_id` is optional and, when present, is a non-empty string.
- `call` permits only `agent`, `tool`, `args`, `user`, and `context`.
  Agent, tool, and user are strings or null; args is an array of strings; and
  context is a string-to-string map. Unknown fields and other JSON shapes are
  rejected.
- An optional `expected` object records the historical policy version, a
  lowercase 64-character SHA-256 digest, decision, and matched-rule indices.
  It is comparison metadata only; it never changes a simulated decision.
- The simulator accepts one baseline policy and an optional candidate policy.
  It parses both before emitting output. A valid trace produces one JSON Lines
  report record per input event, in sequence order.
- Each report record contains `version`, `sequence`, optional `event_id`, the
  optional expected metadata, and `results`. Every result contains the policy
  version/digest, decision, matched-rule indices, and `matches_expected` when
  the expected policy identity is the same. With two policies, a `comparison`
  object reports `action_changed` and `matched_rules_changed`.
- Reports never echo raw arguments or context. The simulator emits no summary
  record and does not provide a human-oriented table in this release.
- Trace errors use stable codes: `invalid_trace_json`,
  `invalid_trace_record`, `unsupported_trace_version`,
  `invalid_trace_sequence`, `invalid_trace_call`, and
  `invalid_trace_expected`. CLI errors are a JSON object on stderr containing
  the code and line number, exit non-zero, and emit no partial stdout.

An event and its single-policy report use these exact field names:

```json
{"version":1,"sequence":1,"event_id":"remove","call":{"agent":"bot","tool":"shell","args":["rm","-rf","/tmp/x"],"user":null,"context":{}},"expected":{"policy":{"version":1,"sha256":"8a9221029667d9196eefd2b364e9cb2dfe098b2356acc777c8ebae09889a2e7e"},"decision":"deny","matched_rules":[0]}}
{"version":1,"sequence":1,"event_id":"remove","expected":{"policy":{"version":1,"sha256":"8a9221029667d9196eefd2b364e9cb2dfe098b2356acc777c8ebae09889a2e7e"},"decision":"deny","matched_rules":[0]},"results":[{"policy":{"version":1,"sha256":"8a9221029667d9196eefd2b364e9cb2dfe098b2356acc777c8ebae09889a2e7e"},"decision":"deny","matched_rules":[0],"matches_expected":true}]}
```

## Tech Stack and Commands

Use existing standard-library JSON and hashing support in Python and existing
`serde_json` plus `sha2` in Rust. Do not add a CLI framework.

```bash
PYTHONPATH=src uv run --with pyyaml python -m hp_guard.simulate \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml
cargo run --bin hp-guard-simulate -- \
  --policy baseline.yaml --trace calls.jsonl --compare candidate.yaml
make check
```

## Project Structure

- `src/hp_guard/simulator.py` and `src/simulator.rs`: pure trace validation and
  simulation APIs.
- `src/hp_guard/simulate.py` and `src/bin/hp-guard-simulate.rs`: dependency-free
  command-line entry points.
- `conformance/cases/simulator_v1.json`: shared trace and report fixtures.
- `tests/test_simulator.py` and `tests/test_simulator.rs`: API, CLI, and
  malformed-input regressions.

## Code Style

Keep the trace boundary strict and normalize before evaluation. Reports derive
only from normalized data and engine decisions:

```python
report = SimulationReport(
    sequence=event.sequence,
    results=[simulate_policy(policy, event.call) for policy in policies],
)
```

## Testing Strategy

Add shared fixtures first for allow, deny, historical expectation matching,
policy-change comparison, malformed JSON, invalid ordering, and invalid call
shapes. Unit-test the pure API in both runtimes and integration-test each CLI
for JSONL stdout, stable stderr errors, no partial output, and absence of an
execution or audit side effect.

## Boundaries

- **Always:** parse policies and the complete trace before writing stdout;
  preserve order; omit raw args/context from reports; use the engine only.
- **Ask first:** JSON array support, human/table output, persistent reports,
  state seeds, new trace versions, or execution-adapter integration.
- **Never:** execute a tool or script, write an audit record, apply a redirect,
  contact an approval handler, or use persistent state during simulation.

## Success Criteria

- Equivalent v1 policies and traces produce byte-equivalent JSON reports in
  Python and Rust.
- A two-policy replay states action and matched-rule differences per event.
- Invalid policies or traces produce stable failures without partial output.
- Simulator paths cannot invoke tool execution, audit logging, or mutable
  state.
