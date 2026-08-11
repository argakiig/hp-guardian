# Spec: Boolean and Temporal Conditions

**Status:** Approved.

## Objective

Extend v1 policy conditions with bounded boolean composition and absolute UTC
time windows, while preserving existing leaf-condition behavior.

## Contract

- Existing leaf conditions (`args_match`, `path_pattern`) remain valid and are
  implicitly ANDed when they appear together in one condition mapping.
- `all` and `any` take an array of condition mappings; `not` takes exactly one
  condition mapping. A mapping cannot mix a boolean operator with leaf fields.
- `all: []` is true; `any: []` is false; `not` without one operand is invalid.
- A `time_window` leaf contains exactly `start` and `end`, both RFC 3339 UTC
  timestamps ending in `Z`. `end` must be later than `start`.
- A window matches when `start <= now < end`. The engine uses an injected UTC
  clock for tests and the current UTC clock in production.
- A rule has at most 32 nested condition levels and 128 total condition nodes.
  Invalid shapes, unknown fields, invalid timestamps, non-UTC offsets,
  excessive depth, and excessive nodes return stable policy errors.

## Commands

```bash
make check
```

## Project Structure

- `src/hp_guard/conditions.py` and `src/conditions.rs`: condition parsing and
  bounded evaluation.
- parser and engine modules: clock propagation and strict validation.
- `conformance/cases/conditions_v1.json`: shared boolean/time fixtures.

## Code Style

Keep policy traversal explicit and bounded:

```python
if "all" in condition:
    return all(evaluate(child, call, now) for child in condition["all"])
```

## Testing Strategy

Add shared fixtures for boolean truth tables, compatibility leaves, empty
operators, nesting/node limits, UTC boundary instants, invalid offsets, and
malformed windows. Test both runtimes under an injected clock.

## Boundaries

- **Always:** preserve existing leaf behavior, validate the full AST before
  evaluation, use UTC, and bound depth/node count.
- **Ask first:** recurring schedules, local timezones, offset-bearing times,
  relative time, stateful predicates, or new leaf conditions.
- **Never:** evaluate host-language code, depend on locale time, or silently
  accept an invalid condition as non-matching.

## Success Criteria

- Equivalent policies produce equal decisions in Python and Rust at identical
  injected timestamps.
- Existing v1 leaf-only policies remain unchanged.
- Invalid or excessive ASTs fail with stable errors before policy activation.
