# Implementation Plan: Boolean and Temporal Conditions

## Architecture

Normalize and validate condition mappings during policy parsing, then evaluate
the bounded tree with a clock supplied by the engine. Leaf-only mappings retain
their current implicit-AND behavior; composition nodes have one operator and no
leaf siblings.

## Slices

1. Define shared AST/time fixtures and stable errors.
2. Add Python parser validation and injected-clock evaluation.
3. Add the equivalent Rust implementation in parallel.
4. Verify v1 compatibility, limits, UTC boundaries, and cross-runtime output.

## Risks

- Different loader/clock behavior: require exact UTC strings and shared
  timestamp fixtures.
- Recursive policy exhaustion: validate 32-level/128-node limits before use.
- Compatibility regression: run existing v1 conformance unchanged.

## Verification

Run focused condition tests after each runtime slice, then `make check` and
`git diff --check`.
