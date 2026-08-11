# Implementation Plan: v2 Fixed-Window Rate Limits

## Overview

Deliver the approved, host-local v2 quota contract in small vertical slices.
The pure engines stay deterministic and state-free; an explicit rate-limited
store performs atomic consumption after static rule selection.

## Architecture Decisions

- V2 is a parser dispatch branch, leaving v1 parser and fixtures unchanged.
- `rate_limit` attaches only to a winning `allow` rule.
- The in-memory store is a locked, fixed-window counter keyed by policy digest,
  rule index, and normalized `(agent, user, tool)` identity.
- A monotonic injected clock supports deterministic tests and rejects rollback.

## Tasks

1. Add a shared RED v2 fixture and parser tests.
   - Acceptance: valid v2 limits and malformed fields have identical outcomes.
   - Verify: focused conformance runners fail before implementation.
2. Add v2 models/parser dispatch in both runtimes.
   - Acceptance: v1 remains unchanged; v2 exposes a validated rate-limit rule.
   - Verify: parser and v1 suites pass.
3. Add locked in-memory fixed-window stores and rate-limited resolvers.
   - Acceptance: quota, reset, identity isolation, and rollback behavior match.
   - Verify: focused runtime tests and shared fixture pass.
4. Add concurrency and static-decision non-consumption regressions.
   - Acceptance: no more than the configured quota is allowed.
   - Verify: Python threads and Rust threads pass deterministically.
5. Update public docs and run full release checks/review.
   - Acceptance: host-local and non-executing limits are explicit.
   - Verify: `make check` and `git diff --check` pass.

## Risks

- Parser duplication can drift: shared cases and strict v1 regression prevent it.
- Quota races can over-admit: state consumption occurs under one store lock.
- Existing audit/adapter APIs are v1-shaped: this slice intentionally adds a
  separate public rate-limited resolver before any audited adapter integration.
