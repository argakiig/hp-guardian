# Implementation Plan: Inline Enforcement Adapter

## Architecture

Add one public inline adapter per runtime around the existing audited-policy
store. The adapter normalizes its request first, compares its deadline against
an injected clock, then asks the store to audit authorization with supplied
metadata. It maps only an `allow` authorization to an immutable effect request.
The store gains a private metadata path so caller ID and deadline are retained
in authorization and outcome audit records without exposing an executor.

## Slices

1. Define shared request/response fixtures and extend audit records with
   caller/deadline metadata.
2. Implement Python request validation, adapter, and deadline/audit tests.
3. Implement the equivalent Rust adapter in parallel from the fixture.
4. Verify no-effect failures, audit metadata, repeated correlations, and
   cross-runtime response equivalence.

## Risks

- A caller executes before durable authorization: adapters expose no executor
  hook and only return an effect after the store write succeeds.
- A stale request gains authority: compare against an injected absolute clock
  before evaluating or recording authorization.
- Caller IDs or deadlines disappear from audit evidence: carry them through the
  authorization object and audit record, but retain raw args/context omission.
- Retry IDs imply deduplication unexpectedly: document that repeat IDs are
  recorded as distinct attempts and add a regression.
- Non-allow actions accidentally execute: construct an effect only for
  `Action::Allow` / `Action.ALLOW`.

## Verification

Run focused Python and Rust adapter tests after each slice, then `make check`
and `git diff --check`. Compare shared-fixture responses after normalizing only
runtime-injected timestamps.
