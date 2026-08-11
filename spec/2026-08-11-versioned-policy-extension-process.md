# Spec: Versioned Policy Extension Process

**Status:** Approved. This is the first implementation slice in the
deferred-capabilities roadmap; it does not add a Policy Language v2 feature.

## Assumptions

1. Policy Language v1 remains a supported, stable contract for both runtimes.
2. Future language additions are introduced by a new integer policy version,
   not by silently expanding v1 or by runtime-specific feature flags.
3. Python and Rust continue to implement the same approved language contract.
4. The first deployment is host-local and fail-closed, but this slice changes
   language selection only; it does not add an adapter, audit persistence, or
   state storage.

## Objective

Provide a controlled path for extending hp-guard without changing the meaning
of existing v1 policies. A contributor must be able to add a future language
version only after documenting its semantics and adding shared executable
fixtures. A policy using an unimplemented version must remain rejected with a
stable error code.

Success means that v1 behavior is demonstrably unchanged, a future version has
an explicit dispatch boundary, and the repository enforces the admission
process for language changes before either runtime accepts new syntax.

## Scope

### In scope

- Document the version-selection and language-admission contract.
- Add a version dispatch boundary in Python and Rust that preserves v1 public
  behavior.
- Define the required shared-fixture coverage for a new language version.
- Document compatibility, migration, and release requirements.

### Out of scope

- Any new policy action, target, condition, or global field.
- Audit storage, policy digests, policy hot reload, adapters, or side effects.
- Capability negotiation, partial v2 profiles, policy migration automation,
  and removal of v1 support.

## Contract

### Version selection

- A policy declares its language with the required top-level integer `version`
  field.
- `version: 1` is routed to the existing v1 parser and evaluator.
- A version is either fully supported by both runtimes or rejected. There is no
  implicit fallback to an older version and no per-runtime feature flag.
- Missing, non-integer, or unsupported versions return the existing stable
  `unsupported_version` error code.
- Version selection must not change the accepted v1 surface, selected action,
  matched-rule ordering, or v1 error-code mapping.

### Admission of a new version

Before implementation begins, a new policy version must provide:

1. A normative specification defining syntax, semantics, precedence, stable
   errors, side effects, security bounds, and compatibility behavior.
2. Shared conformance fixtures that cover supported behavior, malformed input,
   rejection behavior, and interactions with older versions.
3. Python and Rust implementations that pass the same fixtures.
4. Language-local regression tests for implementation details.
5. A release note that identifies the new version, supported runtimes, and any
   migration requirement.

New syntax must never be accepted as an unknown v1 field, nor silently ignored
by an older runtime.

### Compatibility and migration

- Stored policies retain their declared language version.
- A v1 policy remains executable without conversion after a later language
  version is introduced.
- Any policy transformation is an explicit tool with source and destination
  versions. It is not performed automatically during parsing or loading.
- Removing support for a language version requires a separately approved
  deprecation specification with a migration and retention policy.

## Tech Stack

- Python 3.10+ with PyYAML and pytest.
- Rust 2021 with `serde_yaml`, `serde_json`, Cargo test, formatting, Clippy,
  and build checks.
- JSON shared conformance fixtures in `conformance/cases/`.

No new dependency is required for this slice.

## Commands

```bash
make test
make check
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests
cargo test
cargo fmt --check
cargo clippy -- -D warnings
cargo build
```

## Project Structure

```text
spec/policy-language-v1.md                        normative v1 contract
spec/2026-08-11-versioned-policy-extension-process.md  extension admission contract
conformance/cases/*.json                          shared executable behavior
src/hp_guard/parser.py                            Python parse and version dispatch boundary
src/parser.rs                                     Rust parse and version dispatch boundary
tests/test_v1_conformance.py                      Python shared-fixture runner
tests/test_v1_conformance.rs                      Rust shared-fixture runner
```

## Code Style

Keep version handling explicit at the public parser boundary. A later parser
must not rely on an implicit default or reinterpret an older policy.

```rust
match declared_version {
    1 => parse_v1(policy),
    version => Err(PolicyError::UnsupportedVersion { version }),
}
```

The equivalent Python boundary raises `PolicyError("unsupported_version", ...)`.
Both implementations must preserve the current v1 error mapping.

## Testing Strategy

- Add shared fixtures for a valid v1 policy, missing version, non-integer
  version, unsupported future version, and v1 rejection of a proposed future
  field.
- Run each fixture in both runtimes and assert action, matched-rule order, or
  stable error code.
- Retain existing v1 conformance cases unchanged; they are the regression gate
  for the dispatch refactor.
- Add language-local tests only where they prove parser-boundary behavior that
  the shared fixtures cannot express.

## Boundaries

- **Always:** preserve v1 behavior, add a shared fixture before changing policy
  semantics, and run `make check` before review.
- **Ask first:** add a dependency, support a version other than v1, introduce a
  v2 construct, remove version support, or define a policy migration.
- **Never:** silently accept an unsupported field, make one runtime the
  language reference, or fall back from an unsupported version to v1.

## Success Criteria

- Existing v1 fixtures pass unchanged in Python and Rust.
- Unsupported versions continue to return `unsupported_version` in both
  runtimes.
- A proposed v2-only field is rejected when declared in a v1 policy.
- The repository contains a documented checklist for admitting a later version.
- `make check` passes without a new dependency.

## Decision

The next approved policy-language extension will use `version: 2`. It remains
unsupported until its focused specification and shared conformance fixtures are
approved.
