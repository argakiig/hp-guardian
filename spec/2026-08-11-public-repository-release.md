# Spec: Public Repository Release v0.1

**Status:** Approved.

## Objective

Prepare Hardpoint Guardian as a public, source-first v0.1 repository for
application engineers. This release distributes neither Python nor Rust
packages.

## Release Gate

1. Finish the boolean/temporal condition slice: shared conformance fixture,
   Policy Language v1 update, cross-runtime review, and full verification.
2. Add Apache-2.0 licensing and public repository guidance: contribution,
   security-reporting, and supported-scope documents.
3. Make `make check` visible on pushes and pull requests with GitHub Actions.
4. Make README onboarding self-serve: prerequisites, quick start, policy,
   simulator, inline adapter, limitations, verification, and contribution path.
5. Add a v0.1 changelog/release note that names the supported policy features
   and deferred capabilities.

## Boundaries

- **Always:** preserve the dual-runtime conformance gate and declare security
  boundaries and unsupported features plainly.
- **Ask first:** package registry publication, signing, hosted services,
  telemetry, release automation with credentials, or support commitments.
- **Never:** claim sandboxing, automatic tool execution, proxy protection, or
  stateful/rate-limit enforcement that the repository does not provide.

## Success Criteria

- A new contributor can clone, install prerequisites, run `make check`, and
  understand the supported integration boundary from README alone.
- The repository contains an Apache-2.0 license, contribution/security
  guidance, changelog, and CI proof for the same release gate.
- The condition extension meets the same fixture and review standard as every
  other public policy behavior.
