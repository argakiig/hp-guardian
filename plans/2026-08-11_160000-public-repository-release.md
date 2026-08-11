# Implementation Plan: Public Repository Release v0.1

## Order

1. Close condition-language conformance and review; commit it separately.
2. Add license, contributor/security guidance, and GitHub Actions.
3. Rewrite README and add v0.1 changelog/release notes from the implemented
   contract, not future roadmap promises.
4. Perform a clean public-consumer verification and final repository review.

## Risks

- Public docs overstate enforcement: describe the inline adapter as data-only
  and state that host execution remains the integrator's responsibility.
- CI drifts from local checks: run only `make check`.
- Unfinished condition behavior leaks into release: no release note until its
  shared fixture, normative spec update, and independent review are green.

## Verification

Run `make check`, inspect a clean checkout setup path, run `git diff --check`,
and review every public-facing claim against code and tests.
