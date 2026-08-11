# Contributing to Hardpoint Guardian

Hardpoint Guardian has two equal native implementations: Python and Rust. A
public policy behavior is complete only when both runtimes agree through a
shared conformance case.

## Development setup

Install the prerequisites listed in the [README](README.md), clone the
repository, and run the release gate from its root:

```bash
make check
```

The command uses `uv` for the Python suite and Cargo for the Rust suite. No
global Python package installation is required.

## Change policy behavior

Keep the policy contract ahead of implementation:

1. Update the normative policy specification or approved extension
   specification.
2. Add or change the relevant JSON fixture under `conformance/cases/`.
3. Make both runtimes pass that fixture.
4. Add focused language-local regression tests where they clarify behavior.
5. Run `make check` before opening a pull request.

Do not make one runtime the implicit reference implementation. Do not silently
accept unsupported fields or make an unsupported decision behave like `allow`.

## Documentation changes

Keep public documentation in English Standard Technical style: direct,
specific, and grounded in the implemented contract. Do not describe deferred
roadmap work as available behavior. When an integration boundary changes,
update the README and the relevant specification in the same change.

## Pull requests

- Keep a pull request narrow and include tests for changed behavior.
- Explain the contract change, user-visible effect, and verification command in
  the description.
- Use concise, atomic commits where practical.
- Do not commit build output, local audit logs, credentials, or private policy
  data.

By submitting a contribution, you agree that it is licensed under the
[Apache License 2.0](LICENSE).
