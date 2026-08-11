# Tasks: Versioned Policy Extension Process

**Spec:** `spec/2026-08-11-versioned-policy-extension-process.md`  
**Plan:** `plans/2026-08-11_151000-versioned-policy-extension-process.md`

## Task 1: Add shared version-selection fixtures

**Description:** Extend the shared v1 conformance file with the version and
v1-field rejection cases required by the approved specification.

**Acceptance criteria:**

- [x] Missing, non-integer, and `version: 2` policies expect
  `unsupported_version`.
- [x] A v2-only field inside a v1 policy expects `invalid_field`.
- [x] Both existing fixture runners execute the added cases unchanged.

**Verification:**

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_v1_conformance.py
cargo test --test test_v1_conformance
```

**Dependencies:** None.  
**Files:** `conformance/cases/v1_core.json`  
**Scope:** XS.

## Task 2: Refactor the Python version dispatcher

**Description:** Split YAML loading, version selection, and v1 parsing while
preserving `PolicyParser.parse` and every existing v1 result.

**Acceptance criteria:**

- [x] YAML is loaded once and routed by its declared integer version.
- [x] `version: 1` uses a dedicated v1 parser path.
- [x] Unsupported versions and v1 parser errors retain their stable codes.

**Verification:**

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_parser.py tests/test_v1_conformance.py
```

**Dependencies:** Task 1.  
**Files:** `src/hp_guard/parser.py`, `tests/test_parser.py`  
**Scope:** S.

## Task 3: Refactor the Rust version dispatcher

**Description:** Split the Rust public parse boundary from the private v1
document parser without reparsing YAML or changing v1 resolution behavior.

**Acceptance criteria:**

- [x] `PolicyParser::parse` dispatches from one parsed YAML document.
- [x] `version: 1` uses a dedicated v1 parser path.
- [x] Existing public errors and all shared fixture results remain unchanged.

**Verification:**

```bash
cargo test --test test_parser
cargo test --test test_v1_conformance
```

**Dependencies:** Task 1.  
**Files:** `src/parser.rs`, `tests/test_parser.rs`  
**Scope:** S.

## Checkpoint: Cross-runtime dispatch compatibility

- [x] Tasks 1–3 are complete.
- [x] `make check` passes.
- [x] Existing shared v1 cases retain their action and matched-rule order.
- [x] No v2 parser or v2 field is accepted.

## Task 4: Make Python package exports explicit

**Description:** Replace public-API `# noqa: F401` suppressions with an
`__all__` declaration and prove that the package-root imports remain stable.

**Acceptance criteria:**

- [x] `src/hp_guard/__init__.py` declares the intended public names in
  `__all__`.
- [x] The module contains no `# noqa` directive.
- [x] Importing every declared public name from `hp_guard` succeeds.

**Verification:**

```bash
PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests/test_public_api.py
```

**Dependencies:** Tasks 2 and 3.  
**Files:** `src/hp_guard/__init__.py`, `tests/test_public_api.py`  
**Scope:** XS.

## Completion Checkpoint

- [x] `make check` passes.
- [x] `git diff --check` passes.
- [x] The spec, plan, tasks, and code changes have been reviewed together.
- [x] No new dependency, v2 grammar, side effect, or stateful behavior was
  introduced.
