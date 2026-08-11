.PHONY: test test-python test-rust check

test: test-python test-rust

test-python:
	PYTHONPATH=src uv run --with pyyaml --with pytest python -m pytest tests

test-rust:
	cargo test

check: test
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo build
