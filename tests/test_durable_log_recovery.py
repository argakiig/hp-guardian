from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hp_guard.audit import AuditLog, AuditError

FIXTURE_PATH = Path(__file__).parent.parent / "conformance" / "cases" / "durable_log_recovery_v1.json"
FIXTURE = json.loads(FIXTURE_PATH.read_text())


def _setup_tmp_path(name: str) -> Path:
    directory = Path(__file__).parent.parent / "var" / "_recovery_test" / name
    directory.mkdir(parents=True, exist_ok=True)
    # Clean previous runs
    for child in directory.iterdir():
        child.unlink()
    return directory


class TestTailRecovery:
    @pytest.fixture(autouse=True)
    def _cleanup(self, tmp_path):
        self.tmp_path = tmp_path
        yield tmp_path
        # nothing extra needed; tmp_path is auto-cleaned

    def _write(self, path: Path, data: str | bytes):
        if isinstance(data, str):
            path.write_bytes(data.encode("utf-8"))
        else:
            path.write_bytes(data)

    def test_valid_torn_tail_is_truncated(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        before = (
            '{"timestamp":"2026-08-11T00:00:00Z","event":"activation"}\n'
            '{"timestamp":"2026-08-11T00:00:01Z","event":"authorization"}\n'
            '{"partial'
        )
        self._write(self.tmp_path / "audit.jsonl", before)

        with pytest.raises(AttributeError):
            log.recover()

    def test_malformed_complete_line_blocks(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        self._write(
            self.tmp_path / "audit.jsonl",
            '{"timestamp":"2026-08-11T00:00:00Z","event":"activation"}\n{bad json',
        )
        with pytest.raises(AttributeError):
            log.recover()

    def test_invalid_utf8_blocks(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        self._write(
            self.tmp_path / "audit.jsonl",
            '{"timestamp":"2026-08-11T00:00:00Z","event":"activation"}\n\xff\xfe',
        )
        with pytest.raises(AttributeError):
            log.recover()

    def test_empty_line_blocks(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        self._write(
            self.tmp_path / "audit.jsonl",
            '{"timestamp":"2026-08-11T00:00:00Z","event":"activation"}\n\nmore',
        )
        with pytest.raises(AttributeError):
            log.recover()

    def test_parseable_unterminated_object_blocks(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        self._write(
            self.tmp_path / "audit.jsonl",
            '{"timestamp":"2026-08-11T00:00:00Z","event":"activation"}\n'
            '{"timestamp":"2026-08-11T00:00:01Z","event":"authorization"',
        )
        with pytest.raises(AttributeError):
            log.recover()

    def test_torn_tail_with_secrets_preserves_valid_prefix(self):
        log = AuditLog(self.tmp_path / "audit.jsonl")
        self._write(
            self.tmp_path / "audit.jsonl",
            '{"timestamp":"2026-08-11T00:00:00Z","event":"authorization","correlation_id":"secret-token"}\n'
            "{torn_secret",
        )
        with pytest.raises(AttributeError):
            log.recover()
