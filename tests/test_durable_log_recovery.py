from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hp_guard.audit import AuditError, AuditLog


FIXTURE = json.loads(
    (Path(__file__).parent.parent / "conformance" / "cases" / "durable_log_recovery_v1.json").read_text()
)


def _bytes(entry: dict[str, str]) -> bytes:
    if set(entry) == {"utf8"}:
        return entry["utf8"].encode("utf-8")
    if set(entry) == {"hex"}:
        return bytes.fromhex(entry["hex"])
    raise AssertionError(f"invalid fixture file entry: {entry}")


def _path(root: Path, name: str, transaction_id: str | None = None) -> Path:
    active = root / "audit.jsonl"
    if name == "active":
        return active
    if name.startswith("backup_"):
        return active.with_name(f"{active.name}.{name.removeprefix('backup_')}")
    transaction_id = transaction_id or "orphan"
    if name == "stage_active":
        return active.with_name(f"{active.name}.rotation.{transaction_id}.active")
    if name.startswith("stage_backup_"):
        return active.with_name(
            f"{active.name}.rotation.{transaction_id}.backup.{name.removeprefix('stage_backup_')}"
        )
    raise AssertionError(f"unknown fixture path name: {name}")


def _write_case(root: Path, case: dict) -> dict[Path, bytes]:
    manifest = case.get("manifest")
    transaction_id = manifest["transaction_id"] if manifest else None
    before: dict[Path, bytes] = {}
    for name, entry in case.get("files", {}).items():
        path = _path(root, name, transaction_id)
        content = _bytes(entry)
        path.write_bytes(content)
        before[path] = content
    if manifest:
        path = root / "audit.jsonl.rotation.json"
        content = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
        path.write_bytes(content)
        before[path] = content
    return before


def _trigger_recovery(root: Path) -> None:
    AuditLog(root / "audit.jsonl").append({"event": "post_recovery"})


@pytest.mark.parametrize("case", FIXTURE["tail_recovery"], ids=lambda case: case["name"])
def test_tail_recovery_matches_shared_fixture(tmp_path: Path, case: dict) -> None:
    before = _write_case(tmp_path, case)
    expected = case["expect"]

    if expected["error"] is not None:
        with pytest.raises(AuditError) as raised:
            _trigger_recovery(tmp_path)
        assert raised.value.code == expected["error"]
        if expected.get("unchanged"):
            assert {path: path.read_bytes() for path in before} == before
        return

    _trigger_recovery(tmp_path)
    active = (tmp_path / "audit.jsonl").read_bytes()
    assert active.startswith(expected.get("active_prefix", "").encode("utf-8"))
    if expected.get("recovered_tail"):
        assert b'{"partial' not in active
        assert b"{torn" not in active
        assert b"{torn_secret" not in active
        for line in active.splitlines():
            json.loads(line)
    for name, prefix in expected.get("backup_prefixes", {}).items():
        assert _path(tmp_path, name).read_bytes() == prefix.encode("utf-8")


@pytest.mark.parametrize("case", FIXTURE["rotation_recovery"], ids=lambda case: case["name"])
def test_rotation_recovery_matches_shared_fixture(tmp_path: Path, case: dict) -> None:
    before = _write_case(tmp_path, case)
    expected = case["expect"]

    if expected["error"] is not None:
        with pytest.raises(AuditError) as raised:
            _trigger_recovery(tmp_path)
        assert raised.value.code == expected["error"]
        if expected.get("unchanged"):
            assert {path: path.read_bytes() for path in before} == before
        return

    _trigger_recovery(tmp_path)
    assert not (tmp_path / "audit.jsonl.rotation.json").exists()
    assert not list(tmp_path.glob("audit.jsonl.rotation.*"))
    for name, content in expected["backups"].items():
        assert _path(tmp_path, name).read_bytes() == content.encode("utf-8")


def test_second_process_cannot_acquire_the_shared_audit_lease(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            (
                "from hp_guard.audit import AuditLog; "
                f"log = AuditLog({os.fspath(path)!r}); "
                "log.append({'event': 'holder'}); "
                "print('ready', flush=True); "
                "input(); log.close()"
            ),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None
        assert holder.stdout.readline().strip() == "ready"
        with pytest.raises(AuditError) as raised:
            AuditLog(path).append({"event": "contender"})
        assert raised.value.code == FIXTURE["lock_contention"]["expected_error"]
    finally:
        assert holder.stdin is not None
        holder.stdin.write("\n")
        holder.stdin.flush()
        holder.wait(timeout=5)
