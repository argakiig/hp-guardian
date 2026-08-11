from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

import pytest

from hp_guard import (
    AuditError,
    AuditLog,
    AuditedPolicyStore,
    OutcomeStatus,
    PolicyCall,
)


POLICY = """version: 1
rules:
  - action: deny
    target:
      agent: bot
      tool: delete_file
"""


def _records(path):
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_snapshot_uses_sha256_of_exact_policy_utf8_text(tmp_path):
    policy = POLICY + "# the trailing newline is part of the identity\n"
    store = AuditedPolicyStore(policy, AuditLog(tmp_path / "audit.jsonl"))

    assert store.active_snapshot.version == 1
    assert store.active_snapshot.digest == hashlib.sha256(policy.encode("utf-8")).hexdigest()


def test_exposed_snapshot_contains_only_immutable_policy_identity(tmp_path):
    store = AuditedPolicyStore(POLICY, AuditLog(tmp_path / "audit.jsonl"))
    snapshot = store.active_snapshot

    assert not hasattr(snapshot, "engine")
    with pytest.raises(FrozenInstanceError):
        snapshot.digest = "replaced"


def test_activation_is_logged_before_the_snapshot_becomes_active(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(POLICY, AuditLog(path))

    assert _records(path) == [
        {
            "timestamp": _records(path)[0]["timestamp"],
            "event": "activation",
            "correlation_id": None,
            "policy_version": 1,
            "policy_digest": store.active_snapshot.digest,
            "agent": None,
            "tool": None,
            "user": None,
            "decision": None,
            "matched_rules": [],
        }
    ]


def test_invalid_reload_keeps_the_active_snapshot_and_does_not_log_activation(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(POLICY, AuditLog(path))
    original = store.active_snapshot

    with pytest.raises(Exception):
        store.reload("version: 2\nrules: []\n")

    assert store.active_snapshot is original
    assert [record["event"] for record in _records(path)] == ["activation"]


def test_activation_audit_failure_keeps_the_previous_snapshot(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(path)
    store = AuditedPolicyStore(POLICY, audit_log)
    original = store.active_snapshot

    def fail_write(_record):
        raise AuditError("audit_write_failed", "disk unavailable")

    audit_log.append = fail_write

    with pytest.raises(AuditError, match="disk unavailable"):
        store.reload("version: 1\nglobal:\n  default_action: deny\n")

    assert store.active_snapshot is original


def test_authorization_is_persisted_before_it_is_returned_and_omits_raw_input(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(POLICY, AuditLog(path))
    call = PolicyCall(
        agent="bot",
        tool="delete_file",
        user="operator",
        args=["/private/secret.txt"],
        context={"api_key": "not-for-audit"},
    )

    authorization = store.authorize(call)

    record = _records(path)[-1]
    assert authorization.decision.action.value == "deny"
    assert record["event"] == "authorization"
    assert record["correlation_id"] == authorization.correlation_id
    assert record["policy_digest"] == store.active_snapshot.digest
    assert record["agent"] == "bot"
    assert record["tool"] == "delete_file"
    assert record["user"] == "operator"
    assert record["decision"] == "deny"
    assert record["matched_rules"] == [0]
    assert "/private/secret.txt" not in path.read_text()
    assert "not-for-audit" not in path.read_text()
    assert '"args"' not in path.read_text()
    assert '"context"' not in path.read_text()


def test_failed_authorization_write_returns_an_audit_error_without_a_decision(tmp_path):
    audit_log = AuditLog(tmp_path / "audit.jsonl")
    store = AuditedPolicyStore(POLICY, audit_log)

    def fail_write(_record):
        raise AuditError("audit_write_failed", "disk unavailable")

    audit_log.append = fail_write

    with pytest.raises(AuditError, match="disk unavailable"):
        store.authorize(PolicyCall(agent="bot", tool="delete_file"))


def test_closed_policy_store_fails_closed_for_every_audit_boundary(tmp_path):
    store = AuditedPolicyStore(POLICY, AuditLog(tmp_path / "audit.jsonl"))
    store.close()

    with pytest.raises(AuditError) as authorization_error:
        store.authorize(PolicyCall(agent="bot", tool="delete_file"))
    assert authorization_error.value.code == "audit_closed"

    with pytest.raises(AuditError) as reload_error:
        store.reload(POLICY)
    assert reload_error.value.code == "audit_closed"


def test_internal_authorization_metadata_preserves_the_supplied_correlation_id(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(POLICY, AuditLog(path))

    authorization = store._authorize_with_metadata(
        PolicyCall(agent="bot", tool="delete_file"),
        correlation_id="host-request-id",
        caller_id="host-a",
        deadline_unix_ms=1234,
    )

    record = _records(path)[-1]
    assert authorization.correlation_id == "host-request-id"
    assert authorization.caller_id == "host-a"
    assert authorization.deadline_unix_ms == 1234
    assert record["caller_id"] == "host-a"
    assert record["deadline_unix_ms"] == 1234

    store.record_outcome(authorization, OutcomeStatus.SUCCEEDED)

    outcome = _records(path)[-1]
    assert outcome["correlation_id"] == "host-request-id"
    assert outcome["caller_id"] == "host-a"
    assert outcome["deadline_unix_ms"] == 1234


def test_reload_cannot_activate_a_new_snapshot_before_an_inflight_authorization_is_written(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(path)
    store = AuditedPolicyStore(POLICY, audit_log)
    original_append = audit_log.append
    authorization_write_started = threading.Event()
    release_authorization_write = threading.Event()
    reload_finished = threading.Event()
    failures = []

    def block_authorization_write(record):
        if record["event"] == "authorization":
            authorization_write_started.set()
            assert release_authorization_write.wait(timeout=1)
        original_append(record)

    audit_log.append = block_authorization_write

    def authorize():
        try:
            store.authorize(PolicyCall(agent="bot", tool="delete_file"))
        except Exception as error:
            failures.append(error)

    def reload():
        try:
            store.reload("version: 1\nglobal:\n  default_action: allow\n")
            reload_finished.set()
        except Exception as error:
            failures.append(error)

    authorization_thread = threading.Thread(target=authorize)
    authorization_thread.start()
    assert authorization_write_started.wait(timeout=1)
    reload_thread = threading.Thread(target=reload)
    reload_thread.start()

    assert not reload_finished.wait(timeout=0.1)
    release_authorization_write.set()
    authorization_thread.join(timeout=1)
    reload_thread.join(timeout=1)

    assert not authorization_thread.is_alive()
    assert not reload_thread.is_alive()
    assert failures == []
    assert [record["event"] for record in _records(path)] == [
        "activation",
        "authorization",
        "activation",
    ]


def test_outcome_is_correlated_with_authorization_and_has_bounded_detail(tmp_path):
    path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(POLICY, AuditLog(path))
    authorization = store.authorize(PolicyCall(agent="bot", tool="delete_file", user="operator"))

    store.record_outcome(authorization, OutcomeStatus.SUCCEEDED, "deleted")

    outcome = _records(path)[-1]
    assert outcome["event"] == "outcome"
    assert outcome["correlation_id"] == authorization.correlation_id
    assert outcome["outcome_status"] == "succeeded"
    assert outcome["outcome_detail"] == "deleted"
    assert outcome["policy_digest"] == store.active_snapshot.digest
    with pytest.raises(ValueError, match="1024"):
        store.record_outcome(authorization, OutcomeStatus.FAILED, "x" * 1025)


def test_audit_log_rotates_by_size_before_the_append(tmp_path):
    path = tmp_path / "audit.jsonl"
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    audit_log = AuditLog(path, max_bytes=1, now=lambda: now)

    audit_log.append({"event": "first"})
    audit_log.append({"event": "second"})

    assert [record["event"] for record in _records(path.with_name("audit.jsonl.1"))] == ["first"]
    assert [record["event"] for record in _records(path)] == ["second"]


def test_audit_log_rotates_by_age_before_the_append(tmp_path):
    path = tmp_path / "audit.jsonl"
    start = datetime(2026, 8, 11, tzinfo=timezone.utc)
    audit_log = AuditLog(path, max_age=timedelta(hours=1), now=lambda: start)
    audit_log.append({"event": "first"})
    old = (start - timedelta(hours=2)).timestamp()
    os.utime(path, (old, old))

    audit_log.append({"event": "second"})

    assert not path.with_name("audit.jsonl.1").exists()
    assert [record["event"] for record in _records(path)] == ["second"]


def test_audit_log_prunes_rotated_files_past_the_maximum_age(tmp_path):
    path = tmp_path / "audit.jsonl"
    start = datetime(2026, 8, 11, tzinfo=timezone.utc)
    audit_log = AuditLog(path, max_age=timedelta(hours=1), now=lambda: start)
    expired = path.with_name("audit.jsonl.1")
    expired.write_text('{"event":"expired"}\n')
    old = (start - timedelta(hours=2)).timestamp()
    os.utime(expired, (old, old))

    audit_log.append({"event": "current"})

    assert not expired.exists()


def test_audit_file_has_owner_only_permissions(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append({"event": "test"})

    assert os.stat(path).st_mode & 0o777 == 0o600


def test_audit_log_rejects_a_symlinked_active_file(tmp_path):
    path = tmp_path / "audit.jsonl"
    target = tmp_path / "audit-target.jsonl"
    target.write_text("original\n")
    path.symlink_to(target)

    with pytest.raises(AuditError, match="regular file"):
        AuditLog(path).append({"event": "test"})

    assert target.read_text() == "original\n"


def test_audit_log_rejects_a_symlink_in_its_rotation_paths(tmp_path):
    path = tmp_path / "audit.jsonl"
    target = tmp_path / "audit-target.jsonl"
    target.write_text("original\n")
    audit_log = AuditLog(path, max_bytes=1)
    audit_log.append({"event": "first"})
    path.with_name("audit.jsonl.1").symlink_to(target)

    with pytest.raises(AuditError, match="regular file"):
        audit_log.append({"event": "second"})

    assert target.read_text() == "original\n"
