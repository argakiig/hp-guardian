from __future__ import annotations

import json
from pathlib import Path

import pytest

from hp_guard import (
    AdapterError,
    AuditError,
    AuditLog,
    AuditedPolicyStore,
    EnforcementRequest,
    InlineEnforcementAdapter,
    PolicyCall,
)


FIXTURE_PATH = Path(__file__).parents[1] / "conformance" / "cases" / "inline_adapter_v1.json"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def _records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _adapter(tmp_path, *, now_unix_ms: int = 1000):
    fixture = _fixture()
    audit_path = tmp_path / "audit.jsonl"
    store = AuditedPolicyStore(fixture["policy"], AuditLog(audit_path))
    return InlineEnforcementAdapter(store, now_unix_ms=lambda: now_unix_ms), audit_path


def test_adapter_matches_shared_allow_and_non_allow_responses(tmp_path):
    fixture = _fixture()
    adapter, _ = _adapter(tmp_path, now_unix_ms=fixture["now_unix_ms"])

    responses = [
        adapter.authorize(EnforcementRequest.from_dict(request)).to_dict()
        for request in fixture["requests"]
    ]

    assert responses == fixture["responses"]


@pytest.mark.parametrize("case", _fixture()["error_cases"], ids=lambda case: case["name"])
def test_adapter_rejects_shared_errors_without_an_authorization_record(tmp_path, case):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path, now_unix_ms=fixture["now_unix_ms"])
    before = _records(audit_path)

    if case["error"] == "invalid_request":
        with pytest.raises(AdapterError) as raised:
            EnforcementRequest.from_dict(case["request"])
    else:
        with pytest.raises(AdapterError) as raised:
            adapter.authorize(EnforcementRequest.from_dict(case["request"]))

    assert raised.value.code == case["error"]
    assert _records(audit_path) == before


@pytest.mark.parametrize(
    "payload",
    [
        {"caller_id": "caller", "correlation_id": "id", "deadline_unix_ms": True, "call": {}},
        {"caller_id": "caller", "correlation_id": "id", "deadline_unix_ms": -1, "call": {}},
        {"caller_id": "caller", "correlation_id": "id", "deadline_unix_ms": 1, "call": {}},
        {
            "caller_id": "caller",
            "correlation_id": "id",
            "deadline_unix_ms": 1,
            "call": {"agent": None, "tool": None, "args": [1], "user": None, "context": {}},
        },
        {
            "caller_id": "caller",
            "correlation_id": "id",
            "deadline_unix_ms": 1,
            "call": {"agent": None, "tool": None, "args": [], "user": None, "context": {"key": 1}},
        },
        {"caller_id": "x" * 257, "correlation_id": "id", "deadline_unix_ms": 1, "call": {}},
        {"caller_id": "é" * 129, "correlation_id": "id", "deadline_unix_ms": 1, "call": {}},
        {"caller_id": "caller", "correlation_id": "x" * 257, "deadline_unix_ms": 1, "call": {}},
    ],
)
def test_request_boundary_strictly_validates_the_complete_request(payload):
    with pytest.raises(AdapterError) as raised:
        EnforcementRequest.from_dict(payload)

    assert raised.value.code == "invalid_request"


def test_request_constructor_cannot_bypass_validation_with_a_malformed_call():
    with pytest.raises(AdapterError) as raised:
        EnforcementRequest("caller", "id", 1, PolicyCall(args=("not", "a", "list")))

    assert raised.value.code == "invalid_request"


@pytest.mark.parametrize(
    "call",
    [
        {"agent": "\ud800", "tool": "shell", "args": [], "user": None, "context": {}},
        {"agent": None, "tool": "\ud800", "args": [], "user": None, "context": {}},
        {"agent": None, "tool": "shell", "args": [], "user": "\ud800", "context": {}},
        {"agent": None, "tool": "shell", "args": ["\ud800"], "user": None, "context": {}},
        {"agent": None, "tool": "shell", "args": [], "user": None, "context": {"\ud800": "value"}},
        {"agent": None, "tool": "shell", "args": [], "user": None, "context": {"key": "\ud800"}},
    ],
)
def test_request_boundary_rejects_lone_surrogates_in_all_call_strings(call):
    with pytest.raises(AdapterError) as raised:
        EnforcementRequest.from_dict(
            {"caller_id": "caller", "correlation_id": "id", "deadline_unix_ms": 1, "call": call}
        )

    assert raised.value.code == "invalid_request"


@pytest.mark.parametrize(
    "request_factory",
    [
        lambda: EnforcementRequest.from_dict(
            {
                "caller_id": "caller",
                "correlation_id": "id",
                "deadline_unix_ms": 1 << 64,
                "call": {"agent": None, "tool": None, "args": [], "user": None, "context": {}},
            }
        ),
        lambda: EnforcementRequest("caller", "id", 1 << 64, PolicyCall()),
    ],
)
def test_request_deadline_cannot_exceed_unsigned_64_bit_range(request_factory):
    with pytest.raises(AdapterError) as raised:
        request_factory()

    assert raised.value.code == "invalid_request"


def test_adapter_revalidates_a_request_call_before_authorization(tmp_path):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path)
    request = EnforcementRequest.from_dict(fixture["requests"][0])
    request.call.args.append(1)

    with pytest.raises(AdapterError) as raised:
        adapter.authorize(request)

    assert raised.value.code == "invalid_request"
    assert [record["event"] for record in _records(audit_path)] == ["activation"]


def test_adapter_rejects_a_mutated_lone_surrogate_before_audit(tmp_path):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path)
    request = EnforcementRequest.from_dict(fixture["requests"][0])
    request.call.context["token"] = "\ud800"

    with pytest.raises(AdapterError) as raised:
        adapter.authorize(request)

    assert raised.value.code == "invalid_request"
    assert [record["event"] for record in _records(audit_path)] == ["activation"]


def test_authorization_audit_includes_metadata_but_not_raw_call_input(tmp_path):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path)
    request = fixture["requests"][0]
    request = {**request, "call": {**request["call"], "args": ["secret"], "context": {"token": "private"}}}

    response = adapter.authorize(EnforcementRequest.from_dict(request))

    record = _records(audit_path)[-1]
    assert response.correlation_id == "req-allow"
    assert record["caller_id"] == "host-a"
    assert record["deadline_unix_ms"] == 1001
    text = audit_path.read_text()
    assert "secret" not in text
    assert "private" not in text
    assert '"args"' not in text
    assert '"context"' not in text


def test_adapter_audit_matches_the_returned_policy_identity_and_decision(tmp_path):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path, now_unix_ms=fixture["now_unix_ms"])

    response = adapter.authorize(EnforcementRequest.from_dict(fixture["requests"][0]))

    record = _records(audit_path)[-1]
    assert record["event"] == "authorization"
    assert record["correlation_id"] == response.correlation_id
    assert record["policy_version"] == response.policy.version
    assert record["policy_digest"] == response.policy.digest
    assert record["decision"] == response.decision
    assert record["matched_rules"] == list(response.matched_rules)


def test_reused_correlation_id_is_audited_as_two_separate_attempts(tmp_path):
    fixture = _fixture()
    adapter, audit_path = _adapter(tmp_path)
    request = EnforcementRequest.from_dict(fixture["requests"][0])

    adapter.authorize(request)
    adapter.authorize(request)

    authorizations = [record for record in _records(audit_path) if record["event"] == "authorization"]
    assert [record["correlation_id"] for record in authorizations] == ["req-allow", "req-allow"]


def test_audit_failure_fails_closed_with_stable_adapter_error(tmp_path):
    fixture = _fixture()
    audit_path = tmp_path / "audit.jsonl"
    audit_log = AuditLog(audit_path)
    store = AuditedPolicyStore(fixture["policy"], audit_log)
    adapter = InlineEnforcementAdapter(store, now_unix_ms=lambda: fixture["now_unix_ms"])

    def fail_write(_record):
        raise AuditError("audit_write_failed", "disk unavailable")

    audit_log.append = fail_write

    with pytest.raises(AdapterError) as raised:
        adapter.authorize(EnforcementRequest.from_dict(fixture["requests"][0]))

    assert raised.value.code == "audit_write_failed"


def test_closed_adapter_maps_the_closed_audit_boundary_to_a_stable_error(tmp_path):
    fixture = _fixture()
    adapter, _ = _adapter(tmp_path, now_unix_ms=fixture["now_unix_ms"])
    adapter.close()

    with pytest.raises(AdapterError) as raised:
        adapter.authorize(EnforcementRequest.from_dict(fixture["requests"][0]))

    assert raised.value.code == "audit_write_failed"
