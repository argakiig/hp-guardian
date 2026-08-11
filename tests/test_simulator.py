from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from hp_guard.models import PolicyError
from hp_guard.simulator import SimulationPolicy, TraceError, simulate_trace


FIXTURE_PATH = Path(__file__).parents[1] / "conformance" / "cases" / "simulator_v1.json"


def _fixture() -> dict:
    return json.loads(FIXTURE_PATH.read_text())


def _jsonl(records: list[dict]) -> str:
    return "\n".join(json.dumps(record, separators=(",", ":"), ensure_ascii=False) for record in records) + "\n"


def _report_json(reports) -> str:
    return "".join(
        json.dumps(report.to_dict(), separators=(",", ":"), ensure_ascii=False) + "\n"
        for report in reports
    )


def test_simulator_matches_the_shared_single_policy_reports_byte_for_byte():
    fixture = _fixture()
    reports = simulate_trace(
        SimulationPolicy.parse(fixture["baseline_policy"]),
        None,
        _jsonl(fixture["trace"]),
    )

    assert _report_json(reports) == _jsonl(fixture["single_reports"])


def test_simulator_matches_the_shared_policy_comparison_reports_byte_for_byte():
    fixture = _fixture()
    reports = simulate_trace(
        SimulationPolicy.parse(fixture["baseline_policy"]),
        SimulationPolicy.parse(fixture["candidate_policy"]),
        _jsonl(fixture["trace"]),
    )

    assert _report_json(reports) == _jsonl(fixture["comparison_reports"])


@pytest.mark.parametrize("case", _fixture()["invalid_cases"], ids=lambda case: case["name"])
def test_simulator_rejects_shared_invalid_cases_before_returning_reports(case):
    fixture = _fixture()
    with pytest.raises(TraceError) as raised:
        simulate_trace(SimulationPolicy.parse(fixture["baseline_policy"]), None, case["jsonl"])

    assert raised.value.code == case["error"]["code"]
    assert raised.value.line == case["error"]["line"]


@pytest.mark.parametrize(
    ("record", "code"),
    [
        ({"version": 2, "sequence": 1, "call": {}}, "unsupported_trace_version"),
        ({"version": 1, "sequence": True, "call": {}}, "invalid_trace_sequence"),
        ({"version": 1, "sequence": 1, "call": {}, "extra": None}, "invalid_trace_record"),
        (
            {
                "version": 1,
                "sequence": 1,
                "call": {"agent": None, "tool": None, "args": [], "user": None, "context": {}, "x": 1},
            },
            "invalid_trace_call",
        ),
        (
            {
                "version": 1,
                "sequence": 1,
                "call": {"agent": None, "tool": None, "args": [], "user": None, "context": {}},
                "expected": {"policy": {"version": 1, "sha256": "A" * 64}, "decision": "allow", "matched_rules": []},
            },
            "invalid_trace_expected",
        ),
    ],
)
def test_simulator_strictly_validates_trace_shapes(record, code):
    fixture = _fixture()
    with pytest.raises(TraceError) as raised:
        simulate_trace(SimulationPolicy.parse(fixture["baseline_policy"]), None, _jsonl([record]))

    assert raised.value.code == code
    assert raised.value.line == 1


def test_simulator_parses_the_entire_trace_before_returning_any_reports():
    fixture = _fixture()
    trace = _jsonl([fixture["trace"][0], {**fixture["trace"][1], "sequence": 3}])

    with pytest.raises(TraceError) as raised:
        simulate_trace(SimulationPolicy.parse(fixture["baseline_policy"]), None, trace)

    assert raised.value.code == "invalid_trace_sequence"
    assert raised.value.line == 2


def test_simulator_rejects_nonstandard_json_constants():
    fixture = _fixture()
    trace = (
        '{"version":NaN,"sequence":1,"call":'
        '{"agent":null,"tool":null,"args":[],"user":null,"context":{}}}\n'
    )

    with pytest.raises(TraceError) as raised:
        simulate_trace(SimulationPolicy.parse(fixture["baseline_policy"]), None, trace)

    assert raised.value.code == "invalid_trace_json"
    assert raised.value.line == 1


def test_simulator_rejects_lone_unicode_surrogates():
    fixture = _fixture()
    trace = (
        '{"version":1,"sequence":1,"event_id":"\\ud800","call":'
        '{"agent":null,"tool":null,"args":[],"user":null,"context":{}}}\n'
    )

    with pytest.raises(TraceError) as raised:
        simulate_trace(SimulationPolicy.parse(fixture["baseline_policy"]), None, trace)

    assert raised.value.code == "invalid_trace_json"
    assert raised.value.line == 1


def test_cli_writes_only_compact_jsonl_reports_after_full_validation(tmp_path):
    fixture = _fixture()
    policy_path = tmp_path / "baseline.yaml"
    trace_path = tmp_path / "calls.jsonl"
    policy_path.write_text(fixture["baseline_policy"])
    trace_path.write_text(_jsonl(fixture["trace"]))

    completed = _run_cli("--policy", str(policy_path), "--trace", str(trace_path))

    assert completed.returncode == 0
    assert completed.stdout == _jsonl(fixture["single_reports"])
    assert completed.stderr == ""


def test_cli_supports_a_candidate_policy_comparison(tmp_path):
    fixture = _fixture()
    baseline_path = tmp_path / "baseline.yaml"
    candidate_path = tmp_path / "candidate.yaml"
    trace_path = tmp_path / "calls.jsonl"
    baseline_path.write_text(fixture["baseline_policy"])
    candidate_path.write_text(fixture["candidate_policy"])
    trace_path.write_text(_jsonl(fixture["trace"]))

    completed = _run_cli(
        "--policy",
        str(baseline_path),
        "--trace",
        str(trace_path),
        "--compare",
        str(candidate_path),
    )

    assert completed.returncode == 0
    assert completed.stdout == _jsonl(fixture["comparison_reports"])
    assert completed.stderr == ""


def test_cli_writes_non_ascii_event_ids_as_utf8_when_stdout_is_ascii(tmp_path):
    fixture = _fixture()
    policy_path = tmp_path / "baseline.yaml"
    trace_path = tmp_path / "calls.jsonl"
    trace = [{**fixture["trace"][0], "event_id": "rémove"}]
    policy_path.write_text(fixture["baseline_policy"])
    trace_path.write_text(_jsonl(trace))

    completed = _run_cli(
        "--policy",
        str(policy_path),
        "--trace",
        str(trace_path),
        environment={"LC_ALL": "C", "PYTHONCOERCECLOCALE": "0", "PYTHONUTF8": "0"},
        interpreter_args=("-X", "utf8=0"),
    )

    expected = [{**fixture["single_reports"][0], "event_id": "rémove"}]
    assert completed.returncode == 0
    assert completed.stdout == _jsonl(expected)
    assert completed.stderr == ""


def test_cli_emits_a_single_json_error_without_partial_stdout(tmp_path):
    fixture = _fixture()
    policy_path = tmp_path / "baseline.yaml"
    trace_path = tmp_path / "calls.jsonl"
    policy_path.write_text(fixture["baseline_policy"])
    trace_path.write_text(_jsonl([fixture["trace"][0], {**fixture["trace"][1], "sequence": 3}]))

    completed = _run_cli("--policy", str(policy_path), "--trace", str(trace_path))

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert json.loads(completed.stderr) == {"code": "invalid_trace_sequence", "line": 2}


def test_cli_reports_policy_errors_as_json_without_stdout(tmp_path):
    policy_path = tmp_path / "invalid.yaml"
    trace_path = tmp_path / "calls.jsonl"
    policy_path.write_text("version: 2\n")
    trace_path.write_text("")

    completed = _run_cli("--policy", str(policy_path), "--trace", str(trace_path))

    assert completed.returncode != 0
    assert completed.stdout == ""
    assert json.loads(completed.stderr) == {"code": "unsupported_version", "line": None}


def test_simulation_policy_preserves_existing_policy_validation():
    with pytest.raises(PolicyError) as raised:
        SimulationPolicy.parse("version: 2\n")

    assert raised.value.code == "unsupported_version"


def test_simulation_policy_cannot_be_forged_with_an_identity_or_engine():
    with pytest.raises(TypeError):
        SimulationPolicy("version: 1\n")
    with pytest.raises(TypeError):
        SimulationPolicy(version=1, digest="0" * 64, _engine=object())


def _run_cli(
    *args: str,
    environment: dict[str, str] | None = None,
    interpreter_args: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    environment = os.environ | {"PYTHONPATH": str(Path(__file__).parents[1] / "src")} | (environment or {})
    return subprocess.run(
        [sys.executable, *interpreter_args, "-m", "hp_guard.simulate", *args],
        capture_output=True,
        check=False,
        encoding="utf-8",
        env=environment,
    )
