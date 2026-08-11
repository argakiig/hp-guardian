import json
from pathlib import Path

import pytest

from hp_guard.models import PolicyCall, PolicyError
from hp_guard.parser import PolicyParser


def test_v1_core_conformance_cases_match_the_python_runtime():
    fixture_path = Path(__file__).parents[1] / "conformance" / "cases" / "v1_core.json"
    cases = json.loads(fixture_path.read_text())

    for case in cases:
        if "expect_error" in case:
            with pytest.raises(PolicyError) as raised:
                PolicyParser.parse(case["policy"])
            assert raised.value.code == case["expect_error"], case["name"]
            continue

        engine = PolicyParser.parse(case["policy"])
        decision = engine.resolve_call(PolicyCall(**case["call"]))
        assert decision.action.value == case["expect"]["decision"], case["name"]
        assert decision.matched_rules == case["expect"]["matched_rules"], case["name"]
