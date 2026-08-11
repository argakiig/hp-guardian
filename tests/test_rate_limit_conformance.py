from __future__ import annotations

import json
from pathlib import Path

import pytest

from hp_guard import InMemoryRateLimitStore, PolicyCall, PolicyError, PolicyParser, RateLimitedPolicyStore


FIXTURE = json.loads(
    (Path(__file__).parents[1] / "conformance" / "cases" / "rate_limits_v2.json").read_text()
)


@pytest.mark.parametrize("case", FIXTURE["cases"], ids=lambda case: case["name"])
def test_v2_rate_limit_cases_match_shared_fixture(case: dict) -> None:
    now = [0]
    store = RateLimitedPolicyStore(
        case["policy"], InMemoryRateLimitStore(), now_monotonic_seconds=lambda: now[0]
    )

    for step in case["steps"]:
        now[0] = step["now"]
        decision = store.resolve(PolicyCall(**step["call"]))
        assert decision.action.value == step["expect"]["decision"]
        assert decision.matched_rules == step["expect"]["matched_rules"]


@pytest.mark.parametrize("case", FIXTURE["error_cases"], ids=lambda case: case["name"])
def test_v2_rate_limit_errors_match_shared_fixture(case: dict) -> None:
    with pytest.raises(PolicyError) as raised:
        if case.get("entry") == "policy_parser":
            PolicyParser.parse(case["policy"])
        else:
            RateLimitedPolicyStore(case["policy"], InMemoryRateLimitStore())
    assert raised.value.code == case["error"]
