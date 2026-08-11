from datetime import datetime

import pytest

from hp_guard.models import Action, PolicyCall, PolicyError
from hp_guard.parser import PolicyParser


def resolve_at(policy: str, instant: str, call: PolicyCall | None = None):
    now = datetime.fromisoformat(instant.replace("Z", "+00:00"))
    return PolicyParser.parse(policy).resolve_call_at(call or PolicyCall(), now)


def test_boolean_operators_and_existing_leaves_evaluate_with_an_injected_clock():
    policy = """
version: 1
rules:
  - action: deny
    condition:
      all:
        - args_match: '^write .*$'
        - any:
            - path_pattern: /etc/*
            - not:
                time_window:
                  start: '2026-08-11T12:00:00Z'
                  end: '2026-08-11T13:00:00Z'
"""

    assert resolve_at(
        policy,
        "2026-08-11T12:30:00Z",
        PolicyCall(args=["write", "/etc/hosts"]),
    ).action is Action.DENY
    assert resolve_at(
        policy,
        "2026-08-11T12:30:00Z",
        PolicyCall(args=["write", "/tmp/config"]),
    ).action is Action.ALLOW


def test_empty_all_is_true_and_empty_any_is_false():
    decision = resolve_at(
        """
version: 1
rules:
  - action: deny
    condition:
      all: []
  - action: require_approval
    condition:
      any: []
""",
        "2026-08-11T12:30:00Z",
    )

    assert decision.action is Action.DENY
    assert decision.matched_rules == [0]


@pytest.mark.parametrize(
    ("instant", "expected"),
    [
        ("2026-08-11T11:59:59Z", Action.ALLOW),
        ("2026-08-11T12:00:00Z", Action.DENY),
        ("2026-08-11T12:59:59Z", Action.DENY),
        ("2026-08-11T13:00:00Z", Action.ALLOW),
    ],
)
def test_time_window_is_start_inclusive_and_end_exclusive(instant: str, expected: Action):
    decision = resolve_at(
        """
version: 1
rules:
  - action: deny
    condition:
      time_window:
        start: '2026-08-11T12:00:00Z'
        end: '2026-08-11T13:00:00Z'
""",
        instant,
    )

    assert decision.action is expected


@pytest.mark.parametrize(
    "condition",
    [
        "all:\n        - args_match: x\n      path_pattern: /tmp/*",
        "all: []\n      any: []",
        "not: []",
        "all: {}",
        "time_window:\n        start: '2026-08-11T12:00:00Z'",
        "time_window:\n        start: '2026-08-11T12:00:00+00:00'\n        end: '2026-08-11T13:00:00Z'",
        "time_window:\n        start: '2026-08-11T13:00:00Z'\n        end: '2026-08-11T12:00:00Z'",
    ],
)
def test_invalid_boolean_and_temporal_shapes_have_stable_error_codes(condition: str):
    policy = f"""
version: 1
rules:
  - action: deny
    condition:
      {condition}
"""

    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)

    assert error.value.code == "invalid_condition"


def test_condition_depth_is_bounded_before_policy_activation():
    condition = "args_match: x"
    for _ in range(32):
        condition = "all:\n  - " + condition.replace("\n", "\n    ")
    policy = "version: 1\nrules:\n  - action: deny\n    condition:\n      " + condition.replace(
        "\n", "\n      "
    )

    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)

    assert error.value.code == "invalid_condition"


def test_condition_nodes_are_bounded_before_policy_activation():
    children = "\n".join("        - {}" for _ in range(128))
    policy = f"""
version: 1
rules:
  - action: deny
    condition:
      all:
{children}
"""

    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)

    assert error.value.code == "invalid_condition"
