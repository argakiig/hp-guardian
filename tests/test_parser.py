import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import hp_guard.parser as parser_module
from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall, PolicyError


def test_parse_simple_deny_rule():
    yaml_str = """
    version: 1
    global:
      default_action: allow

    agents:
      research-bot:
        tools:
          curl:
            rules:
              - action: deny
                condition:
                  args_match: ".*--delete.*"
    """
    engine = PolicyParser.parse(yaml_str)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "url"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "deny"
    assert len(decision.matched_rules) > 0


def test_parse_policy_with_global_default():
    yaml_str = """
    version: 1
    global:
      default_action: deny

    agents:
      research-bot:
        tools:
          read_file:
            rules:
              - action: allow
                condition:
                  args_match: ".*"
    """
    engine = PolicyParser.parse(yaml_str)
    call = PolicyCall(agent="research-bot", tool="read_file", args=["test.txt"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "allow"


def test_parse_routes_a_loaded_v1_mapping_to_the_v1_parser(monkeypatch):
    parsed_policy = {"version": 1, "global": {"default_action": "deny"}}
    expected_engine = object()
    loads = []

    def load_policy(*args, **kwargs):
        loads.append((args, kwargs))
        return parsed_policy

    monkeypatch.setattr(parser_module.yaml, "load", load_policy)
    monkeypatch.setattr(parser_module, "_parse_v1", lambda policy: expected_engine)

    assert PolicyParser.parse("version: 1") is expected_engine
    assert loads == [(("version: 1",), {"Loader": parser_module._Yaml12SafeLoader})]


@pytest.mark.parametrize(
    ("policy", "code"),
    [
        ("global: {}", "unsupported_version"),
        ("version: 2", "unsupported_version"),
        ("version: 1\nglobal:\n  default_actoin: deny", "invalid_field"),
        ("version: 1\nrules:\n  - action: block", "invalid_action"),
        ("version: 1\nrules:\n  - action: deny\n    target:\n      host: local", "invalid_target"),
        ("version: 1\nrules:\n  - action: deny\n    condition:\n      predicate: x", "invalid_condition"),
        ("version: 1\nrules:\n  - action: deny\n    condition:\n      args_match: '(?=danger)'", "invalid_regex"),
        ("version: 1\nrules:\n  - action: deny\n    condition:\n      args_match: '['", "invalid_regex"),
    ],
)
def test_parse_rejects_invalid_v1_policies(policy, code):
    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)

    assert error.value.code == code


def test_parse_nested_rules_inherit_targets_but_cannot_override_them():
    policy = """
version: 1
agents:
  writer:
    tools:
      write_file:
        rules:
          - action: deny
            target:
              agent: writer
              context:
                phase: prompt
"""
    engine = PolicyParser.parse(policy)
    assert engine.rules[0].target == {
        "agent": "writer",
        "tool": "write_file",
        "context.phase": "prompt",
    }

    conflicting = policy.replace("agent: writer", "agent: other")
    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(conflicting)
    assert error.value.code == "conflicting_target"


def test_parse_rejects_duplicate_rule_ids():
    policy = """
version: 1
rules:
  - id: duplicate
    action: allow
  - id: duplicate
    action: deny
"""
    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)
    assert error.value.code == "invalid_field"


def test_parse_preserves_top_level_yaml_declaration_order():
    policy = """
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: log
rules:
  - action: allow
"""
    engine = PolicyParser.parse(policy)
    assert [rule.rule_index for rule in engine.rules] == [0, 1]
    assert [rule.action.value for rule in engine.rules] == ["log", "allow"]


def test_parse_default_action_applies_to_unmatched_call():
    engine = PolicyParser.parse("version: 1\nglobal:\n  default_action: deny")
    assert engine.resolve_call(PolicyCall()).action.value == "deny"


@pytest.mark.parametrize(
    ("policy", "code"),
    [
        (
            """
version: 1
rules:
  - action: deny
    target:
      tool: 2026-08-11
""",
            "invalid_target",
        ),
        (
            """
version: 1
rules:
  - action: deny
    target:
      context:
        phase: 1:30
""",
            "invalid_target",
        ),
        (
            """
version: 1
rules:
  - id: 1e3
    action: deny
""",
            "invalid_field",
        ),
        (
            """
version: 1
rules:
  - action: deny
    condition:
      path_pattern: 0o755
""",
            "invalid_condition",
        ),
    ],
)
def test_parse_rejects_ambiguous_yaml_scalar_strings(policy, code):
    with pytest.raises(PolicyError) as error:
        PolicyParser.parse(policy)
    assert error.value.code == code
