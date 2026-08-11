import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import yaml
from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall


def test_parse_simple_deny_rule():
    yaml_str = """
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
