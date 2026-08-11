import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall


POLICY = """
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
      write_file:
        rules:
          - action: deny
            condition:
              path_pattern: "/etc/*"
"""


def test_research_bot_curl_delete_denied():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "http://x.com"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "deny"


def test_research_bot_curl_get_allowed():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--get", "http://x.com"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "allow"


def test_research_bot_write_file_etc_denied():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="write_file", args=["/etc/passwd"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "deny"


def test_unknown_agent_defaults_to_allow():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="unknown-agent", tool="anything")
    decision = engine.resolve_call(call)
    assert decision.action.value == "allow"
