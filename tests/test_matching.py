import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.models import Rule, PolicyCall, Action
from hp_guard.matching import rule_matches_rule


def test_unspecified_target_fields_match_anything():
    rule = Rule(action=Action.DENY, target={"agent": "bot"})
    call = PolicyCall(agent="bot", tool="anything")
    assert rule_matches_rule(rule, call) is True


def test_specific_field_must_match():
    rule = Rule(action=Action.DENY, target={"agent": "bot"})
    call = PolicyCall(agent="other", tool="curl")
    assert rule_matches_rule(rule, call) is False


def test_both_agent_and_tool_must_match():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    call = PolicyCall(agent="bot", tool="curl")
    assert rule_matches_rule(rule, call) is True


def test_tool_mismatch_fails():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    call = PolicyCall(agent="bot", tool="write_file")
    assert rule_matches_rule(rule, call) is False


def test_empty_target_matches_all():
    rule = Rule(action=Action.ALLOW, target={})
    call = PolicyCall(agent="bot", tool="curl")
    assert rule_matches_rule(rule, call) is True


def test_user_field_matching():
    rule = Rule(action=Action.DENY, target={"user": "admin"})
    call = PolicyCall(agent="bot", tool="curl", user="admin")
    assert rule_matches_rule(rule, call) is True


def test_user_mismatch():
    rule = Rule(action=Action.DENY, target={"user": "admin"})
    call = PolicyCall(agent="bot", tool="curl", user="guest")
    assert rule_matches_rule(rule, call) is False
