import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.models import Rule, PolicyCall, Action
from hp_guard.engine import Engine


def test_no_rules_returns_allow():
    engine = Engine(rules=[])
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.ALLOW
    assert decision.matched_rules == []


def test_single_matching_rule_applied():
    rules = [
        Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"}, rule_index=0)
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.DENY


def test_non_matching_rule_ignored():
    rules = [
        Rule(action=Action.DENY, target={"agent": "other", "tool": "curl"}, rule_index=0)
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.ALLOW


def test_most_specific_target_wins():
    rules = [
        Rule(action=Action.DENY, target={"agent": "bot"}, rule_index=0),
        Rule(action=Action.ALLOW, target={"agent": "bot", "tool": "curl"}, rule_index=1),
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.DENY
    assert decision.matched_rules == [0, 1]


def test_global_deny_overrides_a_more_specific_allow():
    rules = [
        Rule(action=Action.DENY, rule_index=0),
        Rule(action=Action.ALLOW, target={"agent": "bot", "tool": "curl"}, rule_index=1),
    ]
    decision = Engine(rules=rules).resolve_call(PolicyCall(agent="bot", tool="curl"))
    assert decision.action == Action.DENY
    assert decision.matched_rules == [0, 1]


def test_action_priority_and_declaration_order_break_equal_specificity_ties():
    rules = [
        Rule(action=Action.LOG, target={"agent": "bot"}, rule_index=0),
        Rule(action=Action.REDIRECT, target={"agent": "bot"}, rule_index=1),
        Rule(action=Action.REDIRECT, target={"agent": "bot"}, rule_index=2),
    ]
    decision = Engine(rules=rules).resolve_call(PolicyCall(agent="bot"))
    assert decision.action == Action.REDIRECT
    assert decision.matched_rules == [0, 1, 2]


def test_configured_default_action_applies_when_no_rule_matches():
    decision = Engine(rules=[], default_action=Action.DENY).resolve_call(PolicyCall())
    assert decision.action == Action.DENY
