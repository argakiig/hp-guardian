import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.models import Rule, PolicyCall, Action
from hp_guard.conditions import evaluate


def test_args_match_regex():
    rule = Rule(action=Action.DENY, condition={"args_match": ".*--delete.*"})
    call = PolicyCall(tool="curl", args=["--delete", "http://example.com"])
    assert evaluate(rule, call) is True


def test_args_match_no_match():
    rule = Rule(action=Action.DENY, condition={"args_match": ".*--delete.*"})
    call = PolicyCall(tool="curl", args=["--get", "http://example.com"])
    assert evaluate(rule, call) is False


def test_args_match_empty_args():
    rule = Rule(action=Action.DENY, condition={"args_match": ".*--delete.*"})
    call = PolicyCall(tool="curl", args=[])
    assert evaluate(rule, call) is False


def test_no_conditions_always_passes():
    rule = Rule(action=Action.DENY, condition={})
    call = PolicyCall(tool="curl", args=["anything"])
    assert evaluate(rule, call) is True
