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


def test_path_pattern_is_lexical_and_matches_any_argument():
    rule = Rule(action=Action.DENY, condition={"path_pattern": "/etc/*"})
    call = PolicyCall(args=["--mode", "/etc/nested/config"])
    assert evaluate(rule, call) is True


def test_path_pattern_does_not_normalize_paths():
    rule = Rule(action=Action.DENY, condition={"path_pattern": "/etc/*"})
    call = PolicyCall(args=["/tmp/../etc/passwd"])
    assert evaluate(rule, call) is False


def test_args_match_dot_matches_a_newline_in_the_portable_v1_language():
    rule = Rule(action=Action.DENY, condition={"args_match": "^foo.$"})
    assert evaluate(rule, PolicyCall(args=["foo\n"])) is True


def test_args_match_end_anchor_requires_the_actual_end_of_input():
    rule = Rule(action=Action.DENY, condition={"args_match": "^foo$"})
    assert evaluate(rule, PolicyCall(args=["foo\n"])) is False
