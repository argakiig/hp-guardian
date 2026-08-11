import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.models import Rule, Action


def test_rule_has_action_and_target():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    assert rule.action == Action.DENY
    assert rule.target["agent"] == "bot"
    assert rule.target["tool"] == "curl"


def test_action_enum_values():
    assert Action.ALLOW.value == "allow"
    assert Action.DENY.value == "deny"
    assert Action.THROTTLE.value == "throttle"
    assert Action.LOG.value == "log"
    assert Action.REQUIRE_APPROVAL.value == "require_approval"
    assert Action.REDIRECT.value == "redirect"


def test_rule_default_target_is_empty_dict():
    rule = Rule(action=Action.ALLOW)
    assert rule.target == {}


def test_rule_has_empty_condition_by_default():
    rule = Rule(action=Action.ALLOW)
    assert rule.condition == {}


def test_rule_has_rule_index_zero_by_default():
    rule = Rule(action=Action.ALLOW)
    assert rule.rule_index == 0


def test_rule_stores_condition():
    rule = Rule(
        action=Action.DENY,
        condition={"args_match": ".*--delete.*"}
    )
    assert rule.condition == {"args_match": ".*--delete.*"}


def test_policy_call_fields():
    from hp_guard.models import PolicyCall
    call = PolicyCall(
        agent="research-bot",
        tool="curl",
        args=["--delete", "http://example.com"],
        user="user-123",
        context={"phase": "prompt"},
    )
    assert call.agent == "research-bot"
    assert call.tool == "curl"
    assert call.args == ["--delete", "http://example.com"]
    assert call.user == "user-123"
    assert call.context == {"phase": "prompt"}
