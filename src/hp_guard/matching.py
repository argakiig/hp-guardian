from __future__ import annotations
from .models import Rule, PolicyCall


def rule_matches_rule(rule: Rule, call: PolicyCall) -> bool:
    for field_name, expected_value in rule.target.items():
        actual_value = getattr(call, field_name, None)
        if expected_value != actual_value:
            return False
    return True
