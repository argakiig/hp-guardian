from __future__ import annotations
from .models import Rule, PolicyCall


def rule_matches_rule(rule: Rule, call: PolicyCall) -> bool:
    for field_name, expected_value in rule.target.items():
        if field_name in {"agent", "tool", "user"}:
            if expected_value != getattr(call, field_name):
                return False
        elif field_name.startswith("context."):
            context_key = field_name.removeprefix("context.")
            if call.context.get(context_key) != expected_value:
                return False
        else:
            return False
    return True
