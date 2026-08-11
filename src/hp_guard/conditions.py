from __future__ import annotations
import re
from .models import Rule, PolicyCall


def evaluate(rule: Rule, call: PolicyCall) -> bool:
    """Evaluate all conditions on a rule against a call. All conditions must pass (ANDed)."""
    for key, value in rule.condition.items():
        if key == "args_match":
            if not args_match(call.args, value):
                return False
        else:
            # Unknown condition keys cause the rule to NOT match
            return False
    return True


def args_match(args: list, pattern: str) -> bool:
    concatenated = " ".join(args)
    return bool(re.search(pattern, concatenated))
