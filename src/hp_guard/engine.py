from __future__ import annotations
from dataclasses import dataclass, field
from .models import Rule, PolicyCall, Action
from .matching import rule_matches_rule
from .conditions import evaluate


@dataclass
class Decision:
    action: Action
    matched_rules: list = field(default_factory=list)


def _rule_specificity(rule: Rule) -> int:
    return len(rule.target)


class Engine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def resolve_call(self, call: PolicyCall) -> Decision:
        matching = [
            r for r in self.rules
            if rule_matches_rule(r, call) and evaluate(r, call)
        ]
        if not matching:
            return Decision(action=Action.ALLOW)

        # Sort by specificity descending (more target fields = more specific)
        matching.sort(key=lambda r: _rule_specificity(r), reverse=True)

        # Among same specificity, deny overrides allow
        best = matching[0]
        if any(
            r.action == Action.DENY and _rule_specificity(r) == _rule_specificity(best)
            for r in matching
        ):
            deny_rules = [r for r in matching if r.action == Action.DENY and _rule_specificity(r) == _rule_specificity(best)]
            best = deny_rules[0]

        return Decision(action=best.action, matched_rules=[best.rule_index])
