from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from .models import Rule, PolicyCall, Action, RateLimit
from .matching import rule_matches_rule
from .conditions import evaluate


@dataclass
class Decision:
    action: Action
    matched_rules: list = field(default_factory=list)


def _rule_specificity(rule: Rule) -> int:
    return len(rule.target)


def _action_priority(action: Action) -> int:
    return {
        Action.REQUIRE_APPROVAL: 5,
        Action.THROTTLE: 4,
        Action.REDIRECT: 3,
        Action.ALLOW: 2,
        Action.LOG: 1,
    }.get(action, 0)


class Engine:
    def __init__(
        self,
        rules: list[Rule],
        default_action: Action = Action.ALLOW,
        *,
        version: int = 1,
        rate_limits: dict[int, RateLimit] | None = None,
    ):
        self.rules = rules
        self.default_action = default_action
        self.version = version
        self.rate_limits = rate_limits or {}

    def resolve_call(self, call: PolicyCall) -> Decision:
        return self.resolve_call_at(call, datetime.now(timezone.utc))

    def resolve_call_at(self, call: PolicyCall, now: datetime) -> Decision:
        """Resolve a call at an explicit UTC instant for deterministic evaluation."""
        decision, selected_rule = self._resolve_call_at(call, now)
        if selected_rule in self.rate_limits and decision.action is Action.ALLOW:
            return Decision(action=Action.THROTTLE, matched_rules=decision.matched_rules)
        return decision

    def _resolve_call_at(self, call: PolicyCall, now: datetime) -> tuple[Decision, int | None]:
        matching = [
            r for r in self.rules
            if rule_matches_rule(r, call) and evaluate(r, call, now)
        ]
        if not matching:
            return Decision(action=self.default_action), None

        matched_rules = [rule.rule_index for rule in matching]
        if any(rule.action == Action.DENY for rule in matching):
            return Decision(action=Action.DENY, matched_rules=matched_rules), None

        best = matching[0]
        for rule in matching[1:]:
            if _rule_specificity(rule) > _rule_specificity(best):
                best = rule
            elif _rule_specificity(rule) == _rule_specificity(best) and _action_priority(rule.action) > _action_priority(best.action):
                best = rule

        return Decision(action=best.action, matched_rules=matched_rules), best.rule_index
