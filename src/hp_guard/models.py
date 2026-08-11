from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    THROTTLE = "throttle"
    LOG = "log"
    REQUIRE_APPROVAL = "require_approval"
    REDIRECT = "redirect"


class PolicyError(Exception):
    """A policy validation failure with a stable, language-neutral code."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RateLimit:
    max_calls: int
    window_seconds: int


@dataclass
class Rule:
    action: Action
    target: Dict[str, Any] = field(default_factory=dict)
    condition: Dict[str, Any] = field(default_factory=dict)
    rule_index: int = 0

@dataclass
class PolicyCall:
    agent: str | None = None
    tool: str | None = None
    args: list = field(default_factory=list)
    user: str | None = None
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEntry:
    timestamp: str
    agent: str | None
    tool: str | None
    args: list
    decision: Action
    matched_rules: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent": self.agent,
            "tool": self.tool,
            "args": self.args,
            "decision": self.decision.value,
            "matched_rules": self.matched_rules,
        }
