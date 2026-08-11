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
