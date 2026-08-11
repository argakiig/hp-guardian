from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from .engine import Decision, Engine
from .models import Action, PolicyCall, PolicyError, RateLimit
from .parser import PolicyParser


class StateError(Exception):
    """A required state operation failed, so the stateful boundary must close."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class _RateLimitKey:
    policy_digest: str
    rule_index: int
    agent: str | None
    user: str | None
    tool: str | None


class RateLimitStore(Protocol):
    def check_and_consume(self, key: _RateLimitKey, limit: RateLimit, now_seconds: int) -> bool: ...


class InMemoryRateLimitStore:
    """A process-local, locked fixed-window quota store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: dict[_RateLimitKey, tuple[int, int]] = {}
        self._last_now: int | None = None

    def check_and_consume(self, key: _RateLimitKey, limit: RateLimit, now_seconds: int) -> bool:
        if type(now_seconds) is not int or now_seconds < 0:
            raise StateError("state_unavailable", "monotonic time must be a non-negative integer")
        with self._lock:
            if self._last_now is not None and now_seconds < self._last_now:
                raise StateError("state_unavailable", "monotonic clock regressed")
            self._last_now = now_seconds
            window_start = now_seconds - now_seconds % limit.window_seconds
            previous_start, count = self._buckets.get(key, (window_start, 0))
            if previous_start != window_start:
                count = 0
            if count >= limit.max_calls:
                self._buckets[key] = (window_start, count)
                return False
            self._buckets[key] = (window_start, count + 1)
            return True


class RateLimitedPolicyStore:
    """Explicit stateful v2 resolver; the underlying Engine remains pure."""

    def __init__(
        self,
        policy_text: str,
        state_store: RateLimitStore,
        *,
        now_monotonic_seconds: Callable[[], int] | None = None,
    ) -> None:
        engine = PolicyParser.parse_rate_limited(policy_text)
        self._engine = engine
        self._digest = hashlib.sha256(policy_text.encode("utf-8")).hexdigest()
        self._state_store = state_store
        self._now = now_monotonic_seconds or (lambda: time.monotonic_ns() // 1_000_000_000)

    def resolve(self, call: PolicyCall) -> Decision:
        decision, selected_rule = self._engine._resolve_call_at(call, _utc_now())
        if selected_rule is None or decision.action is not Action.ALLOW:
            return decision
        limit = self._engine.rate_limits.get(selected_rule)
        if limit is None:
            return decision
        key = _RateLimitKey(self._digest, selected_rule, call.agent, call.user, call.tool)
        if self._state_store.check_and_consume(key, limit, self._now()):
            return decision
        return Decision(action=Action.THROTTLE, matched_rules=decision.matched_rules)


def _utc_now():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)
