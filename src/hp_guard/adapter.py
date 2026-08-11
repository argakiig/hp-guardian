from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping

from .audit import AuditError, AuditedPolicyStore, PolicySnapshot
from .models import Action, PolicyCall


_REQUEST_FIELDS = {"caller_id", "correlation_id", "deadline_unix_ms", "call"}
_CALL_FIELDS = {"agent", "tool", "args", "user", "context"}
_MAX_U64 = (1 << 64) - 1


class AdapterError(Exception):
    """An inline-adapter request or required authorization failure."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class EnforcementRequest:
    caller_id: str
    correlation_id: str
    deadline_unix_ms: int
    call: PolicyCall

    def __post_init__(self) -> None:
        _opaque_id(self.caller_id, "caller_id")
        _opaque_id(self.correlation_id, "correlation_id")
        _validate_deadline(self.deadline_unix_ms)
        object.__setattr__(self, "call", _normalize_policy_call(self.call))

    @classmethod
    def from_dict(cls, value: Any) -> EnforcementRequest:
        if not isinstance(value, Mapping) or set(value) != _REQUEST_FIELDS:
            raise AdapterError("invalid_request", "request must contain exactly the required fields")
        caller_id = _opaque_id(value["caller_id"], "caller_id")
        correlation_id = _opaque_id(value["correlation_id"], "correlation_id")
        deadline_unix_ms = value["deadline_unix_ms"]
        _validate_deadline(deadline_unix_ms)
        return cls(
            caller_id=caller_id,
            correlation_id=correlation_id,
            deadline_unix_ms=deadline_unix_ms,
            call=_normalize_call(value["call"]),
        )


@dataclass(frozen=True)
class EffectRequest:
    caller_id: str
    correlation_id: str
    deadline_unix_ms: int
    policy: PolicySnapshot
    decision: str
    matched_rules: tuple[int, ...]
    call: PolicyCall

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "correlation_id": self.correlation_id,
            "deadline_unix_ms": self.deadline_unix_ms,
            "policy": _policy_identity(self.policy),
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
            "call": _call_dict(self.call),
        }


@dataclass(frozen=True)
class EnforcementResponse:
    caller_id: str
    correlation_id: str
    deadline_unix_ms: int
    policy: PolicySnapshot
    decision: str
    matched_rules: tuple[int, ...]
    effect: EffectRequest | None = None

    def to_dict(self) -> dict[str, Any]:
        response = {
            "caller_id": self.caller_id,
            "correlation_id": self.correlation_id,
            "deadline_unix_ms": self.deadline_unix_ms,
            "policy": _policy_identity(self.policy),
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
        }
        if self.effect is not None:
            response["effect"] = self.effect.to_dict()
        return response


class InlineEnforcementAdapter:
    """Authorize a normalized call and return data for a host-owned effect."""

    def __init__(
        self,
        policy_store: AuditedPolicyStore,
        *,
        now_unix_ms: Callable[[], int] | None = None,
    ):
        self._policy_store = policy_store
        self._now_unix_ms = now_unix_ms or (lambda: time.time_ns() // 1_000_000)

    def authorize(self, request: EnforcementRequest) -> EnforcementResponse:
        if not isinstance(request, EnforcementRequest):
            raise AdapterError("invalid_request", "request must be an EnforcementRequest")
        call = _normalize_policy_call(request.call)
        if request.deadline_unix_ms <= self._now_unix_ms():
            raise AdapterError("deadline_exceeded", "request deadline has elapsed")
        try:
            authorization = self._policy_store._authorize_with_metadata(
                call,
                correlation_id=request.correlation_id,
                caller_id=request.caller_id,
                deadline_unix_ms=request.deadline_unix_ms,
            )
        except AuditError as error:
            raise AdapterError("audit_write_failed", "required audit write failed") from error

        decision = authorization.decision.action.value
        matched_rules = tuple(authorization.decision.matched_rules)
        effect = None
        if authorization.decision.action is Action.ALLOW:
            effect = EffectRequest(
                caller_id=request.caller_id,
                correlation_id=request.correlation_id,
                deadline_unix_ms=request.deadline_unix_ms,
                policy=authorization.snapshot,
                decision=decision,
                matched_rules=matched_rules,
                call=call,
            )
        return EnforcementResponse(
            caller_id=request.caller_id,
            correlation_id=request.correlation_id,
            deadline_unix_ms=request.deadline_unix_ms,
            policy=authorization.snapshot,
            decision=decision,
            matched_rules=matched_rules,
            effect=effect,
        )


def _opaque_id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise AdapterError("invalid_request", f"{name} must be a non-empty string")
    size = _utf8_size(value, name)
    if size > 256:
        raise AdapterError("invalid_request", f"{name} must be at most 256 UTF-8 bytes")
    return value


def _validate_deadline(value: Any) -> None:
    if type(value) is not int or not 0 <= value <= _MAX_U64:
        raise AdapterError("invalid_request", "deadline_unix_ms must be an unsigned 64-bit integer")


def _utf8_size(value: str, name: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as error:
        raise AdapterError("invalid_request", f"{name} must be valid UTF-8") from error


def _normalize_call(value: Any) -> PolicyCall:
    if not isinstance(value, Mapping) or set(value) != _CALL_FIELDS:
        raise AdapterError("invalid_request", "call must contain exactly the required fields")
    for name in ("agent", "tool", "user"):
        if value[name] is not None and not isinstance(value[name], str):
            raise AdapterError("invalid_request", f"call.{name} must be a string or null")
        if value[name] is not None:
            _utf8_size(value[name], f"call.{name}")
    args = value["args"]
    if not isinstance(args, list) or any(not isinstance(argument, str) for argument in args):
        raise AdapterError("invalid_request", "call.args must be an array of strings")
    for argument in args:
        _utf8_size(argument, "call.args item")
    context = value["context"]
    if not isinstance(context, Mapping) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in context.items()
    ):
        raise AdapterError("invalid_request", "call.context must be a string-to-string map")
    for key, item in context.items():
        _utf8_size(key, "call.context key")
        _utf8_size(item, "call.context value")
    return PolicyCall(
        agent=value["agent"],
        tool=value["tool"],
        args=list(args),
        user=value["user"],
        context=dict(context),
    )


def _normalize_policy_call(value: Any) -> PolicyCall:
    if not isinstance(value, PolicyCall):
        raise AdapterError("invalid_request", "call must be a PolicyCall")
    return _normalize_call(
        {
            "agent": value.agent,
            "tool": value.tool,
            "args": value.args,
            "user": value.user,
            "context": value.context,
        }
    )


def _copy_call(call: PolicyCall) -> PolicyCall:
    return PolicyCall(
        agent=call.agent,
        tool=call.tool,
        args=list(call.args),
        user=call.user,
        context=dict(call.context),
    )


def _call_dict(call: PolicyCall) -> dict[str, Any]:
    return {
        "agent": call.agent,
        "tool": call.tool,
        "args": list(call.args),
        "user": call.user,
        "context": dict(call.context),
    }


def _policy_identity(snapshot: PolicySnapshot) -> dict[str, Any]:
    return {"version": snapshot.version, "sha256": snapshot.digest}
