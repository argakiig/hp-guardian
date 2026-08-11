from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from typing import Any

from .engine import Engine
from .models import Action, PolicyCall
from .parser import PolicyParser


_EVENT_FIELDS = {"version", "sequence", "event_id", "call", "expected"}
_CALL_FIELDS = {"agent", "tool", "args", "user", "context"}
_EXPECTED_FIELDS = {"policy", "decision", "matched_rules"}
_EXPECTED_POLICY_FIELDS = {"version", "sha256"}
_DIGEST = re.compile(r"[0-9a-f]{64}")
_DECISIONS = {action.value for action in Action}
_POLICY_CONSTRUCTION_TOKEN = object()


class TraceError(Exception):
    """A trace-format failure with a stable code and physical line number."""

    def __init__(self, code: str, line: int, message: str):
        self.code = code
        self.line = line
        super().__init__(message)


@dataclass(frozen=True)
class ExpectedDecision:
    policy_version: int
    policy_digest: str
    decision: str
    matched_rules: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": {"version": self.policy_version, "sha256": self.policy_digest},
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
        }


@dataclass(frozen=True)
class TraceEvent:
    sequence: int
    call: PolicyCall
    event_id: str | None = None
    expected: ExpectedDecision | None = None


@dataclass(frozen=True, init=False)
class SimulationPolicy:
    """A parsed policy and the identity of its exact UTF-8 source text."""

    version: int
    digest: str
    _engine: Engine

    def __init__(self, token: object, digest: str, engine: Engine):
        if token is not _POLICY_CONSTRUCTION_TOKEN:
            raise TypeError("SimulationPolicy instances must be created with SimulationPolicy.parse()")
        object.__setattr__(self, "version", 1)
        object.__setattr__(self, "digest", digest)
        object.__setattr__(self, "_engine", engine)

    @classmethod
    def parse(cls, policy_text: str) -> SimulationPolicy:
        engine = PolicyParser.parse(policy_text)
        return cls(
            _POLICY_CONSTRUCTION_TOKEN,
            hashlib.sha256(policy_text.encode("utf-8")).hexdigest(),
            engine,
        )

    def policy_identity(self) -> dict[str, Any]:
        return {"version": self.version, "sha256": self.digest}


@dataclass(frozen=True)
class SimulationResult:
    policy: SimulationPolicy
    decision: str
    matched_rules: tuple[int, ...]
    matches_expected: bool | None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "policy": self.policy.policy_identity(),
            "decision": self.decision,
            "matched_rules": list(self.matched_rules),
        }
        if self.matches_expected is not None:
            result["matches_expected"] = self.matches_expected
        return result


@dataclass(frozen=True)
class SimulationReport:
    sequence: int
    event_id: str | None
    expected: ExpectedDecision | None
    results: tuple[SimulationResult, ...]

    def to_dict(self) -> dict[str, Any]:
        report: dict[str, Any] = {"version": 1, "sequence": self.sequence}
        if self.event_id is not None:
            report["event_id"] = self.event_id
        if self.expected is not None:
            report["expected"] = self.expected.to_dict()
        report["results"] = [result.to_dict() for result in self.results]
        if len(self.results) == 2:
            baseline, candidate = self.results
            report["comparison"] = {
                "action_changed": baseline.decision != candidate.decision,
                "matched_rules_changed": baseline.matched_rules != candidate.matched_rules,
            }
        return report


def parse_trace(jsonl: str) -> list[TraceEvent]:
    """Parse a complete v1 JSON Lines trace before any policy evaluation."""

    events: list[TraceEvent] = []
    expected_sequence = 1
    for line_number, raw_line in enumerate(jsonl.splitlines(), start=1):
        if not raw_line.strip():
            continue
        try:
            record = json.loads(raw_line, parse_constant=_reject_non_json_constant)
            if _contains_lone_surrogate(record):
                raise ValueError("JSON strings must not contain lone Unicode surrogates")
        except (json.JSONDecodeError, ValueError) as error:
            raise TraceError("invalid_trace_json", line_number, "trace line is not valid JSON") from error
        event = _parse_event(record, line_number)
        if event.sequence != expected_sequence:
            raise TraceError(
                "invalid_trace_sequence",
                line_number,
                f"trace sequence must be {expected_sequence}",
            )
        events.append(event)
        expected_sequence += 1
    return events


def _reject_non_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _contains_lone_surrogate(value: Any) -> bool:
    if isinstance(value, str):
        return any(0xD800 <= ord(character) <= 0xDFFF for character in value)
    if isinstance(value, list):
        return any(_contains_lone_surrogate(item) for item in value)
    if isinstance(value, dict):
        return any(
            _contains_lone_surrogate(key) or _contains_lone_surrogate(item)
            for key, item in value.items()
        )
    return False


def simulate_trace(
    baseline: SimulationPolicy,
    candidate: SimulationPolicy | None,
    jsonl: str,
) -> list[SimulationReport]:
    """Resolve a complete trace against one or two policies without side effects."""

    events = parse_trace(jsonl)
    policies = (baseline,) if candidate is None else (baseline, candidate)
    return [_simulate_event(event, policies) for event in events]


def _parse_event(record: Any, line: int) -> TraceEvent:
    if not isinstance(record, dict):
        raise TraceError("invalid_trace_record", line, "trace record must be an object")
    if set(record) - _EVENT_FIELDS or not {"version", "sequence", "call"} <= set(record):
        raise TraceError("invalid_trace_record", line, "trace record has invalid fields")
    if type(record["version"]) is not int or record["version"] != 1:
        raise TraceError("unsupported_trace_version", line, "trace version must be the integer 1")
    if type(record["sequence"]) is not int or record["sequence"] <= 0:
        raise TraceError("invalid_trace_sequence", line, "trace sequence must be a positive integer")

    event_id = record.get("event_id")
    if event_id is not None and (not isinstance(event_id, str) or not event_id):
        raise TraceError("invalid_trace_record", line, "event_id must be a non-empty string")
    call = _parse_call(record["call"], line)
    expected = _parse_expected(record["expected"], line) if "expected" in record else None
    return TraceEvent(sequence=record["sequence"], event_id=event_id, call=call, expected=expected)


def _parse_call(value: Any, line: int) -> PolicyCall:
    if not isinstance(value, dict) or set(value) != _CALL_FIELDS:
        raise TraceError("invalid_trace_call", line, "call has invalid fields")
    for name in ("agent", "tool", "user"):
        if value[name] is not None and not isinstance(value[name], str):
            raise TraceError("invalid_trace_call", line, f"call.{name} must be a string or null")
    args = value["args"]
    if not isinstance(args, list) or any(not isinstance(argument, str) for argument in args):
        raise TraceError("invalid_trace_call", line, "call.args must be an array of strings")
    context = value["context"]
    if not isinstance(context, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in context.items()
    ):
        raise TraceError("invalid_trace_call", line, "call.context must be a string map")
    return PolicyCall(
        agent=value["agent"],
        tool=value["tool"],
        args=list(args),
        user=value["user"],
        context=dict(context),
    )


def _parse_expected(value: Any, line: int) -> ExpectedDecision:
    if not isinstance(value, dict) or set(value) != _EXPECTED_FIELDS:
        raise TraceError("invalid_trace_expected", line, "expected has invalid fields")
    policy = value["policy"]
    if not isinstance(policy, dict) or set(policy) != _EXPECTED_POLICY_FIELDS:
        raise TraceError("invalid_trace_expected", line, "expected.policy has invalid fields")
    if type(policy["version"]) is not int or policy["version"] != 1:
        raise TraceError("invalid_trace_expected", line, "expected policy version must be the integer 1")
    digest = policy["sha256"]
    if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
        raise TraceError("invalid_trace_expected", line, "expected policy digest must be lowercase SHA-256")
    decision = value["decision"]
    if not isinstance(decision, str) or decision not in _DECISIONS:
        raise TraceError("invalid_trace_expected", line, "expected decision is invalid")
    matched_rules = value["matched_rules"]
    if not isinstance(matched_rules, list) or any(
        type(index) is not int or not 0 <= index <= sys.maxsize for index in matched_rules
    ):
        raise TraceError("invalid_trace_expected", line, "expected matched rules are invalid")
    return ExpectedDecision(
        policy_version=policy["version"],
        policy_digest=digest,
        decision=decision,
        matched_rules=tuple(matched_rules),
    )


def _simulate_event(
    event: TraceEvent, policies: tuple[SimulationPolicy, ...]
) -> SimulationReport:
    results = tuple(_simulate_policy(policy, event) for policy in policies)
    return SimulationReport(
        sequence=event.sequence,
        event_id=event.event_id,
        expected=event.expected,
        results=results,
    )


def _simulate_policy(policy: SimulationPolicy, event: TraceEvent) -> SimulationResult:
    decision = policy._engine.resolve_call(event.call)
    matches_expected: bool | None = None
    if event.expected is not None and (
        policy.version == event.expected.policy_version and policy.digest == event.expected.policy_digest
    ):
        matches_expected = (
            decision.action.value == event.expected.decision
            and tuple(decision.matched_rules) == event.expected.matched_rules
        )
    return SimulationResult(
        policy=policy,
        decision=decision.action.value,
        matched_rules=tuple(decision.matched_rules),
        matches_expected=matches_expected,
    )
