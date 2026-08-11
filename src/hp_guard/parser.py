from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

import yaml

from .engine import Engine
from .conditions import parse_time_window, validate_args_pattern
from .models import Action, PolicyError, RateLimit, Rule


_ACTIONS = {action.value: action for action in Action}
_RULE_FIELDS = {"id", "action", "target", "condition"}
_TARGET_FIELDS = {"agent", "tool", "user", "context"}
_CONDITION_LEAF_FIELDS = {"args_match", "path_pattern", "time_window"}
_CONDITION_OPERATOR_FIELDS = {"all", "any", "not"}
_CONDITION_FIELDS = _CONDITION_LEAF_FIELDS | _CONDITION_OPERATOR_FIELDS
_MAX_CONDITION_DEPTH = 32
_MAX_CONDITION_NODES = 128
_YAML_BOOL_TAG = "tag:yaml.org,2002:bool"
_YAML_TIMESTAMP_TAG = "tag:yaml.org,2002:timestamp"
_AMBIGUOUS_SCALAR_PATTERNS = (
    re.compile(r"^(?:true|false|yes|no|on|off|null|~)$", re.IGNORECASE),
    re.compile(r"^\d{4}-\d{2}-\d{2}(?:[Tt _].*)?$"),
    re.compile(r"^[+-]?(?:\d[\d_]*\.?[\d_]*|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?$"),
    re.compile(r"^[+-]?0[xX][0-9a-fA-F_]+$"),
    re.compile(r"^[+-]?0[oO][0-7_]+$"),
    re.compile(r"^[+-]?0[bB][01_]+$"),
    re.compile(r"^[+-]?\d[\d_]*(?::\d[\d_]*(?:\.\d[\d_]*)?)+$"),
    re.compile(r"^[+-]?\.(?:inf|nan)$", re.IGNORECASE),
)


class _Yaml12SafeLoader(yaml.SafeLoader):
    """Use YAML 1.2 booleans so plain yes remains a string."""


_Yaml12SafeLoader.yaml_implicit_resolvers = {
    first_character: [
        resolver
        for resolver in resolvers
        if resolver[0] not in {_YAML_BOOL_TAG, _YAML_TIMESTAMP_TAG}
    ]
    for first_character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_Yaml12SafeLoader.add_implicit_resolver(
    _YAML_BOOL_TAG,
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


class PolicyParser:
    @staticmethod
    def parse(yaml_str: str) -> Engine:
        policy, version = _load_policy(yaml_str)
        if version != 1:
            raise PolicyError("unsupported_version", "policy version must be the integer 1")
        return _parse_v1(policy)

    @staticmethod
    def parse_rate_limited(yaml_str: str) -> Engine:
        policy, version = _load_policy(yaml_str)
        if version != 2:
            raise PolicyError("unsupported_version", "rate-limited policy version must be the integer 2")
        return _parse_v2(policy)


def _load_policy(yaml_str: str) -> tuple[Mapping[Any, Any], int]:
    try:
        policy = yaml.load(yaml_str, Loader=_Yaml12SafeLoader)
    except yaml.YAMLError as error:
        raise PolicyError("invalid_yaml", f"invalid YAML policy: {error}") from error

    policy = _mapping(policy, "policy")
    version = policy.get("version")
    if type(version) is not int:
        raise PolicyError("unsupported_version", "policy version must be an integer")
    return policy, version


def _parse_v1(policy: Mapping[Any, Any]) -> Engine:
    return _parse_version(policy, version=1, allow_rate_limit=False)


def _parse_v2(policy: Mapping[Any, Any]) -> Engine:
    return _parse_version(policy, version=2, allow_rate_limit=True)


def _parse_version(policy: Mapping[Any, Any], *, version: int, allow_rate_limit: bool) -> Engine:
    _reject_unknown_fields(policy, {"version", "global", "rules", "agents"}, "policy")

    rules: list[Rule] = []
    rate_limits: dict[int, RateLimit] = {}
    seen_ids: set[str] = set()
    default_action = Action.ALLOW
    for field, value in policy.items():
        if field == "version":
            continue
        if field == "global":
            global_config = _mapping(value, "global")
            _reject_unknown_fields(global_config, {"default_action"}, "global")
            if "default_action" in global_config:
                default_action = _parse_action(global_config["default_action"])
        elif field == "rules":
            _add_rules(value, {}, rules, seen_ids, rate_limits, allow_rate_limit)
        elif field == "agents":
            _add_agents(value, rules, seen_ids, rate_limits, allow_rate_limit)

    return Engine(rules=rules, default_action=default_action, version=version, rate_limits=rate_limits)


def _add_agents(
    agents: Any,
    rules: list[Rule],
    seen_ids: set[str],
    rate_limits: dict[int, RateLimit],
    allow_rate_limit: bool,
) -> None:
    agents = _mapping(agents, "agents")
    for agent_name, agent_config in agents.items():
        agent_name = _string(agent_name, "agent name", "invalid_field")
        agent_config = _mapping(agent_config, f"agents.{agent_name}")
        _reject_unknown_fields(agent_config, {"tools"}, f"agents.{agent_name}")
        if "tools" not in agent_config:
            raise PolicyError("invalid_field", f"agents.{agent_name}.tools is required")
        tools = _mapping(agent_config["tools"], f"agents.{agent_name}.tools")
        for tool_name, tool_config in tools.items():
            tool_name = _string(tool_name, "tool name", "invalid_field")
            tool_config = _mapping(tool_config, f"agents.{agent_name}.tools.{tool_name}")
            _reject_unknown_fields(tool_config, {"rules"}, f"agents.{agent_name}.tools.{tool_name}")
            if "rules" not in tool_config:
                raise PolicyError("invalid_field", f"rules are required for tool {tool_name}")
            _add_rules(
                tool_config["rules"],
                {"agent": agent_name, "tool": tool_name},
                rules,
                seen_ids,
                rate_limits,
                allow_rate_limit,
            )


def _add_rules(
    entries: Any,
    enclosing_target: dict[str, str],
    rules: list[Rule],
    seen_ids: set[str],
    rate_limits: dict[int, RateLimit],
    allow_rate_limit: bool,
) -> None:
    if isinstance(entries, (str, bytes)) or not isinstance(entries, Sequence):
        raise PolicyError("invalid_field", "rules must be a sequence")
    for entry in entries:
        rule = _mapping(entry, "rule")
        _reject_unknown_fields(
            rule, _RULE_FIELDS | ({"rate_limit"} if allow_rate_limit else set()), "rule"
        )
        if "action" not in rule:
            raise PolicyError("invalid_action", "rule action is required")
        if "id" in rule:
            rule_id = _unambiguous_string(rule["id"], "rule id", "invalid_field")
            if rule_id in seen_ids:
                raise PolicyError("invalid_field", f"duplicate rule id: {rule_id}")
            seen_ids.add(rule_id)

        target = _parse_target(rule.get("target", {}))
        for key, value in enclosing_target.items():
            if key in target and target[key] != value:
                raise PolicyError("conflicting_target", f"nested target conflicts with {key}")
            target[key] = value
        condition = _parse_condition(rule.get("condition", {}))
        action = _parse_action(rule["action"])
        rate_limit = _parse_rate_limit(rule["rate_limit"]) if "rate_limit" in rule else None
        if rate_limit is not None and action is not Action.ALLOW:
            raise PolicyError("invalid_field", "rate_limit is permitted only on an allow rule")
        rule_index = len(rules)
        rules.append(
            Rule(
                action=action,
                target=target,
                condition=condition,
                rule_index=rule_index,
            )
        )
        if rate_limit is not None:
            rate_limits[rule_index] = rate_limit


def _parse_rate_limit(value: Any) -> RateLimit:
    config = _mapping(value, "rate_limit")
    _reject_unknown_fields(config, {"max_calls", "window_seconds"}, "rate_limit")
    if set(config) != {"max_calls", "window_seconds"}:
        raise PolicyError("invalid_field", "rate_limit requires max_calls and window_seconds")
    max_calls = config["max_calls"]
    window_seconds = config["window_seconds"]
    if (
        type(max_calls) is not int
        or type(window_seconds) is not int
        or not 1 <= max_calls <= 86_400
        or not 1 <= window_seconds <= 86_400
    ):
        raise PolicyError("invalid_field", "rate_limit values must be positive integers at most 86400")
    return RateLimit(max_calls=max_calls, window_seconds=window_seconds)


def _parse_action(value: Any) -> Action:
    if not isinstance(value, str) or value not in _ACTIONS:
        raise PolicyError("invalid_action", f"unsupported policy action: {value!r}")
    return _ACTIONS[value]


def _parse_target(value: Any) -> dict[str, str]:
    target = _mapping(value, "target", "invalid_target")
    _reject_unknown_fields(target, _TARGET_FIELDS, "target", "invalid_target")
    parsed: dict[str, str] = {}
    for key in ("agent", "tool", "user"):
        if key in target:
            parsed[key] = _unambiguous_string(target[key], f"target.{key}", "invalid_target")
    if "context" in target:
        context = _mapping(target["context"], "target.context", "invalid_target")
        for key, value in context.items():
            key = _unambiguous_string(key, "target.context key", "invalid_target")
            parsed[f"context.{key}"] = _unambiguous_string(
                value, f"target.context.{key}", "invalid_target"
            )
    return parsed


def _parse_condition(value: Any) -> dict[str, Any]:
    return _parse_condition_node(value, depth=1, node_count=[0])


def _parse_condition_node(value: Any, *, depth: int, node_count: list[int]) -> dict[str, Any]:
    condition = _mapping(value, "condition", "invalid_condition")
    _reject_unknown_fields(condition, _CONDITION_FIELDS, "condition", "invalid_condition")
    node_count[0] += 1
    if depth > _MAX_CONDITION_DEPTH:
        raise PolicyError("invalid_condition", "condition nesting exceeds 32 levels")
    if node_count[0] > _MAX_CONDITION_NODES:
        raise PolicyError("invalid_condition", "condition contains more than 128 nodes")

    operators = _CONDITION_OPERATOR_FIELDS.intersection(condition)
    if operators:
        if len(operators) != 1 or len(condition) != 1:
            raise PolicyError(
                "invalid_condition",
                "a boolean condition must contain exactly one operator",
            )
        operator = next(iter(operators))
        operand = condition[operator]
        if operator in {"all", "any"}:
            if isinstance(operand, (str, bytes)) or not isinstance(operand, Sequence):
                raise PolicyError("invalid_condition", f"condition.{operator} must be a sequence")
            return {
                operator: [
                    _parse_condition_node(child, depth=depth + 1, node_count=node_count)
                    for child in operand
                ]
            }
        return {
            "not": _parse_condition_node(operand, depth=depth + 1, node_count=node_count)
        }

    parsed: dict[str, Any] = {}
    for key, value in condition.items():
        if key == "args_match":
            value = _unambiguous_string(value, f"condition.{key}", "invalid_condition")
            _validate_portable_regex(value)
        elif key == "path_pattern":
            value = _unambiguous_string(value, f"condition.{key}", "invalid_condition")
        else:
            try:
                parse_time_window(value)
            except ValueError as error:
                raise PolicyError("invalid_condition", f"invalid time_window: {error}") from error
        parsed[key] = value
    return parsed


def _validate_portable_regex(pattern: str) -> None:
    try:
        validate_args_pattern(pattern)
    except ValueError as error:
        raise PolicyError("invalid_regex", f"invalid args_match regex {pattern!r}: {error}") from error


def _mapping(value: Any, name: str, code: str = "invalid_field") -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise PolicyError(code, f"{name} must be a mapping")
    return value


def _string(value: Any, name: str, code: str) -> str:
    if not isinstance(value, str):
        raise PolicyError(code, f"{name} must be a string")
    return value


def _unambiguous_string(value: Any, name: str, code: str) -> str:
    value = _string(value, name, code)
    if any(pattern.fullmatch(value) for pattern in _AMBIGUOUS_SCALAR_PATTERNS):
        raise PolicyError(code, f"{name} must not use an ambiguous YAML scalar: {value!r}")
    return value


def _reject_unknown_fields(
    mapping: Mapping[Any, Any], allowed: set[str], name: str, code: str = "invalid_field"
) -> None:
    for key in mapping:
        if not isinstance(key, str) or key not in allowed:
            raise PolicyError(code, f"invalid field in {name}: {key!r}")
