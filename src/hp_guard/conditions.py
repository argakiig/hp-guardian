from __future__ import annotations
from datetime import datetime, timezone
from functools import lru_cache
import re
from collections.abc import Mapping
from typing import Any

from .models import Rule, PolicyCall


_UTC_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


def evaluate(rule: Rule, call: PolicyCall, now: datetime | None = None) -> bool:
    """Evaluate a validated condition tree against a call at one UTC instant."""
    return _evaluate_condition(rule.condition, call, now or datetime.now(timezone.utc))


def _evaluate_condition(condition: Mapping[str, Any], call: PolicyCall, now: datetime) -> bool:
    if "all" in condition:
        return all(_evaluate_condition(child, call, now) for child in condition["all"])
    if "any" in condition:
        return any(_evaluate_condition(child, call, now) for child in condition["any"])
    if "not" in condition:
        return not _evaluate_condition(condition["not"], call, now)

    for key, value in condition.items():
        if key == "args_match":
            if not args_match(call.args, value):
                return False
        elif key == "path_pattern":
            if not any(path_matches(value, argument) for argument in call.args):
                return False
        elif key == "time_window":
            start, end = parse_time_window(value)
            if not start <= now < end:
                return False
        else:
            # Unknown condition keys cause the rule to NOT match
            return False
    return True


def parse_time_window(value: Any) -> tuple[datetime, datetime]:
    """Validate and parse a closed UTC time-window definition."""
    if not isinstance(value, Mapping) or set(value) != {"start", "end"}:
        raise ValueError("time_window must contain exactly start and end")
    start = parse_utc_timestamp(value["start"])
    end = parse_utc_timestamp(value["end"])
    if end <= start:
        raise ValueError("time_window.end must be later than time_window.start")
    return start, end


def parse_utc_timestamp(value: Any) -> datetime:
    """Parse the policy's intentionally narrow RFC 3339 UTC timestamp subset."""
    if not isinstance(value, str) or not _UTC_TIMESTAMP.fullmatch(value):
        raise ValueError("timestamp must be RFC 3339 UTC and end in Z")
    try:
        return datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ValueError("timestamp must be a valid RFC 3339 UTC instant") from error


def args_match(args: list, pattern: str) -> bool:
    concatenated = " ".join(args)
    tokens, anchored_start, anchored_end = _parse_args_pattern(pattern)
    start_positions = (0,) if anchored_start else range(len(concatenated) + 1)

    @lru_cache(maxsize=None)
    def matches_from(token_index: int, character_index: int) -> bool:
        if token_index == len(tokens):
            return not anchored_end or character_index == len(concatenated)

        token, repeats = tokens[token_index]
        if repeats:
            if matches_from(token_index + 1, character_index):
                return True
            while (
                character_index < len(concatenated)
                and _token_matches(token, concatenated[character_index])
            ):
                character_index += 1
                if matches_from(token_index + 1, character_index):
                    return True
            return False

        return (
            character_index < len(concatenated)
            and _token_matches(token, concatenated[character_index])
            and matches_from(token_index + 1, character_index + 1)
        )

    return any(matches_from(0, position) for position in start_positions)


def validate_args_pattern(pattern: str) -> None:
    """Reject syntax outside the language-neutral v1 args_match grammar."""
    _parse_args_pattern(pattern)


def _parse_args_pattern(pattern: str) -> tuple[list[tuple[str | None, bool]], bool, bool]:
    tokens: list[tuple[str | None, bool]] = []
    anchored_start = False
    anchored_end = False
    index = 0

    while index < len(pattern):
        character = pattern[index]
        if character == "\\":
            index += 1
            if index == len(pattern) or pattern[index] not in "\\.*^$":
                raise ValueError("only \\, ., *, ^, and $ may be escaped")
            tokens.append((pattern[index], False))
        elif character == "^":
            if index != 0:
                raise ValueError("^ is only valid at the start of a pattern")
            anchored_start = True
        elif character == "$":
            if index != len(pattern) - 1:
                raise ValueError("$ is only valid at the end of a pattern")
            anchored_end = True
        elif character == ".":
            tokens.append((None, False))
        elif character == "*":
            if not tokens or tokens[-1][1]:
                raise ValueError("* must apply to one preceding literal or .")
            token, _ = tokens[-1]
            tokens[-1] = (token, True)
        elif character in "[]()|+?{}":
            raise ValueError(f"unsupported v1 args_match character: {character}")
        else:
            tokens.append((character, False))
        index += 1

    return tokens, anchored_start, anchored_end


def _token_matches(token: str | None, character: str) -> bool:
    return token is None or token == character


def path_matches(pattern: str, path: str) -> bool:
    """Match only literal characters and *, where * includes path separators."""
    previous = [True] + [False] * len(path)
    for pattern_character in pattern:
        current = [False] * (len(path) + 1)
        if pattern_character == "*":
            current[0] = previous[0]
            for index in range(1, len(path) + 1):
                current[index] = previous[index] or current[index - 1]
        else:
            for index in range(1, len(path) + 1):
                current[index] = previous[index - 1] and pattern_character == path[index - 1]
        previous = current
    return previous[-1]
