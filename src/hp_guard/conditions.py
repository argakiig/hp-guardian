from __future__ import annotations
from functools import lru_cache

from .models import Rule, PolicyCall


def evaluate(rule: Rule, call: PolicyCall) -> bool:
    """Evaluate all conditions on a rule against a call. All conditions must pass (ANDed)."""
    for key, value in rule.condition.items():
        if key == "args_match":
            if not args_match(call.args, value):
                return False
        elif key == "path_pattern":
            if not any(path_matches(value, argument) for argument in call.args):
                return False
        else:
            # Unknown condition keys cause the rule to NOT match
            return False
    return True


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
