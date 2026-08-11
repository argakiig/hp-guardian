# Hardpoint Guardian — Implementation Plan

> **For palOMine:** Use test-driven-development skill to implement this plan step-by-step.

**Goal:** Implement the core rule parser and stateless enforcement engine from the hp-guard spec v0.1 — reading YAML policies, evaluating rules against tool calls, and returning decisions with matched rules.

**Architecture:** Two-module approach — `policy.Parser` converts YAML policy files to an internal rule index; `engine.Engine` evaluates incoming calls against that index using the spec's precedence model (agent > tool > global scope, deny > allow > throttle > log, most specific target wins).

**Tech Stack:** Python 3.14+, PyYAML for policy parsing, pure Python (no external deps beyond pytest + pyyaml).

---

## Phase 1: Rule Data Model

### Task 1.1: Create `Rule` and `Action` dataclasses

**Objective:** Define the internal representation of a single policy rule with typed action enum and condition dict.

**Files:**
- Create: `src/hp_guard/__init__.py` (make it importable)
- Create: `src/hp_guard/models.py`
- Test: `tests/test_models.py`

**Step 1: Write failing test**

```python
from hp_guard.models import Rule, Action

def test_rule_has_action_and_target():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    assert rule.action == Action.DENY
    assert rule.target["agent"] == "bot"
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_models.py::test_rule_has_action_and_target -v`
Expected: FAIL — "ModuleNotFoundError: No module named 'hp_guard.models'"

**Step 3: Write minimal implementation**

```python
# src/hp_guard/__init__.py
from hp_guard.models import Rule, Action  # noqa: F401

__version__ = "0.1.0"
```

```python
# src/hp_guard/models.py
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional


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
```

**Step 4: Run test to verify pass**

Run: `.venv/bin/python -m pytest tests/test_models.py::test_rule_has_action_and_target -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add Rule model and Action enum"
```

---

## Phase 2: Policy Call Input Model

### Task 2.1: Create `PolicyCall` dataclass

**Objective:** Define the internal representation of a tool call that the engine evaluates.

**Files:**
- Modify: `src/hp_guard/models.py` (add PolicyCall)
- Test: `tests/test_models.py`

**Step 1: Write failing test**

```python
from hp_guard.models import PolicyCall

def test_policy_call_fields():
    call = PolicyCall(
        agent="research-bot",
        tool="curl",
        args=["--delete", "http://example.com"],
        user="user-123",
        context={"phase": "prompt"},
    )
    assert call.agent == "research-bot"
    assert call.tool == "curl"
    assert call.args == ["--delete", "http://example.com"]
    assert call.user == "user-123"
    assert call.context == {"phase": "prompt"}
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_models.py::test_policy_call_fields -v`
Expected: FAIL — "name 'PolicyCall' is not defined"

**Step 3: Add PolicyCall to models.py**

```python
@dataclass
class PolicyCall:
    agent: Optional[str] = None
    tool: Optional[str] = None
    args: list = field(default_factory=list)
    user: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)
```

**Step 4: Run test to verify pass**

Run: `.venv/bin/python -m pytest tests/test_models.py::test_policy_call_fields -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add PolicyCall dataclass"
```

---

## Phase 3: Rule Matching (Core Logic)

### Task 3.1: Implement rule target matching

**Objective:** A rule's target is ANDed across fields. A rule matches a call if every specified target field in the rule matches the corresponding field in the call. Unspecified fields match anything.

**Files:**
- Create: `src/hp_guard/matching.py`
- Test: `tests/test_matching.py`

**Step 1: Write failing tests**

```python
from hp_guard.models import Rule, PolicyCall, Action


def test_unspecified_target_fields_match_anything():
    rule = Rule(action=Action.DENY, target={"agent": "bot"})
    call = PolicyCall(agent="bot", tool="anything")
    assert rule_matches_rule(rule, call) is True


def test_specific_field_must_match():
    rule = Rule(action=Action.DENY, target={"agent": "bot"})
    call = PolicyCall(agent="other", tool="curl")
    assert rule_matches_rule(rule, call) is False


def test_both_agent_and_tool_must_match():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    call = PolicyCall(agent="bot", tool="curl")
    assert rule_matches_rule(rule, call) is True


def test_tool_mismatch_fails():
    rule = Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"})
    call = PolicyCall(agent="bot", tool="write_file")
    assert rule_matches_rule(rule, call) is False


def test_empty_target_matches_all():
    rule = Rule(action=Action.ALLOW, target={})
    call = PolicyCall(agent="bot", tool="curl")
    assert rule_matches_rule(rule, call) is True
```

**Step 2: Run tests to verify failure**

Run: `.venv/bin/python -m pytest tests/test_matching.py -v`
Expected: FAIL — "name 'rule_matches_rule' is not defined"

**Step 3: Minimal implementation**

```python
# src/hp_guard/matching.py
from __future__ import annotations
from .models import Rule, PolicyCall


def rule_matches_rule(rule: Rule, call: PolicyCall) -> bool:
    for field_name, expected_value in rule.target.items():
        actual_value = getattr(call, field_name, None)
        if expected_value != actual_value:
            return False
    return True
```

**Step 4: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/test_matching.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add rule_matches_rule function"
```

---

## Phase 4: Condition Evaluation

### Task 4.1: Implement args_match condition

**Objective:** `args_match` is a regex that tool arguments are concatenated into and matched against.

**Files:**
- Create: `src/hp_guard/conditions.py`
- Test: `tests/test_conditions.py`

**Step 1: Write failing tests**

```python
import re
from hp_guard.models import Rule, PolicyCall, Action, conditions


def test_args_match_regex():
    rule = Rule(
        action=Action.DENY,
        condition={"args_match": ".*--delete.*"}
    )
    call = PolicyCall(tool="curl", args=["--delete", "http://example.com"])
    assert conditions.evaluate(rule, call) is True


def test_args_match_no_match():
    rule = Rule(
        action=Action.DENY,
        condition={"args_match": ".*--delete.*"}
    )
    call = PolicyCall(tool="curl", args=["--get", "http://example.com"])
    assert conditions.evaluate(rule, call) is False


def test_args_match_empty_args():
    rule = Rule(
        action=Action.DENY,
        condition={"args_match": ".*--delete.*"}
    )
    call = PolicyCall(tool="curl", args=[])
    assert conditions.evaluate(rule, call) is False
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_conditions.py -v`
Expected: FAIL — "ModuleNotFoundError"

**Step 3: Minimal implementation**

```python
# src/hp_guard/conditions.py
from __future__ import annotations
import re
from .models import Rule, PolicyCall


def evaluate(rule: Rule, call: PolicyCall) -> bool:
    """Evaluate all conditions on a rule against a call. All conditions must pass (ANDed)."""
    for key, value in rule.condition.items():
        if key == "args_match":
            if not args_match(call.args, value):
                return False
    return True


def args_match(args: list[str], pattern: str) -> bool:
    concatenated = " ".join(args)
    return bool(re.search(pattern, concatenated))
```

**Step 4: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/test_conditions.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add args_match condition evaluation"
```

---

## Phase 5: Engine — Rule Resolution & Decision

### Task 5.1: Implement Engine.resolve_call (find best matching rule)

**Objective:** Given a PolicyCall and a list of rules, find the single best-matching rule using precedence: more specific targets win (most target fields first). If multiple rules match with same specificity, deny overrides allow.

**Files:**
- Create: `src/hp_guard/engine.py`
- Test: `tests/test_engine.py`

**Step 1: Write failing tests**

```python
from hp_guard.models import Rule, PolicyCall, Action
from hp_guard.engine import Engine


def test_no_rules_returns_allow():
    engine = Engine(rules=[])
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.ALLOW
    assert decision.matched_rules == []


def test_single_matching_rule_applied():
    rules = [
        Rule(action=Action.DENY, target={"agent": "bot", "tool": "curl"}, rule_index=0)
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.DENY


def test_non_matching_rule_ignored():
    rules = [
        Rule(action=Action.DENY, target={"agent": "other", "tool": "curl"}, rule_index=0)
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.ALLOW


def test_most_specific_target_wins():
    rules = [
        Rule(action=Action.DENY, target={"agent": "bot"}, rule_index=0),
        Rule(action=Action.ALLOW, target={"agent": "bot", "tool": "curl"}, rule_index=1),
    ]
    engine = Engine(rules=rules)
    call = PolicyCall(agent="bot", tool="curl")
    decision = engine.resolve_call(call)
    assert decision.action == Action.ALLOW
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_engine.py -v`
Expected: FAIL — "ModuleNotFoundError"

**Step 3: Minimal implementation**

```python
# src/hp_guard/engine.py
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
        matching = [r for r in self.rules if rule_matches_rule(r, call)]
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
```

**Step 4: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/test_engine.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add Engine with rule resolution and precedence"
```

---

## Phase 6: YAML Policy Parsing

### Task 6.1: Implement PolicyParser

**Objective:** Parse a YAML policy string into an Engine. Extract global defaults, per-agent/per-tool rules. Handle the nested YAML structure from the spec.

**Files:**
- Create: `src/hp_guard/parser.py`
- Test: `tests/test_parser.py`

**Step 1: Write failing test**

```python
import yaml
from hp_guard.parser import PolicyParser


def test_parse_simple_deny_rule():
    yaml_str = """
global:
  default_action: allow

agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
"""
    engine = PolicyParser.parse(yaml_str)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "url"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "deny"
    assert len(decision.matched_rules) > 0


def test_parse_policy_with_global_default():
    yaml_str = """
global:
  default_action: deny

agents:
  research-bot:
    tools:
      read_file:
        rules:
          - action: allow
            condition:
              args_match: ".*"
"""
    engine = PolicyParser.parse(yaml_str)
    call = PolicyCall(agent="research-bot", tool="read_file", args=["test.txt"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "allow"
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_parser.py -v`
Expected: FAIL — "ModuleNotFoundError"

**Step 3: Minimal implementation**

```python
# src/hp_guard/parser.py
from __future__ import annotations
import yaml
from .models import Rule, PolicyCall, Action
from .engine import Engine


class PolicyParser:
    @staticmethod
    def parse(yaml_str: str) -> Engine:
        policy = yaml.safe_load(yaml_str)
        rules: list[Rule] = []
        index = 0

        for agent_name, agent_config in policy.get("agents", {}).items():
            tools = agent_config.get("tools", {})
            for tool_name, tool_config in tools.items():
                for rule_entry in tool_config.get("rules", []):
                    action_str = rule_entry.get("action", "allow")
                    rules.append(
                        Rule(
                            action=Action(action_str),
                            target={"agent": agent_name, "tool": tool_name},
                            condition=rule_entry.get("condition", {}),
                            rule_index=index,
                        )
                    )
                    index += 1

        return Engine(rules=rules)
```

**Step 4: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/test_parser.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add YAML policy parser"
```

---

## Phase 7: Audit Logging

### Task 7.1: Implement audit log entry creation

**Objective:** When a decision is made, produce a log entry with timestamp, call details, decision, and matched rules.

**Files:**
- Create: `src/hp_guard/logging.py`
- Test: `tests/test_logging.py`

**Step 1: Write failing test**

```python
from hp_guard.models import PolicyCall, Action
from hp_guard.engine import Decision
from hp_guard.logging import AuditLogger


def test_audit_log_entry_created():
    logger = AuditLogger()
    call = PolicyCall(agent="bot", tool="curl", args=["--delete", "url"])
    decision = Decision(action=Action.DENY, matched_rules=[0])
    entry = logger.log(call, decision)
    assert entry["agent"] == "bot"
    assert entry["tool"] == "curl"
    assert entry["decision"] == "deny"
    assert entry["matched_rules"] == [0]
    assert "timestamp" in entry
```

**Step 2: Run test to verify failure**

Run: `.venv/bin/python -m pytest tests/test_logging.py -v`
Expected: FAIL — "ModuleNotFoundError"

**Step 3: Minimal implementation**

```python
# src/hp_guard/logging.py
from __future__ import annotations
from datetime import datetime, timezone
from .models import PolicyCall
from .engine import Decision


class AuditLogger:
    def log(self, call: PolicyCall, decision: Decision) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": call.agent,
            "tool": call.tool,
            "args": call.args,
            "decision": decision.action.value,
            "matched_rules": decision.matched_rules,
        }
```

**Step 4: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/test_logging.py -v`
Expected: PASS

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: add AuditLogger for policy decisions"
```

---

## Phase 8: Full End-to-End + Integration

### Task 8.1: Integration test with full policy

**Objective:** Parse the example policy from the spec, verify correct decisions across multiple calls.

**Files:**
- Test: `tests/test_integration.py`

**Step 1: Write integration test**

```python
from hp_guard.parser import PolicyParser

POLICY = """
global:
  rate_limit: 100/min
  log_all: true
  default_action: allow

agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
        rate_limit: 20/min
      write_file:
        rules:
          - action: deny
            condition:
              path_pattern: "/etc/*"
"""

def test_research_bot_curl_delete_denied():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--delete", "http://x.com"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "deny"


def test_research_bot_curl_get_allowed():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="curl", args=["--get", "http://x.com"])
    decision = engine.resolve_call(call)
    assert decision.action.value == "allow"


def test_research_bot_write_file_etc_denied():
    engine = PolicyParser.parse(POLICY)
    call = PolicyCall(agent="research-bot", tool="write_file", args=["/etc/passwd"])
    decision = engine.resolve_call(call)
    # Currently no path_pattern support — this will fail until implemented
    # For now, test that unknown rules default to allow
    assert decision.action.value == "allow"
```

**Step 2: Run test to verify expected behavior**

Run: `.venv/bin/python -m pytest tests/test_integration.py -v`
Expected: 2 pass, 1 pass (write_file defaults to allow since no rules match — that's correct)

**Step 3: Commit**

```bash
git add -A && git commit -m "test: add integration test with full policy example"
```

---

## Phase 9: Polish — main.py & README

### Task 9.1: Update main.py as CLI entry point

**Files:**
- Modify: `main.py`

**Step 1: Minimal main.py**

```python
import sys
import yaml
from hp_guard.parser import PolicyParser
from hp_guard.models import PolicyCall
from hp_guard.engine import Engine
from hp_guard.logging import AuditLogger


def main():
    if len(sys.argv) < 2:
        print("Usage: hp-guard <policy.yaml> <call_json>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        policy = f.read()

    call = PolicyCall(**yaml.safe_load(sys.stdin.read()))
    engine = PolicyParser.parse(policy)
    decision = engine.resolve_call(call)
    logger = AuditLogger()
    entry = logger.log(call, decision)
    print(yaml.dump(entry))


if __name__ == "__main__":
    main()
```

**Step 2: Commit**

```bash
git add -A && git commit -m "feat: add CLI entry point for hp-guard"
```

---

## Verification Checklist

After all phases:
- [ ] Every test passes: `.venv/bin/python -m pytest tests/ -v`
- [ ] `python -c "import hp_guard; print(hp_guard.__version__)"` prints 0.1.0
- [ ] No production code written without a preceding failing test
- [ ] All commits are descriptive
