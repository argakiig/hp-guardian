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
