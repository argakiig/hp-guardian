use crate::models::{Action, PolicyError, Rule};
use crate::Engine;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
struct RuleEntry {
    action: String,
    condition: Option<BTreeMap<String, String>>,
}

#[derive(serde::Deserialize)]
struct ToolConfig {
    rules: Vec<RuleEntry>,
}

#[derive(serde::Deserialize)]
struct AgentConfig {
    tools: BTreeMap<String, ToolConfig>,
}

#[derive(serde::Deserialize)]
struct PolicyFile {
    #[serde(default)]
    global: GlobalConfig,
    #[serde(default)]
    agents: BTreeMap<String, AgentConfig>,
}

#[derive(Default, serde::Deserialize)]
struct GlobalConfig {
    default_action: Option<String>,
}

/// Parses YAML policy strings into an Engine.
pub struct PolicyParser;

impl PolicyParser {
    pub fn parse(yaml_str: &str) -> Result<Engine, PolicyError> {
        let policy: PolicyFile =
            serde_yaml::from_str(yaml_str).map_err(PolicyError::InvalidYaml)?;
        let default_action = policy
            .global
            .default_action
            .as_deref()
            .map(parse_action)
            .transpose()?
            .unwrap_or(Action::Allow);
        let mut rules: Vec<Rule> = Vec::new();
        let mut index: usize = 0;

        for (agent_name, agent_config) in &policy.agents {
            for (tool_name, tool_config) in &agent_config.tools {
                for rule_entry in &tool_config.rules {
                    let action = parse_action(&rule_entry.action)?;

                    let mut target = BTreeMap::new();
                    target.insert("agent".to_string(), agent_name.clone());
                    target.insert("tool".to_string(), tool_name.clone());

                    rules.push(Rule {
                        action,
                        target,
                        condition: rule_entry.condition.clone().unwrap_or_default(),
                        rule_index: index,
                    });
                    index += 1;
                }
            }
        }

        Ok(Engine::with_default_action(rules, default_action))
    }
}

fn parse_action(action: &str) -> Result<Action, PolicyError> {
    match action {
        "allow" => Ok(Action::Allow),
        "deny" => Ok(Action::Deny),
        "throttle" => Ok(Action::Throttle),
        "log" => Ok(Action::Log),
        "require_approval" => Ok(Action::RequireApproval),
        "redirect" => Ok(Action::Redirect),
        _ => Err(PolicyError::InvalidAction {
            action: action.to_owned(),
        }),
    }
}
