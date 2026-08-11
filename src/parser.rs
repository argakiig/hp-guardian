use crate::models::{Action, PolicyError, Rule};
use crate::Engine;
use std::collections::BTreeMap;

#[derive(serde::Deserialize)]
struct RuleEntry {
    action: String,
    target: Option<BTreeMap<String, serde_yaml::Value>>,
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
    rules: Vec<RuleEntry>,
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

        for rule_entry in &policy.rules {
            add_rule(&mut rules, rule_entry, BTreeMap::new(), &mut index)?;
        }

        for (agent_name, agent_config) in &policy.agents {
            for (tool_name, tool_config) in &agent_config.tools {
                for rule_entry in &tool_config.rules {
                    let enclosing_target = [
                        ("agent".to_owned(), agent_name.clone()),
                        ("tool".to_owned(), tool_name.clone()),
                    ]
                    .into();
                    add_rule(&mut rules, rule_entry, enclosing_target, &mut index)?;
                }
            }
        }

        Ok(Engine::with_default_action(rules, default_action))
    }
}

fn add_rule(
    rules: &mut Vec<Rule>,
    rule_entry: &RuleEntry,
    enclosing_target: BTreeMap<String, String>,
    index: &mut usize,
) -> Result<(), PolicyError> {
    let action = parse_action(&rule_entry.action)?;
    let mut target = parse_target(rule_entry.target.as_ref())?;
    for (key, value) in enclosing_target {
        add_enclosing_target(&mut target, &key, &value)?;
    }
    let condition = rule_entry.condition.clone().unwrap_or_default();
    validate_conditions(&condition)?;

    rules.push(Rule {
        action,
        target,
        condition,
        rule_index: *index,
    });
    *index += 1;
    Ok(())
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

fn parse_target(
    target: Option<&BTreeMap<String, serde_yaml::Value>>,
) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut parsed = BTreeMap::new();

    for (key, value) in target.into_iter().flatten() {
        match key.as_str() {
            "agent" | "tool" | "user" => {
                let value = value.as_str().ok_or_else(|| PolicyError::InvalidTarget {
                    target: key.clone(),
                })?;
                parsed.insert(key.clone(), value.to_owned());
            }
            "context" => {
                let context = value
                    .as_mapping()
                    .ok_or_else(|| PolicyError::InvalidTarget {
                        target: key.clone(),
                    })?;
                for (context_key, context_value) in context {
                    let context_key =
                        context_key
                            .as_str()
                            .ok_or_else(|| PolicyError::InvalidTarget {
                                target: "context".to_owned(),
                            })?;
                    let context_value =
                        context_value
                            .as_str()
                            .ok_or_else(|| PolicyError::InvalidTarget {
                                target: format!("context.{context_key}"),
                            })?;
                    parsed.insert(format!("context.{context_key}"), context_value.to_owned());
                }
            }
            _ => {
                return Err(PolicyError::InvalidTarget {
                    target: key.clone(),
                });
            }
        }
    }

    Ok(parsed)
}

fn add_enclosing_target(
    target: &mut BTreeMap<String, String>,
    key: &str,
    enclosing_value: &str,
) -> Result<(), PolicyError> {
    match target.get(key) {
        Some(value) if value != enclosing_value => Err(PolicyError::ConflictingTarget {
            target: key.to_owned(),
        }),
        _ => {
            target.insert(key.to_owned(), enclosing_value.to_owned());
            Ok(())
        }
    }
}

fn validate_conditions(condition: &BTreeMap<String, String>) -> Result<(), PolicyError> {
    for (key, value) in condition {
        match key.as_str() {
            "args_match" => {
                regex::Regex::new(value).map_err(|source| PolicyError::InvalidRegex {
                    pattern: value.clone(),
                    source,
                })?;
            }
            "path_pattern" => {}
            _ => {
                return Err(PolicyError::InvalidCondition {
                    condition: key.clone(),
                });
            }
        }
    }
    Ok(())
}
