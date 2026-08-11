use crate::conditions::validate_args_match as validate_portable_args_match;
use crate::models::{Action, PolicyError, Rule};
use crate::Engine;
use std::collections::{BTreeMap, BTreeSet};

const SUPPORTED_VERSION: i64 = 1;

/// Parses YAML policy strings into an Engine.
pub struct PolicyParser;

impl PolicyParser {
    pub fn parse(yaml_str: &str) -> Result<Engine, PolicyError> {
        let policy: serde_yaml::Value =
            serde_yaml::from_str(yaml_str).map_err(PolicyError::InvalidYaml)?;
        match declared_version(&policy)? {
            SUPPORTED_VERSION => parse_v1(&policy),
            version => Err(PolicyError::UnsupportedVersion {
                version: Some(version.to_string()),
            }),
        }
    }
}

fn declared_version(policy: &serde_yaml::Value) -> Result<i64, PolicyError> {
    let fields = mapping(policy, "policy")?;
    let version_value = fields
        .iter()
        .find_map(|(field, value)| (field.as_str() == Some("version")).then_some(value))
        .ok_or(PolicyError::UnsupportedVersion { version: None })?;

    let version = version_value.as_i64();
    version.ok_or_else(|| PolicyError::UnsupportedVersion {
        version: version_value
            .as_str()
            .map(str::to_owned)
            .or_else(|| version.map(|value| value.to_string())),
    })
}

fn parse_v1(policy: &serde_yaml::Value) -> Result<Engine, PolicyError> {
    let fields = mapping(policy, "policy")?;
    let mut default_action = Action::Allow;
    let mut rules = Vec::new();
    let mut rule_ids = BTreeSet::new();
    let mut index = 0;

    for (field, value) in fields {
        let field = field_name(field, "top-level")?;
        match field {
            "version" => {}
            "global" => default_action = parse_global(value)?,
            "rules" => add_rules(
                &mut rules,
                value,
                BTreeMap::new(),
                &mut rule_ids,
                &mut index,
            )?,
            "agents" => add_agents(&mut rules, value, &mut rule_ids, &mut index)?,
            _ => {
                return Err(PolicyError::InvalidField {
                    field: field.to_owned(),
                });
            }
        }
    }

    Ok(Engine::with_default_action(rules, default_action))
}

fn parse_global(value: &serde_yaml::Value) -> Result<Action, PolicyError> {
    let fields = mapping(value, "global")?;
    let mut default_action = Action::Allow;

    for (field, value) in fields {
        let field = field_name(field, "global")?;
        match field {
            "default_action" => {
                let action = value.as_str().ok_or_else(|| PolicyError::InvalidAction {
                    action: value_description(value),
                })?;
                default_action = parse_action(action)?;
            }
            _ => {
                return Err(PolicyError::InvalidField {
                    field: format!("global.{field}"),
                });
            }
        }
    }

    Ok(default_action)
}

fn add_agents(
    rules: &mut Vec<Rule>,
    agents: &serde_yaml::Value,
    rule_ids: &mut BTreeSet<String>,
    index: &mut usize,
) -> Result<(), PolicyError> {
    for (agent_name, agent_value) in mapping(agents, "agents")? {
        let agent_name = field_name(agent_name, "agent")?;
        let agent_fields = mapping(agent_value, "agent configuration")?;
        let mut tools = None;

        for (field, value) in agent_fields {
            match field_name(field, "agent configuration")? {
                "tools" => tools = Some(value),
                field => {
                    return Err(PolicyError::InvalidField {
                        field: format!("agents.{agent_name}.{field}"),
                    });
                }
            }
        }

        let tools = tools.ok_or_else(|| PolicyError::InvalidField {
            field: format!("agents.{agent_name}.tools"),
        })?;
        for (tool_name, tool_value) in mapping(tools, "tools")? {
            let tool_name = field_name(tool_name, "tool")?;
            let tool_fields = mapping(tool_value, "tool configuration")?;
            let mut tool_rules = None;

            for (field, value) in tool_fields {
                match field_name(field, "tool configuration")? {
                    "rules" => tool_rules = Some(value),
                    field => {
                        return Err(PolicyError::InvalidField {
                            field: format!("agents.{agent_name}.tools.{tool_name}.{field}"),
                        });
                    }
                }
            }

            let tool_rules = tool_rules.ok_or_else(|| PolicyError::InvalidField {
                field: format!("agents.{agent_name}.tools.{tool_name}.rules"),
            })?;
            let enclosing_target = [
                ("agent".to_owned(), agent_name.to_owned()),
                ("tool".to_owned(), tool_name.to_owned()),
            ]
            .into();
            add_rules(rules, tool_rules, enclosing_target, rule_ids, index)?;
        }
    }
    Ok(())
}

fn add_rules(
    rules: &mut Vec<Rule>,
    value: &serde_yaml::Value,
    enclosing_target: BTreeMap<String, String>,
    rule_ids: &mut BTreeSet<String>,
    index: &mut usize,
) -> Result<(), PolicyError> {
    let entries = value
        .as_sequence()
        .ok_or_else(|| PolicyError::InvalidField {
            field: "rules must be a sequence".to_owned(),
        })?;
    for entry in entries {
        add_rule(rules, entry, enclosing_target.clone(), rule_ids, index)?;
    }
    Ok(())
}

fn add_rule(
    rules: &mut Vec<Rule>,
    value: &serde_yaml::Value,
    enclosing_target: BTreeMap<String, String>,
    rule_ids: &mut BTreeSet<String>,
    index: &mut usize,
) -> Result<(), PolicyError> {
    let fields = mapping(value, "rule")?;
    let mut action = None;
    let mut target = None;
    let mut condition = None;
    let mut id = None;

    for (field, value) in fields {
        match field_name(field, "rule")? {
            "action" => {
                action = Some(
                    value
                        .as_str()
                        .ok_or_else(|| PolicyError::InvalidAction {
                            action: value_description(value),
                        })?
                        .to_owned(),
                );
            }
            "target" => target = Some(value),
            "condition" => condition = Some(value),
            "id" => {
                let value = value.as_str().ok_or_else(|| PolicyError::InvalidField {
                    field: "rule.id".to_owned(),
                })?;
                if is_ambiguous_yaml_scalar(value) {
                    return Err(PolicyError::InvalidField {
                        field: "rule.id must not be an ambiguous YAML scalar".to_owned(),
                    });
                }
                id = Some(value.to_owned());
            }
            field => {
                return Err(PolicyError::InvalidField {
                    field: format!("rule.{field}"),
                });
            }
        }
    }

    let action = action.ok_or_else(|| PolicyError::InvalidAction {
        action: "missing rule.action".to_owned(),
    })?;
    if let Some(id) = id {
        if !rule_ids.insert(id.clone()) {
            return Err(PolicyError::InvalidField {
                field: format!("duplicate rule id: {id}"),
            });
        }
    }

    let mut target = parse_target(target)?;
    for (key, value) in enclosing_target {
        add_enclosing_target(&mut target, &key, &value)?;
    }
    let condition = parse_conditions(condition)?;

    rules.push(Rule {
        action: parse_action(&action)?,
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
    target: Option<&serde_yaml::Value>,
) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut parsed = BTreeMap::new();
    let Some(target) = target else {
        return Ok(parsed);
    };

    let fields = mapping(target, "target").map_err(|_| PolicyError::InvalidTarget {
        target: "target".to_owned(),
    })?;
    for (key, value) in fields {
        let key = field_name(key, "target").map_err(|_| PolicyError::InvalidTarget {
            target: "target".to_owned(),
        })?;
        match key {
            "agent" | "tool" | "user" => {
                let value = value.as_str().ok_or_else(|| PolicyError::InvalidTarget {
                    target: key.to_owned(),
                })?;
                if is_ambiguous_yaml_scalar(value) {
                    return Err(PolicyError::InvalidTarget {
                        target: key.to_owned(),
                    });
                }
                parsed.insert(key.to_owned(), value.to_owned());
            }
            "context" => {
                let context =
                    mapping(value, "target.context").map_err(|_| PolicyError::InvalidTarget {
                        target: "context".to_owned(),
                    })?;
                for (context_key, context_value) in context {
                    let context_key = field_name(context_key, "target.context").map_err(|_| {
                        PolicyError::InvalidTarget {
                            target: "context".to_owned(),
                        }
                    })?;
                    let context_value =
                        context_value
                            .as_str()
                            .ok_or_else(|| PolicyError::InvalidTarget {
                                target: format!("context.{context_key}"),
                            })?;
                    if is_ambiguous_yaml_scalar(context_value) {
                        return Err(PolicyError::InvalidTarget {
                            target: format!("context.{context_key}"),
                        });
                    }
                    parsed.insert(format!("context.{context_key}"), context_value.to_owned());
                }
            }
            _ => {
                return Err(PolicyError::InvalidTarget {
                    target: key.to_owned(),
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

fn parse_conditions(
    condition: Option<&serde_yaml::Value>,
) -> Result<BTreeMap<String, String>, PolicyError> {
    let mut parsed = BTreeMap::new();
    let Some(condition) = condition else {
        return Ok(parsed);
    };

    let fields = mapping(condition, "condition").map_err(|_| PolicyError::InvalidCondition {
        condition: "condition".to_owned(),
    })?;
    for (key, value) in fields {
        let key = field_name(key, "condition").map_err(|_| PolicyError::InvalidCondition {
            condition: "condition".to_owned(),
        })?;
        match key {
            "args_match" => {
                let value = value
                    .as_str()
                    .ok_or_else(|| PolicyError::InvalidCondition {
                        condition: key.to_owned(),
                    })?;
                if is_ambiguous_yaml_scalar(value) {
                    return Err(PolicyError::InvalidCondition {
                        condition: key.to_owned(),
                    });
                }
                validate_args_match(value)?;
                parsed.insert(key.to_owned(), value.to_owned());
            }
            "path_pattern" => {
                let value = value
                    .as_str()
                    .ok_or_else(|| PolicyError::InvalidCondition {
                        condition: key.to_owned(),
                    })?;
                if is_ambiguous_yaml_scalar(value) {
                    return Err(PolicyError::InvalidCondition {
                        condition: key.to_owned(),
                    });
                }
                parsed.insert(key.to_owned(), value.to_owned());
            }
            _ => {
                return Err(PolicyError::InvalidCondition {
                    condition: key.to_owned(),
                });
            }
        }
    }

    Ok(parsed)
}

fn validate_args_match(pattern: &str) -> Result<(), PolicyError> {
    validate_portable_args_match(pattern).map_err(|reason| PolicyError::InvalidRegex {
        pattern: pattern.to_owned(),
        reason,
    })
}

fn mapping<'a>(
    value: &'a serde_yaml::Value,
    description: &str,
) -> Result<&'a serde_yaml::Mapping, PolicyError> {
    value.as_mapping().ok_or_else(|| PolicyError::InvalidField {
        field: format!("{description} must be a mapping"),
    })
}

fn field_name<'a>(field: &'a serde_yaml::Value, scope: &str) -> Result<&'a str, PolicyError> {
    field.as_str().ok_or_else(|| PolicyError::InvalidField {
        field: format!("{scope} field names must be strings"),
    })
}

fn value_description(value: &serde_yaml::Value) -> String {
    serde_yaml::to_string(value)
        .unwrap_or_else(|_| "non-string value".to_owned())
        .trim()
        .to_owned()
}

fn is_ambiguous_yaml_scalar(value: &str) -> bool {
    let lowercase = value.to_ascii_lowercase();
    if matches!(
        lowercase.as_str(),
        "y" | "yes" | "n" | "no" | "true" | "false" | "on" | "off" | "null" | "~"
    ) {
        return true;
    }

    let Some(first) = value.chars().next() else {
        return false;
    };
    if !first.is_ascii_digit() && !matches!(first, '+' | '-') {
        return false;
    }

    value.chars().all(|character| {
        character.is_ascii_digit()
            || matches!(
                character,
                '_' | ':' | '.' | '+' | '-' | 'e' | 'E' | 'x' | 'X' | 'o' | 'O' | 'b' | 'B'
            )
    })
}
