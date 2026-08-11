use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Actions the engine can take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    Throttle,
    Log,
    RequireApproval,
    Redirect,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Throttle => "throttle",
            Self::Log => "log",
            Self::RequireApproval => "require_approval",
            Self::Redirect => "redirect",
        }
    }
}

/// A policy failed validation before it could be enforced.
#[derive(Debug)]
pub enum PolicyError {
    InvalidYaml(serde_yaml::Error),
    InvalidAction {
        action: String,
    },
    InvalidCondition {
        condition: String,
    },
    InvalidTarget {
        target: String,
    },
    InvalidField {
        field: String,
    },
    ConflictingTarget {
        target: String,
    },
    InvalidRegex {
        pattern: String,
        source: regex::Error,
    },
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(formatter, "invalid YAML policy: {error}"),
            Self::InvalidAction { action } => {
                write!(formatter, "unsupported policy action: {action}")
            }
            Self::InvalidCondition { condition } => {
                write!(formatter, "unsupported policy condition: {condition}")
            }
            Self::InvalidTarget { target } => {
                write!(formatter, "unsupported policy target: {target}")
            }
            Self::InvalidField { field } => write!(formatter, "invalid policy field: {field}"),
            Self::ConflictingTarget { target } => {
                write!(
                    formatter,
                    "nested target conflicts with enclosing {target} scope"
                )
            }
            Self::InvalidRegex { pattern, source } => {
                write!(formatter, "invalid args_match regex {pattern:?}: {source}")
            }
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidYaml(error) => Some(error),
            Self::InvalidRegex { source, .. } => Some(source),
            Self::InvalidAction { .. }
            | Self::InvalidCondition { .. }
            | Self::InvalidTarget { .. }
            | Self::InvalidField { .. }
            | Self::ConflictingTarget { .. } => None,
        }
    }
}

/// A single declarative policy rule.
#[derive(Debug, Clone)]
pub struct Rule {
    pub action: Action,
    pub target: BTreeMap<String, String>,
    pub condition: BTreeMap<String, String>,
    pub rule_index: usize,
}

/// A tool call that the engine evaluates against policy rules.
#[derive(Debug, Clone, Default)]
pub struct PolicyCall {
    pub agent: Option<String>,
    pub tool: Option<String>,
    pub args: Vec<String>,
    pub user: Option<String>,
    pub context: BTreeMap<String, String>,
}

/// The decision returned by the engine for a given call.
#[derive(Debug, Clone)]
pub struct Decision {
    pub action: Action,
    pub matched_rules: Vec<usize>,
}

/// The structured audit record emitted for a policy decision.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub agent: Option<String>,
    pub tool: Option<String>,
    pub args: Vec<String>,
    pub decision: Action,
    pub matched_rules: Vec<usize>,
}
