use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Actions the engine can take when a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allow,
    Deny,
    Throttle,
    Log,
    RequireApproval,
    Redirect,
}

/// A policy failed validation before it could be enforced.
#[derive(Debug)]
pub enum PolicyError {
    InvalidYaml(serde_yaml::Error),
    InvalidAction { action: String },
}

impl Display for PolicyError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(formatter, "invalid YAML policy: {error}"),
            Self::InvalidAction { action } => {
                write!(formatter, "unsupported policy action: {action}")
            }
        }
    }
}

impl Error for PolicyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidYaml(error) => Some(error),
            Self::InvalidAction { .. } => None,
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
