use crate::conditions::evaluate_at;
use crate::matching::rule_matches_rule;
use crate::models::{Action, Decision, PolicyCall, RateLimit, Rule};
use chrono::{DateTime, Utc};
use std::collections::BTreeMap;

fn rule_specificity(rule: &Rule) -> usize {
    rule.target.len()
}

fn action_priority(action: Action) -> usize {
    match action {
        Action::Deny => 6,
        Action::RequireApproval => 5,
        Action::Throttle => 4,
        Action::Redirect => 3,
        Action::Allow => 2,
        Action::Log => 1,
    }
}

/// The rule engine — resolves a PolicyCall against a set of rules.
#[derive(Debug, Clone)]
pub struct Engine {
    pub rules: Vec<Rule>,
    pub rate_limits: BTreeMap<usize, RateLimit>,
    pub version: i64,
    default_action: Action,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self::with_default_action(rules, Action::Allow)
    }

    pub fn with_default_action(rules: Vec<Rule>, default_action: Action) -> Self {
        Self::with_version(rules, default_action, 1, BTreeMap::new())
    }

    pub fn with_version(
        rules: Vec<Rule>,
        default_action: Action,
        version: i64,
        rate_limits: BTreeMap<usize, RateLimit>,
    ) -> Self {
        Self {
            rules,
            rate_limits,
            version,
            default_action,
        }
    }

    pub fn resolve_call(&self, call: &PolicyCall) -> Decision {
        self.resolve_call_at(call, Utc::now())
    }

    /// Resolve a call at an explicit UTC instant for deterministic evaluation.
    pub fn resolve_call_at(&self, call: &PolicyCall, now: DateTime<Utc>) -> Decision {
        let (decision, selected_rule) = self.resolve_call_with_selected_rule_at(call, now);
        if selected_rule.is_some_and(|index| self.rate_limits.contains_key(&index))
            && decision.action == Action::Allow
        {
            return Decision {
                action: Action::Throttle,
                matched_rules: decision.matched_rules,
            };
        }
        decision
    }

    pub(crate) fn resolve_call_with_selected_rule_at(
        &self,
        call: &PolicyCall,
        now: DateTime<Utc>,
    ) -> (Decision, Option<usize>) {
        let matching: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| rule_matches_rule(r, call) && evaluate_at(r, call, now))
            .collect();

        if matching.is_empty() {
            return (
                Decision {
                    action: self.default_action,
                    matched_rules: Vec::new(),
                },
                None,
            );
        }

        let matched_rules = matching.iter().map(|rule| rule.rule_index).collect();
        if matching.iter().any(|rule| rule.action == Action::Deny) {
            return (
                Decision {
                    action: Action::Deny,
                    matched_rules,
                },
                None,
            );
        }

        let mut best = matching[0];
        for rule in matching.into_iter().skip(1) {
            let candidate_specificity = rule_specificity(rule);
            let current_specificity = rule_specificity(best);
            if candidate_specificity > current_specificity
                || (candidate_specificity == current_specificity
                    && action_priority(rule.action) > action_priority(best.action))
            {
                best = rule;
            }
        }

        (
            Decision {
                action: best.action,
                matched_rules,
            },
            Some(best.rule_index),
        )
    }
}
