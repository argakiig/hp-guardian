use crate::conditions::evaluate;
use crate::matching::rule_matches_rule;
use crate::models::{Action, Decision, PolicyCall, Rule};

fn rule_specificity(rule: &Rule) -> usize {
    rule.target.len()
}

/// The rule engine — resolves a PolicyCall against a set of rules.
#[derive(Debug, Clone)]
pub struct Engine {
    pub rules: Vec<Rule>,
    default_action: Action,
}

impl Engine {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self::with_default_action(rules, Action::Allow)
    }

    pub fn with_default_action(rules: Vec<Rule>, default_action: Action) -> Self {
        Self {
            rules,
            default_action,
        }
    }

    pub fn resolve_call(&self, call: &PolicyCall) -> Decision {
        let matching: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| rule_matches_rule(r, call) && evaluate(r, call))
            .collect();

        if matching.is_empty() {
            return Decision {
                action: self.default_action,
                matched_rules: Vec::new(),
            };
        }

        // Sort by specificity descending (more target fields = more specific)
        let mut sorted = matching;
        sorted.sort_by_key(|rule| std::cmp::Reverse(rule_specificity(rule)));

        let best = sorted[0];
        let best_specificity = rule_specificity(best);

        // Among same specificity, deny overrides allow
        if sorted
            .iter()
            .any(|r| r.action == Action::Deny && rule_specificity(r) == best_specificity)
        {
            // Find the first deny rule at this specificity level
            let deny_idx = sorted
                .iter()
                .position(|r| r.action == Action::Deny && rule_specificity(r) == best_specificity)
                .unwrap();
            Decision {
                action: Action::Deny,
                matched_rules: vec![sorted[deny_idx].rule_index],
            }
        } else {
            Decision {
                action: best.action,
                matched_rules: vec![best.rule_index],
            }
        }
    }
}
