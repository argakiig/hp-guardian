use crate::models::{PolicyCall, Rule};

/// Check whether a rule's target fields are compatible with a PolicyCall.
/// All specified target fields are ANDed. Unspecified fields match anything.
pub fn rule_matches_rule(rule: &Rule, call: &PolicyCall) -> bool {
    for (key, value) in &rule.target {
        match key.as_str() {
            "agent" => match &call.agent {
                Some(call_agent) if call_agent != value => return false,
                None => return false,
                _ => {}
            },
            "tool" => match &call.tool {
                Some(call_tool) if call_tool != value => return false,
                None => return false,
                _ => {}
            },
            "user" => match &call.user {
                Some(call_user) if call_user != value => return false,
                None => return false,
                _ => {}
            },
            _ => {
                // Unknown target keys cause the rule to NOT match
                return false;
            }
        }
    }
    true
}
