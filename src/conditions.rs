use crate::models::{PolicyCall, Rule};
use regex::Regex;

/// Evaluate all conditions on a rule against a call. All conditions must pass (ANDed).
pub fn evaluate(rule: &Rule, call: &PolicyCall) -> bool {
    for (key, value) in &rule.condition {
        match key.as_str() {
            "args_match" => {
                let concatenated = call.args.join(" ");
                if !Regex::new(value).unwrap().is_match(&concatenated) {
                    return false;
                }
            }
            _ => {
                // Unknown condition keys cause the rule to NOT match
                return false;
            }
        }
    }
    true
}
