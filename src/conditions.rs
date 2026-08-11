use crate::models::{PolicyCall, Rule};
use regex::Regex;

/// Evaluate all conditions on a rule against a call. All conditions must pass (ANDed).
pub fn evaluate(rule: &Rule, call: &PolicyCall) -> bool {
    for (key, value) in &rule.condition {
        match key.as_str() {
            "args_match" => {
                let concatenated = call.args.join(" ");
                let Ok(regex) = Regex::new(value) else {
                    return false;
                };
                if !regex.is_match(&concatenated) {
                    return false;
                }
            }
            "path_pattern" => {
                if !call
                    .args
                    .iter()
                    .any(|argument| path_matches(value, argument))
                {
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

fn path_matches(pattern: &str, path: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let path: Vec<char> = path.chars().collect();
    let mut previous = vec![false; path.len() + 1];
    previous[0] = true;

    for pattern_character in pattern {
        let mut current = vec![false; path.len() + 1];
        if pattern_character == '*' {
            current[0] = previous[0];
            for index in 1..=path.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=path.len() {
                current[index] = previous[index - 1] && pattern_character == path[index - 1];
            }
        }
        previous = current;
    }

    previous[path.len()]
}
