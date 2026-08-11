use crate::models::{Condition, PolicyCall, Rule};
use chrono::{DateTime, Utc};

#[derive(Clone, Copy)]
enum TokenKind {
    Literal(char),
    Any,
}

#[derive(Clone, Copy)]
struct Token {
    kind: TokenKind,
    repeated: bool,
}

impl Token {
    fn matches(self, character: char) -> bool {
        match self.kind {
            TokenKind::Literal(expected) => expected == character,
            TokenKind::Any => true,
        }
    }
}

struct ArgsPattern {
    start_anchored: bool,
    end_anchored: bool,
    tokens: Vec<Token>,
}

/// Validate the small v1 pattern language shared by both runtimes.
pub(crate) fn validate_args_match(pattern: &str) -> Result<(), String> {
    parse_args_pattern(pattern).map(|_| ())
}

/// Evaluate all conditions on a rule against a call. All conditions must pass (ANDed).
pub fn evaluate(rule: &Rule, call: &PolicyCall) -> bool {
    evaluate_at(rule, call, Utc::now())
}

/// Evaluate all conditions on a rule at an explicit UTC instant.
pub fn evaluate_at(rule: &Rule, call: &PolicyCall, now: DateTime<Utc>) -> bool {
    evaluate_condition(&rule.condition, call, now)
}

fn evaluate_condition(condition: &Condition, call: &PolicyCall, now: DateTime<Utc>) -> bool {
    match condition {
        Condition::Leaves {
            args_match: args_pattern,
            path_pattern,
            time_window,
        } => {
            args_pattern
                .as_ref()
                .is_none_or(|pattern| args_match(&call.args.join(" "), pattern))
                && path_pattern.as_ref().is_none_or(|pattern| {
                    call.args
                        .iter()
                        .any(|argument| path_matches(pattern, argument))
                })
                && time_window
                    .as_ref()
                    .is_none_or(|window| window.start <= now && now < window.end)
        }
        Condition::All(children) => children
            .iter()
            .all(|child| evaluate_condition(child, call, now)),
        Condition::Any(children) => children
            .iter()
            .any(|child| evaluate_condition(child, call, now)),
        Condition::Not(child) => !evaluate_condition(child, call, now),
    }
}

fn args_match(text: &str, pattern: &str) -> bool {
    let Ok(pattern) = parse_args_pattern(pattern) else {
        return false;
    };
    let characters: Vec<char> = text.chars().collect();

    if pattern.start_anchored {
        return matches_at(&pattern, &characters, 0);
    }

    (0..=characters.len()).any(|start| matches_at(&pattern, &characters, start))
}

fn matches_at(pattern: &ArgsPattern, characters: &[char], start: usize) -> bool {
    let mut memo = vec![vec![None; characters.len() + 1]; pattern.tokens.len() + 1];
    matches_from(pattern, characters, 0, start, &mut memo)
}

fn matches_from(
    pattern: &ArgsPattern,
    characters: &[char],
    token_index: usize,
    character_index: usize,
    memo: &mut [Vec<Option<bool>>],
) -> bool {
    if let Some(result) = memo[token_index][character_index] {
        return result;
    }

    let result = if token_index == pattern.tokens.len() {
        !pattern.end_anchored || character_index == characters.len()
    } else {
        let token = pattern.tokens[token_index];
        if token.repeated {
            matches_from(pattern, characters, token_index + 1, character_index, memo)
                || (character_index < characters.len()
                    && token.matches(characters[character_index])
                    && matches_from(pattern, characters, token_index, character_index + 1, memo))
        } else {
            character_index < characters.len()
                && token.matches(characters[character_index])
                && matches_from(
                    pattern,
                    characters,
                    token_index + 1,
                    character_index + 1,
                    memo,
                )
        }
    };
    memo[token_index][character_index] = Some(result);
    result
}

fn parse_args_pattern(pattern: &str) -> Result<ArgsPattern, String> {
    let characters: Vec<char> = pattern.chars().collect();
    let mut index = 0;
    let start_anchored = characters.first() == Some(&'^');
    if start_anchored {
        index += 1;
    }

    let mut end_anchored = false;
    let mut tokens = Vec::new();
    while index < characters.len() {
        let character = characters[index];
        match character {
            '$' if index + 1 == characters.len() => {
                end_anchored = true;
                index += 1;
            }
            '^' | '$' => return Err("anchors are only valid at pattern boundaries".to_owned()),
            '\\' => {
                let escaped = *characters
                    .get(index + 1)
                    .ok_or_else(|| "pattern ends with an escape".to_owned())?;
                if !matches!(escaped, '\\' | '.' | '*' | '^' | '$') {
                    return Err(format!("unsupported escape: \\{escaped}"));
                }
                tokens.push(Token {
                    kind: TokenKind::Literal(escaped),
                    repeated: false,
                });
                index += 2;
            }
            '*' => {
                let Some(previous) = tokens.last_mut() else {
                    return Err("* must follow a literal or .".to_owned());
                };
                if previous.repeated {
                    return Err("* cannot repeat another *".to_owned());
                }
                previous.repeated = true;
                index += 1;
            }
            '.' => {
                tokens.push(Token {
                    kind: TokenKind::Any,
                    repeated: false,
                });
                index += 1;
            }
            '[' | ']' | '(' | ')' | '{' | '}' | '|' | '+' | '?' => {
                return Err(format!("unsupported pattern character: {character}"));
            }
            literal => {
                tokens.push(Token {
                    kind: TokenKind::Literal(literal),
                    repeated: false,
                });
                index += 1;
            }
        }
    }

    Ok(ArgsPattern {
        start_anchored,
        end_anchored,
        tokens,
    })
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
