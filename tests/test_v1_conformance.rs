use hp_guard::{PolicyCall, PolicyParser};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
struct ConformanceCase {
    name: String,
    policy: String,
    call: FixtureCall,
    expect: Option<ExpectedDecision>,
    expect_error: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
struct FixtureCall {
    #[serde(default)]
    agent: Option<String>,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    context: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedDecision {
    decision: String,
    matched_rules: Vec<usize>,
}

impl From<FixtureCall> for PolicyCall {
    fn from(call: FixtureCall) -> Self {
        Self {
            agent: call.agent,
            tool: call.tool,
            args: call.args,
            user: call.user,
            context: call.context,
        }
    }
}

#[test]
fn v1_core_conformance_cases_match_the_rust_runtime() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/conformance/cases/v1_core.json"
    );
    let fixture = std::fs::read_to_string(fixture_path).expect("v1 fixture is readable");
    let cases: Vec<ConformanceCase> =
        serde_json::from_str(&fixture).expect("v1 fixture is valid JSON");

    for case in cases {
        let parsed = PolicyParser::parse(&case.policy);
        match (case.expect, case.expect_error) {
            (Some(expected), None) => {
                let engine = parsed.unwrap_or_else(|error| {
                    panic!("{}: policy should parse, got {error}", case.name)
                });
                let decision = engine.resolve_call(&case.call.into());
                assert_eq!(decision.action.as_str(), expected.decision, "{}", case.name);
                assert_eq!(
                    decision.matched_rules, expected.matched_rules,
                    "{}",
                    case.name
                );
            }
            (None, Some(expected_error)) => {
                let error = parsed.expect_err("fixture policy should be rejected");
                assert_eq!(error.code(), expected_error, "{}", case.name);
            }
            _ => panic!("{}: fixture must have exactly one expectation", case.name),
        }
    }
}
