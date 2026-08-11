use chrono::{TimeZone, Utc};
use hp_guard::conditions::evaluate;
use hp_guard::models::{Action, Condition, PolicyCall, Rule};
use hp_guard::parser::PolicyParser;

#[test]
fn test_args_match_regex() {
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: Condition::Leaves {
            args_match: Some(".*--delete.*".into()),
            path_pattern: None,
            time_window: None,
        },
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: None,
        tool: Some("curl".into()),
        args: vec!["--delete".into(), "http://example.com".into()],
        user: None,
        context: Default::default(),
    };
    assert!(evaluate(&rule, &call));
}

#[test]
fn test_args_match_no_match() {
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: Condition::Leaves {
            args_match: Some(".*--delete.*".into()),
            path_pattern: None,
            time_window: None,
        },
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: None,
        tool: Some("curl".into()),
        args: vec!["--get".into(), "http://example.com".into()],
        user: None,
        context: Default::default(),
    };
    assert!(!evaluate(&rule, &call));
}

#[test]
fn test_args_match_empty_args() {
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: Condition::Leaves {
            args_match: Some(".*--delete.*".into()),
            path_pattern: None,
            time_window: None,
        },
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: None,
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!evaluate(&rule, &call));
}

#[test]
fn test_no_conditions_always_passes() {
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: None,
        tool: Some("curl".into()),
        args: vec!["anything".into()],
        user: None,
        context: Default::default(),
    };
    assert!(evaluate(&rule, &call));
}

#[test]
fn test_composed_conditions_and_utc_window_control_a_rule() {
    let yaml = r#"
version: 1
rules:
  - action: deny
    condition:
      all:
        - any:
            - args_match: ".*--delete.*"
            - path_pattern: "/etc/*"
        - not:
            path_pattern: "/etc/allowed/*"
        - time_window:
            start: "2026-08-11T12:00:00Z"
            end: "2026-08-11T13:00:00Z"
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    let now = Utc.with_ymd_and_hms(2026, 8, 11, 12, 30, 0).unwrap();
    let call = PolicyCall {
        args: vec!["--delete".into(), "/tmp/data".into()],
        ..Default::default()
    };

    assert_eq!(engine.resolve_call_at(&call, now).action, Action::Deny);
}

#[test]
fn test_time_window_end_is_exclusive() {
    let yaml = r#"
version: 1
rules:
  - action: deny
    condition:
      time_window:
        start: "2026-08-11T12:00:00Z"
        end: "2026-08-11T13:00:00Z"
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    let call = PolicyCall::default();
    let end = Utc.with_ymd_and_hms(2026, 8, 11, 13, 0, 0).unwrap();

    assert_eq!(engine.resolve_call_at(&call, end).action, Action::Allow);
}

#[test]
fn test_boolean_and_time_window_policy_errors_are_stable() {
    for condition in [
        "all: []\n      args_match: foo",
        "not: null",
        "time_window:\n        start: \"2026-08-11T12:00:00+01:00\"\n        end: \"2026-08-11T13:00:00Z\"",
    ] {
        let yaml = format!(
            "version: 1\nrules:\n  - action: deny\n    condition:\n      {condition}\n"
        );
        let error = PolicyParser::parse(&yaml).expect_err("condition must be rejected");
        assert_eq!(error.code(), "invalid_condition");
    }
}

#[test]
fn test_empty_boolean_operators_have_deterministic_truth_values() {
    let allow_empty_all = r#"
version: 1
rules:
  - action: deny
    condition:
      all: []
"#;
    let reject_empty_any = r#"
version: 1
rules:
  - action: deny
    condition:
      any: []
"#;
    let call = PolicyCall::default();

    assert_eq!(
        PolicyParser::parse(allow_empty_all)
            .expect("empty all is valid")
            .resolve_call(&call)
            .action,
        Action::Deny
    );
    assert_eq!(
        PolicyParser::parse(reject_empty_any)
            .expect("empty any is valid")
            .resolve_call(&call)
            .action,
        Action::Allow
    );
}

#[test]
fn test_condition_depth_and_node_limits_are_rejected() {
    let mut nested = "args_match: foo".to_owned();
    for _ in 0..32 {
        nested = format!("all:\n  - {}", nested.replace('\n', "\n    "));
    }
    let deep_policy = format!(
        "version: 1\nrules:\n  - action: deny\n    condition:\n      {}\n",
        nested.replace('\n', "\n      ")
    );
    let many_children = (0..128)
        .map(|_| "        - args_match: foo")
        .collect::<Vec<_>>()
        .join("\n");
    let wide_policy = format!(
        "version: 1\nrules:\n  - action: deny\n    condition:\n      all:\n{many_children}\n"
    );

    for policy in [deep_policy, wide_policy] {
        let error = PolicyParser::parse(&policy).expect_err("condition limit must be enforced");
        assert_eq!(error.code(), "invalid_condition");
    }
}
