use hp_guard::conditions::evaluate;
use hp_guard::models::{Action, PolicyCall, Rule};

#[test]
fn test_args_match_regex() {
    let mut cond = std::collections::BTreeMap::<String, String>::new();
    cond.insert("args_match".into(), ".*--delete.*".into());
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: cond,
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
    let mut cond = std::collections::BTreeMap::<String, String>::new();
    cond.insert("args_match".into(), ".*--delete.*".into());
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: cond,
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
    let mut cond = std::collections::BTreeMap::<String, String>::new();
    cond.insert("args_match".into(), ".*--delete.*".into());
    let rule = Rule {
        action: Action::Deny,
        target: Default::default(),
        condition: cond,
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
