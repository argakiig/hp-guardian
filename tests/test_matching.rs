use hp_guard::matching::rule_matches_rule;
use hp_guard::models::{Action, PolicyCall, Rule};

#[test]
fn test_unspecified_target_fields_match_anything() {
    let rule = Rule {
        action: Action::Deny,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("anything".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(rule_matches_rule(&rule, &call));
}

#[test]
fn test_specific_field_must_match() {
    let rule = Rule {
        action: Action::Deny,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("other".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}

#[test]
fn test_both_agent_and_tool_must_match() {
    let rule = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(rule_matches_rule(&rule, &call));
}

#[test]
fn test_tool_mismatch_fails() {
    let rule = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("write_file".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}

#[test]
fn test_empty_target_matches_all() {
    let rule = Rule {
        action: Action::Allow,
        target: Default::default(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(rule_matches_rule(&rule, &call));
}

#[test]
fn test_user_field_matching() {
    let rule = Rule {
        action: Action::Deny,
        target: [("user".into(), "admin".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: Some("admin".into()),
        context: Default::default(),
    };
    assert!(rule_matches_rule(&rule, &call));
}

#[test]
fn test_user_mismatch() {
    let rule = Rule {
        action: Action::Deny,
        target: [("user".into(), "admin".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: Some("guest".into()),
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}

// ─── Cover missing None branches ───

#[test]
fn test_agent_none_causes_mismatch() {
    // When the rule specifies agent="bot" and call.agent is None,
    // the rule should NOT match (None != "bot").
    let rule = Rule {
        action: Action::Deny,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: None,
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}

#[test]
fn test_tool_none_causes_mismatch() {
    let rule = Rule {
        action: Action::Deny,
        target: [("tool".into(), "curl".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: None,
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}

#[test]
fn test_user_none_causes_mismatch() {
    let rule = Rule {
        action: Action::Deny,
        target: [("user".into(), "admin".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    assert!(!rule_matches_rule(&rule, &call));
}
