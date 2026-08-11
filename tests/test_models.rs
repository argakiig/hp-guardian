//! Test suite mirroring the Python hp_guard tests — models.

use hp_guard::models::{Action, Condition, PolicyCall, Rule};

#[test]
fn test_rule_has_action_and_target() {
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
    assert_eq!(rule.action, Action::Deny);
    assert_eq!(rule.target.get("agent").unwrap(), "bot");
    assert_eq!(rule.target.get("tool").unwrap(), "curl");
}

#[test]
fn test_action_enum_values() {
    assert_eq!(Action::Allow as u8, 0);
    assert_eq!(Action::Deny as u8, 1);
    assert_eq!(Action::Throttle as u8, 2);
    assert_eq!(Action::Log as u8, 3);
    assert_eq!(Action::RequireApproval as u8, 4);
    assert_eq!(Action::Redirect as u8, 5);
}

#[test]
fn test_rule_default_target_is_empty_dict() {
    let rule = Rule {
        action: Action::Allow,
        target: Default::default(),
        condition: Default::default(),
        rule_index: 0,
    };
    assert!(rule.target.is_empty());
}

#[test]
fn test_rule_has_empty_condition_by_default() {
    let rule = Rule {
        action: Action::Allow,
        target: Default::default(),
        condition: Default::default(),
        rule_index: 0,
    };
    assert!(matches!(rule.condition, Condition::Leaves { .. }));
}

#[test]
fn test_rule_has_rule_index_zero_by_default() {
    let rule = Rule {
        action: Action::Allow,
        target: Default::default(),
        condition: Default::default(),
        rule_index: 0,
    };
    assert_eq!(rule.rule_index, 0);
}

#[test]
fn test_rule_stores_condition() {
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
    assert!(matches!(
        rule.condition,
        Condition::Leaves {
            args_match: Some(ref pattern),
            ..
        } if pattern == ".*--delete.*"
    ));
}

#[test]
fn test_policy_call_fields() {
    let mut context = std::collections::BTreeMap::<String, String>::new();
    context.insert("phase".into(), "prompt".into());
    let call = PolicyCall {
        agent: Some("research-bot".into()),
        tool: Some("curl".into()),
        args: vec!["--delete".into(), "http://example.com".into()],
        user: Some("user-123".into()),
        context,
    };
    assert_eq!(call.agent.as_deref(), Some("research-bot"));
    assert_eq!(call.tool.as_deref(), Some("curl"));
    assert_eq!(call.args, vec!["--delete", "http://example.com"]);
    assert_eq!(call.user.as_deref(), Some("user-123"));
    assert_eq!(call.context.get("phase").unwrap(), "prompt");
}
