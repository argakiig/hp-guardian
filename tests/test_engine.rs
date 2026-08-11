//! Cover engine.rs deny-override branch and engine.rs branch coverage.
use hp_guard::engine::Engine;
use hp_guard::models::{PolicyCall, Rule};
use hp_guard::Action;

/// When two rules match at the same specificity, deny beats allow.
#[test]
fn test_deny_overrides_allow_at_same_specificity() {
    // Both rules have 2 target fields (same specificity)
    // deny should win over allow
    let deny_rule = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let allow_rule = Rule {
        action: Action::Allow,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 1,
    };
    let engine = Engine::new(vec![allow_rule, deny_rule]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    // deny should win because both have same specificity
    assert_eq!(decision.action, Action::Deny);
}

/// When deny is more specific, it beats allow at different specificity.
#[test]
fn test_deny_overrides_allow_different_specificity() {
    let allow_broad = Rule {
        action: Action::Allow,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let deny_specific = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 1,
    };
    let engine = Engine::new(vec![allow_broad, deny_specific]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    // most specific (deny) should win
    assert_eq!(decision.action, Action::Deny);
}

/// Multiple denys at same specificity — first one wins.
#[test]
fn test_multiple_denys_same_specificity() {
    let deny_rule_0 = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let deny_rule_1 = Rule {
        action: Action::Deny,
        target: [
            ("agent".into(), "bot".into()),
            ("tool".into(), "curl".into()),
        ]
        .into(),
        condition: Default::default(),
        rule_index: 1,
    };
    let engine = Engine::new(vec![deny_rule_0, deny_rule_1]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Deny);
    // should pick the first deny rule at highest specificity
    assert!(decision.matched_rules.contains(&0));
}

/// Throttle action test
#[test]
fn test_throttle_action() {
    let rule = Rule {
        action: Action::Throttle,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let engine = Engine::new(vec![rule]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("any_tool".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Throttle);
}

/// Log action test
#[test]
fn test_log_action() {
    let rule = Rule {
        action: Action::Log,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let engine = Engine::new(vec![rule]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("any_tool".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Log);
}

/// RequireApproval action test
#[test]
fn test_require_approval_action() {
    let rule = Rule {
        action: Action::RequireApproval,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let engine = Engine::new(vec![rule]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("any_tool".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::RequireApproval);
}

/// Redirect action test
#[test]
fn test_redirect_action() {
    let rule = Rule {
        action: Action::Redirect,
        target: [("agent".into(), "bot".into())].into(),
        condition: Default::default(),
        rule_index: 0,
    };
    let engine = Engine::new(vec![rule]);
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("any_tool".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Redirect);
}
