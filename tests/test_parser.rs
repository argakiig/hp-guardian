use hp_guard::models::PolicyCall;
use hp_guard::parser::PolicyParser;
use hp_guard::Action;

#[test]
fn test_parse_throttle_action() {
    let yaml = r#"
agents:
  my-agent:
    tools:
      slow_tool:
        rules:
          - action: throttle
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].action, Action::Throttle);
}

#[test]
fn test_parse_log_action() {
    let yaml = r#"
agents:
  my-agent:
    tools:
      log_tool:
        rules:
          - action: log
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].action, Action::Log);
}

#[test]
fn test_parse_require_approval_action() {
    let yaml = r#"
agents:
  my-agent:
    tools:
      approve_tool:
        rules:
          - action: require_approval
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].action, Action::RequireApproval);
}

#[test]
fn test_parse_redirect_action() {
    let yaml = r#"
agents:
  my-agent:
    tools:
      redir_tool:
        rules:
          - action: redirect
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    assert_eq!(engine.rules.len(), 1);
    assert_eq!(engine.rules[0].action, Action::Redirect);
}

#[test]
fn test_parse_rule_without_condition_defaults_empty() {
    let yaml = r#"
agents:
  bot:
    tools:
      foo:
        rules:
          - action: deny
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    assert_eq!(engine.rules[0].condition.len(), 0);
}

#[test]
fn test_global_default_deny_is_applied_to_unknown_calls() {
    let yaml = r#"
global:
  default_action: deny
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("unknown-agent".into()),
        tool: Some("unknown-tool".into()),
        ..Default::default()
    };

    assert_eq!(engine.resolve_call(&call).action, Action::Deny);
}

#[test]
fn test_unknown_action_is_rejected_at_parse_time() {
    let yaml = r#"
agents:
  bot:
    tools:
      curl:
        rules:
          - action: denyy
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}
