use hp_guard::models::PolicyCall;
use hp_guard::parser::PolicyParser;
use hp_guard::Action;

#[test]
fn test_parse_throttle_action() {
    let yaml = r#"
version: 1
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
version: 1
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
version: 1
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
version: 1
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
version: 1
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
version: 1
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
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: denyy
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}

#[test]
fn test_invalid_args_match_regex_is_rejected_at_parse_time() {
    let yaml = r#"
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: "["
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}

#[test]
fn test_unknown_condition_is_rejected_at_parse_time() {
    let yaml = r#"
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              unsupported: value
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}

#[test]
fn test_rule_target_user_limits_the_enclosing_tool_rule() {
    let yaml = r#"
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: deny
            target:
              user: admin
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");

    let admin_call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        user: Some("admin".into()),
        ..Default::default()
    };
    let guest_call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        user: Some("guest".into()),
        ..Default::default()
    };

    assert_eq!(engine.resolve_call(&admin_call).action, Action::Deny);
    assert_eq!(engine.resolve_call(&guest_call).action, Action::Allow);
}

#[test]
fn test_rule_target_context_limits_the_enclosing_tool_rule() {
    let yaml = r#"
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: deny
            target:
              context:
                phase: prompt
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");

    let prompt_call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        context: [("phase".into(), "prompt".into())].into(),
        ..Default::default()
    };
    let execution_call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        context: [("phase".into(), "execution".into())].into(),
        ..Default::default()
    };

    assert_eq!(engine.resolve_call(&prompt_call).action, Action::Deny);
    assert_eq!(engine.resolve_call(&execution_call).action, Action::Allow);
}

#[test]
fn test_global_deny_cannot_be_overridden_by_specific_allow() {
    let yaml = r#"
version: 1
rules:
  - action: deny
agents:
  bot:
    tools:
      curl:
        rules:
          - action: allow
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        ..Default::default()
    };

    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Deny);
    assert_eq!(decision.matched_rules, vec![0, 1]);
}

#[test]
fn test_unknown_global_field_is_rejected_instead_of_falling_back_to_allow() {
    let yaml = r#"
version: 1
global:
  default_actoin: deny
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}

#[test]
fn test_unknown_top_level_field_is_rejected() {
    let yaml = r#"
version: 1
agants:
  bot: {}
"#;

    assert!(PolicyParser::parse(yaml).is_err());
}

#[test]
fn test_missing_version_is_rejected_with_a_stable_error_code() {
    let yaml = r#"
global:
  default_action: deny
"#;

    let error = PolicyParser::parse(yaml).expect_err("version is required");
    assert_eq!(error.code(), "unsupported_version");
}

#[test]
fn test_unsupported_version_is_rejected_with_a_stable_error_code() {
    let yaml = r#"
version: 2
"#;

    let error = PolicyParser::parse(yaml).expect_err("only version 1 is supported");
    assert_eq!(error.code(), "unsupported_version");
}

#[test]
fn test_portability_excluded_args_match_regex_is_rejected() {
    let yaml = r#"
version: 1
rules:
  - action: deny
    condition:
      args_match: "(?=delete)delete"
"#;

    let error = PolicyParser::parse(yaml).expect_err("look-around is not portable in v1");
    assert_eq!(error.code(), "invalid_regex");
}

#[test]
fn test_numeric_args_match_backreference_is_rejected() {
    let yaml = r#"
version: 1
rules:
  - action: deny
    condition:
      args_match: "(delete)\\1"
"#;

    let error = PolicyParser::parse(yaml).expect_err("backreferences are not portable in v1");
    assert_eq!(error.code(), "invalid_regex");
}

#[test]
fn test_escaped_grouping_syntax_is_rejected_outside_the_v1_pattern_language() {
    let yaml = r#"
version: 1
rules:
  - action: deny
    condition:
      args_match: '\(\?='
"#;

    let error = PolicyParser::parse(yaml).expect_err("grouping syntax is not supported in v1");
    assert_eq!(error.code(), "invalid_regex");
}

#[test]
fn test_duplicate_rule_ids_are_rejected() {
    let yaml = r#"
version: 1
rules:
  - id: block-delete
    action: deny
  - id: block-delete
    action: allow
"#;

    let error = PolicyParser::parse(yaml).expect_err("rule identifiers must be unique");
    assert_eq!(error.code(), "invalid_field");
}

#[test]
fn test_rule_indices_follow_the_document_declaration_order() {
    let yaml = r#"
version: 1
agents:
  bot:
    tools:
      curl:
        rules:
          - action: log
            target:
              user: admin
rules:
  - action: log
    target:
      agent: bot
      tool: curl
"#;
    let engine = PolicyParser::parse(yaml).expect("policy is valid");

    assert_eq!(
        engine.rules[0].target.get("user").map(String::as_str),
        Some("admin")
    );
    assert_eq!(
        engine.rules[1].target.get("agent").map(String::as_str),
        Some("bot")
    );
}
