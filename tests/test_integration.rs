//! Full end-to-end integration tests mirroring the Python integration suite.
use hp_guard::models::PolicyCall;
use hp_guard::parser::PolicyParser;
use hp_guard::Action;

const POLICY: &str = r#"
version: 1
global:
  default_action: allow

agents:
  research-bot:
    tools:
      curl:
        rules:
          - action: deny
            condition:
              args_match: ".*--delete.*"
      write_file:
        rules:
          - action: deny
            condition:
              path_pattern: "/etc/*"
"#;

#[test]
fn test_research_bot_curl_delete_denied() {
    let engine = PolicyParser::parse(POLICY).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("research-bot".into()),
        tool: Some("curl".into()),
        args: vec!["--delete".into(), "http://x.com".into()],
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Deny);
}

#[test]
fn test_research_bot_curl_get_allowed() {
    let engine = PolicyParser::parse(POLICY).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("research-bot".into()),
        tool: Some("curl".into()),
        args: vec!["--get".into(), "http://x.com".into()],
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Allow);
}

#[test]
fn test_research_bot_write_file_etc_denied() {
    let engine = PolicyParser::parse(POLICY).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("research-bot".into()),
        tool: Some("write_file".into()),
        args: vec!["/etc/passwd".into()],
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Deny);
}

#[test]
fn test_unknown_agent_defaults_to_allow() {
    let engine = PolicyParser::parse(POLICY).expect("policy is valid");
    let call = PolicyCall {
        agent: Some("unknown-agent".into()),
        tool: Some("anything".into()),
        args: Default::default(),
        user: None,
        context: Default::default(),
    };
    let decision = engine.resolve_call(&call);
    assert_eq!(decision.action, Action::Allow);
}
