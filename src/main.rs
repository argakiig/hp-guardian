// ─── main.rs ───
// Simple CLI demo: run through policy engine and print results.
use hp_guard::logging::AuditLogger;
use hp_guard::models::{Action, PolicyCall};
use hp_guard::parser::PolicyParser;

fn demo_policy() -> &'static str {
    r#"
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
              args_match: "/etc/.*"
"#
}

/// Run the demo policy through the engine and return results.
pub fn run_demo() -> Vec<(Action, String)> {
    let engine = PolicyParser::parse(demo_policy()).expect("demo policy is valid");
    let logger = AuditLogger;

    let results = vec![
        // Test: DELETE blocked
        {
            let call = PolicyCall {
                agent: Some("research-bot".into()),
                tool: Some("curl".into()),
                args: vec!["--delete".into(), "http://example.com".into()],
                user: None,
                context: Default::default(),
            };
            let decision = engine.resolve_call(&call);
            let entry = logger.log(&call, &decision);
            (decision.action, entry.decision.as_str().to_owned())
        },
        // Test: GET allowed
        {
            let call = PolicyCall {
                agent: Some("research-bot".into()),
                tool: Some("curl".into()),
                args: vec!["--get".into(), "http://example.com".into()],
                user: None,
                context: Default::default(),
            };
            let decision = engine.resolve_call(&call);
            let entry = logger.log(&call, &decision);
            (decision.action, entry.decision.as_str().to_owned())
        },
    ];

    for (action, decision) in &results {
        println!("Test: action={action:?}, decision={decision}");
    }
    results
}

fn main() {
    let results = run_demo();
    println!("\nAll demo tests passed!");
    assert_eq!(results[0].0, Action::Deny);
    assert_eq!(results[1].0, Action::Allow);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_parse_policy() {
        let engine = PolicyParser::parse(demo_policy()).expect("demo policy is valid");
        assert!(!engine.rules.is_empty());
    }

    #[test]
    fn demo_delete_denied() {
        let results = run_demo();
        assert_eq!(results[0].0, Action::Deny);
        assert_eq!(results[0].1, "deny");
    }

    #[test]
    fn demo_get_allowed() {
        let results = run_demo();
        assert_eq!(results[1].0, Action::Allow);
        assert_eq!(results[1].1, "allow");
    }

    #[test]
    fn demo_etc_path_denied() {
        let engine = PolicyParser::parse(demo_policy()).expect("demo policy is valid");

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
    fn demo_unknown_agent_defaults_allow() {
        let engine = PolicyParser::parse(demo_policy()).expect("demo policy is valid");

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
}
