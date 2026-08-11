use hp_guard::logging::AuditLogger;
use hp_guard::models::Action as HpAction;
use hp_guard::models::Decision;
use hp_guard::models::PolicyCall;

#[test]
fn test_audit_log_entry_created() {
    let logger = AuditLogger;
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("curl".into()),
        args: vec!["--delete".into(), "url".into()],
        user: None,
        context: Default::default(),
    };
    let decision = Decision {
        action: HpAction::Deny,
        matched_rules: vec![0],
    };
    let entry = logger.log(&call, &decision);
    assert_eq!(entry.agent.as_deref(), Some("bot"));
    assert_eq!(entry.tool.as_deref(), Some("curl"));
    assert_eq!(entry.decision, HpAction::Deny);
    assert_eq!(entry.matched_rules, vec![0]);
    assert!(entry.timestamp.timestamp() > 0);
}

#[test]
fn test_audit_log_entry_includes_args() {
    let logger = AuditLogger;
    let call = PolicyCall {
        agent: Some("bot".into()),
        tool: Some("write_file".into()),
        args: vec!["/tmp/test.txt".into()],
        user: None,
        context: Default::default(),
    };
    let decision = Decision {
        action: HpAction::Allow,
        matched_rules: Vec::new(),
    };
    let entry = logger.log(&call, &decision);
    assert_eq!(entry.args, vec!["/tmp/test.txt"]);

    let serialized = serde_json::to_value(entry).expect("audit entry serializes");
    assert_eq!(serialized["args"], serde_json::json!(["/tmp/test.txt"]));
    assert_eq!(serialized["matched_rules"], serde_json::json!([]));
}
