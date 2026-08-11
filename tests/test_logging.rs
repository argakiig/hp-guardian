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
    assert_eq!(entry.get("agent").unwrap(), "bot");
    assert_eq!(entry.get("tool").unwrap(), "curl");
    assert_eq!(entry.get("decision").unwrap(), "deny");
    assert_eq!(entry.get("matched_rules").unwrap(), "[0]");
    assert!(entry.contains_key("timestamp"));
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
    assert_eq!(entry.get("args").unwrap(), "[\"/tmp/test.txt\"]");
}
