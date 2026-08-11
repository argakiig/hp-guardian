use hp_guard::{
    AdapterError, AuditLog, AuditLogConfig, AuditedPolicyStore, EnforcementRequest,
    InlineEnforcementAdapter,
};
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn fixture() -> Value {
    serde_json::from_str(
        &fs::read_to_string("conformance/cases/inline_adapter_v1.json").expect("read fixture"),
    )
    .expect("valid fixture")
}

fn audit_path(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "hp-guard-adapter-{name}-{}-{sequence}",
        std::process::id()
    ));
    fs::create_dir_all(&directory).expect("create test directory");
    directory.join("audit.jsonl")
}

fn records(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .expect("read audit log")
        .lines()
        .map(|line| serde_json::from_str(line).expect("valid JSON Line"))
        .collect()
}

fn adapter(policy: &str, path: &Path) -> InlineEnforcementAdapter {
    let log = AuditLog::new(path, AuditLogConfig::default()).expect("valid audit log");
    let store = AuditedPolicyStore::with_policy(policy, log).expect("activate policy");
    InlineEnforcementAdapter::with_clock(store, Arc::new(|| 1000))
}

#[test]
fn serializes_shared_fixture_responses_and_only_allows_effects() {
    let fixture = fixture();
    let path = audit_path("fixture");
    let mut adapter = adapter(fixture["policy"].as_str().expect("policy"), &path);

    let actual = fixture["requests"]
        .as_array()
        .expect("requests")
        .iter()
        .map(|value| {
            let request = EnforcementRequest::from_value(value).expect("valid request");
            serde_json::to_value(adapter.authorize(request).expect("authorized response"))
                .expect("serialize response")
        })
        .collect::<Vec<_>>();

    assert_eq!(
        actual,
        fixture["responses"].as_array().expect("responses").to_vec()
    );
    let audit_records = records(&path);
    assert_eq!(audit_records.len(), 4);
    for record in &audit_records[1..] {
        assert_eq!(record["event"], "authorization");
        assert_eq!(record["caller_id"], "host-a");
        assert_eq!(record["deadline_unix_ms"], 1001);
        assert!(record.get("args").is_none());
        assert!(record.get("context").is_none());
        assert!(!record.to_string().contains("/tmp/x"));
    }
}

#[test]
fn adapter_audit_matches_the_returned_policy_identity_and_decision() {
    let fixture = fixture();
    let path = audit_path("response-audit-identity");
    let mut adapter = adapter(fixture["policy"].as_str().expect("policy"), &path);
    let request = EnforcementRequest::from_value(&fixture["requests"][0]).expect("request");

    let response = adapter.authorize(request).expect("authorized response");

    let audit_records = records(&path);
    let record = audit_records.last().expect("authorization record");
    assert_eq!(record["event"], "authorization");
    assert_eq!(record["correlation_id"], response.correlation_id);
    assert_eq!(record["policy_version"], response.policy.version);
    assert_eq!(record["policy_digest"], response.policy.sha256);
    assert_eq!(record["decision"], serde_json::json!(response.decision));
    assert_eq!(
        record["matched_rules"],
        serde_json::json!(response.matched_rules)
    );
}

#[test]
fn rejects_expired_and_invalid_requests_before_writing_authorization() {
    let fixture = fixture();
    let path = audit_path("validation");
    let mut adapter = adapter(fixture["policy"].as_str().expect("policy"), &path);

    for case in fixture["error_cases"].as_array().expect("error cases") {
        let request = EnforcementRequest::from_value(&case["request"]);
        let error = match request {
            Ok(request) => adapter.authorize(request).expect_err("request must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code(), case["error"].as_str().expect("error code"));
    }
    assert_eq!(records(&path).len(), 1, "only activation is persisted");
}

#[test]
fn reused_correlation_ids_are_audited_as_separate_attempts() {
    let fixture = fixture();
    let path = audit_path("reused-correlation");
    let mut adapter = adapter(fixture["policy"].as_str().expect("policy"), &path);
    let mut request = EnforcementRequest::from_value(&fixture["requests"][0]).expect("request");
    request.correlation_id = "retry-1".into();

    let first = adapter.authorize(request.clone()).expect("first response");
    let second = adapter.authorize(request).expect("second response");
    assert_eq!(first.correlation_id, "retry-1");
    assert_eq!(second.correlation_id, "retry-1");
    let audit_records = records(&path);
    assert_eq!(audit_records.len(), 3);
    assert_eq!(audit_records[1]["correlation_id"], "retry-1");
    assert_eq!(audit_records[2]["correlation_id"], "retry-1");
}

#[test]
fn closes_when_the_required_audit_write_fails() {
    let fixture = fixture();
    let path = audit_path("audit-failure");
    let mut adapter = adapter(fixture["policy"].as_str().expect("policy"), &path);
    fs::remove_file(&path).expect("remove audit log");
    fs::remove_dir(path.parent().expect("audit parent")).expect("remove audit directory");
    let request = EnforcementRequest::from_value(&fixture["requests"][0]).expect("request");

    assert!(matches!(
        adapter.authorize(request),
        Err(AdapterError::AuditWriteFailed)
    ));
}

#[test]
fn validates_identifier_lengths_and_complete_json_shape() {
    let fixture = fixture();
    let mut invalid = fixture["requests"][0].clone();
    invalid["caller_id"] = json!("x".repeat(257));
    assert!(matches!(
        EnforcementRequest::from_value(&invalid),
        Err(AdapterError::InvalidRequest)
    ));

    invalid = fixture["requests"][0].clone();
    invalid["extra"] = json!(true);
    assert!(matches!(
        EnforcementRequest::from_value(&invalid),
        Err(AdapterError::InvalidRequest)
    ));

    invalid = fixture["requests"][0].clone();
    invalid["call"]["context"] = json!({"attempt": 1});
    assert!(matches!(
        EnforcementRequest::from_value(&invalid),
        Err(AdapterError::InvalidRequest)
    ));
}
