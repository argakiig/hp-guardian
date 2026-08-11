use chrono::{Duration as ChronoDuration, Utc};
use hp_guard::{
    Action, AuditError, AuditLog, AuditLogConfig, AuditedPolicyStore, OutcomeStatus, PolicyCall,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const POLICY: &str = "version: 1\nrules:\n  - action: deny\n    target:\n      tool: delete_file\n";

fn audit_path(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let directory = std::env::temp_dir().join(format!(
        "hp-guard-audit-{name}-{}-{sequence}",
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

fn call() -> PolicyCall {
    PolicyCall {
        agent: Some("maintenance-bot".into()),
        tool: Some("delete_file".into()),
        user: Some("operator".into()),
        args: vec!["/private/secret.txt".into()],
        context: [("access_token".into(), "not-for-audit".into())].into(),
    }
}

#[test]
fn activation_creates_an_exact_text_sha256_snapshot() {
    let path = audit_path("snapshot");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");

    let snapshot = store.active_snapshot().expect("active snapshot");
    assert_eq!(snapshot.version, 1);
    assert_eq!(
        snapshot.digest,
        "cf777f91bb9a1f35e2fe65513ed1c0556477d0c5d7167845eebc368eb1fe9bc9"
    );

    let record = records(&path).pop().expect("activation record");
    assert_eq!(record["event"], "activation");
    assert_eq!(record["policy_digest"], snapshot.digest);
    assert!(record.get("outcome_status").is_none());
    assert!(record.get("outcome_detail").is_none());
}

#[test]
fn authorization_is_persisted_without_raw_call_data_before_returning_decision() {
    let path = audit_path("authorization");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");

    let authorization = store.authorize(&call()).expect("authorized decision");

    assert_eq!(authorization.decision.action, Action::Deny);
    assert!(authorization.correlation_id.starts_with("auth-"));
    let records = records(&path);
    let record = records.last().expect("authorization record");
    assert_eq!(record["event"], "authorization");
    assert_eq!(record["correlation_id"], authorization.correlation_id);
    assert_eq!(record["agent"], "maintenance-bot");
    assert_eq!(record["tool"], "delete_file");
    assert_eq!(record["user"], "operator");
    assert_eq!(record["decision"], "deny");
    assert_eq!(record["matched_rules"], serde_json::json!([0]));
    assert!(record.get("args").is_none());
    assert!(record.get("context").is_none());
    assert!(record.get("outcome_status").is_none());
    assert!(record.get("outcome_detail").is_none());
    assert!(!record.to_string().contains("secret.txt"));
    assert!(!record.to_string().contains("access_token"));
}

#[test]
fn separate_stores_never_reuse_an_authorization_correlation_id() {
    let path = audit_path("unique-correlation");
    let first_log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut first_store =
        AuditedPolicyStore::with_policy(POLICY, first_log).expect("activate policy");
    let first = first_store.authorize(&call()).expect("first authorization");

    let second_log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut second_store =
        AuditedPolicyStore::with_policy(POLICY, second_log).expect("reactivate policy");
    let second = second_store
        .authorize(&call())
        .expect("second authorization");

    assert_ne!(first.correlation_id, second.correlation_id);
}

#[test]
fn outcome_uses_the_authorization_correlation_and_has_bounded_detail() {
    let path = audit_path("outcome");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    let authorization = store.authorize(&call()).expect("authorize");

    store
        .record_outcome(&authorization, OutcomeStatus::Failed, Some("tool exited 1"))
        .expect("record outcome");

    let audit_records = records(&path);
    let record = audit_records.last().expect("outcome record");
    assert_eq!(record["event"], "outcome");
    assert_eq!(record["correlation_id"], authorization.correlation_id);
    assert_eq!(record["outcome_status"], "failed");
    assert_eq!(record["outcome_detail"], "tool exited 1");
    assert!(record.get("args").is_none());
    assert!(record.get("context").is_none());

    let too_large_detail = "x".repeat(1025);
    assert!(matches!(
        store.record_outcome(
            &authorization,
            OutcomeStatus::Succeeded,
            Some(&too_large_detail),
        ),
        Err(AuditError::OutcomeDetailTooLong { .. })
    ));

    store
        .record_outcome(&authorization, OutcomeStatus::Succeeded, None)
        .expect("record outcome without detail");
    assert!(records(&path)
        .last()
        .expect("outcome record")
        .get("outcome_detail")
        .is_some());
    assert!(records(&path).last().expect("outcome record")["outcome_detail"].is_null());
}

#[test]
fn audit_log_rejects_invalid_rotation_configuration() {
    let path = audit_path("invalid-config");
    for config in [
        AuditLogConfig {
            max_bytes: Some(0),
            ..AuditLogConfig::default()
        },
        AuditLogConfig {
            max_age: Some(ChronoDuration::zero()),
            ..AuditLogConfig::default()
        },
        AuditLogConfig {
            max_rotated_files: 0,
            ..AuditLogConfig::default()
        },
    ] {
        assert!(matches!(
            AuditLog::new(&path, config),
            Err(AuditError::InvalidConfiguration { .. })
        ));
    }
}

#[test]
fn audit_log_rejects_a_directory_at_the_configured_file_path() {
    let path = audit_path("directory-path");
    fs::create_dir(&path).expect("create audit directory");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");

    assert!(matches!(
        AuditedPolicyStore::with_policy(POLICY, log),
        Err(AuditError::Io(_))
    ));
}

#[test]
fn audit_log_rejects_a_non_regular_rotated_entry() {
    let path = audit_path("rotation-directory");
    let log = AuditLog::new(
        &path,
        AuditLogConfig {
            max_bytes: Some(1),
            max_age: None,
            max_rotated_files: 2,
        },
    )
    .expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    fs::create_dir(path.with_extension("jsonl.1")).expect("create rotated directory");

    assert!(matches!(store.authorize(&call()), Err(AuditError::Io(_))));
    assert!(path.with_extension("jsonl.1").is_dir());
}

#[cfg(unix)]
#[test]
fn audit_log_rejects_symlinks_and_creates_owner_only_files() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let path = audit_path("symlink");
    let target = path.with_file_name("target.jsonl");
    fs::write(&target, "unchanged\n").expect("create target");
    symlink(&target, &path).expect("create audit symlink");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    assert!(matches!(
        AuditedPolicyStore::with_policy(POLICY, log),
        Err(AuditError::Io(_))
    ));
    assert_eq!(
        fs::read_to_string(&target).expect("read target"),
        "unchanged\n"
    );

    let mode_path = audit_path("owner-mode");
    let log = AuditLog::new(&mode_path, AuditLogConfig::default()).expect("valid audit config");
    AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    assert_eq!(
        fs::metadata(mode_path)
            .expect("audit metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}

#[test]
fn invalid_or_unwritable_reload_keeps_the_previous_snapshot_active() {
    let path = audit_path("reload");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    let original_digest = store.active_snapshot().expect("snapshot").digest.clone();

    assert!(matches!(
        store.reload("version: 2\n"),
        Err(AuditError::Policy(_))
    ));
    assert_eq!(
        store
            .active_snapshot()
            .expect("prior snapshot remains")
            .digest,
        original_digest
    );

    fs::remove_file(&path).expect("remove active log");
    fs::remove_dir(path.parent().expect("parent")).expect("remove log directory");
    assert!(matches!(store.reload(POLICY), Err(AuditError::Io(_))));
    assert_eq!(
        store
            .active_snapshot()
            .expect("prior snapshot remains")
            .digest,
        original_digest
    );
}

#[test]
fn required_authorization_write_failure_returns_no_decision() {
    let path = audit_path("write-failure");
    let log = AuditLog::new(&path, AuditLogConfig::default()).expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");

    fs::remove_file(&path).expect("remove active log");
    fs::remove_dir(path.parent().expect("parent")).expect("remove log directory");
    assert!(matches!(store.authorize(&call()), Err(AuditError::Io(_))));
}

#[test]
fn audit_log_rotates_before_size_limit_and_at_maximum_age() {
    let path = audit_path("rotation");
    let config = AuditLogConfig {
        max_bytes: Some(1),
        max_age: None,
        max_rotated_files: 2,
    };
    let log = AuditLog::new(&path, config).expect("valid audit config");
    let mut store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    store
        .authorize(&call())
        .expect("rotate before authorization");
    assert!(path.with_extension("jsonl.1").exists());

    let age_path = audit_path("age-rotation");
    let log = AuditLog::with_clock(
        &age_path,
        AuditLogConfig {
            max_bytes: None,
            max_age: Some(ChronoDuration::hours(1)),
            max_rotated_files: 2,
        },
        Arc::new(|| Utc::now() + ChronoDuration::hours(2)),
    )
    .expect("valid audit config");
    let mut age_store = AuditedPolicyStore::with_policy(POLICY, log).expect("activate policy");
    age_store.authorize(&call()).expect("rotate by age");
    assert!(age_path.exists());
    assert!(!age_path.with_extension("jsonl.1").exists());
}
