use hp_guard::{AuditError, AuditLog, AuditLogConfig, AuditedPolicyStore};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

const POLICY: &str = "version: 1\n";

fn fixture() -> Value {
    serde_json::from_str(
        &fs::read_to_string("conformance/cases/durable_log_recovery_v1.json").expect("fixture"),
    )
    .expect("valid fixture")
}

fn root(name: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "hp-guard-recovery-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("directory");
    path
}

fn path(root: &Path, name: &str, transaction: Option<&str>) -> PathBuf {
    let active = root.join("audit.jsonl");
    if name == "active" {
        return active;
    }
    if let Some(index) = name.strip_prefix("backup_") {
        return root.join(format!("audit.jsonl.{index}"));
    }
    let transaction = transaction.unwrap_or("orphan");
    if name == "stage_active" {
        return root.join(format!("audit.jsonl.rotation.{transaction}.active"));
    }
    root.join(format!(
        "audit.jsonl.rotation.{transaction}.backup.{}",
        name.strip_prefix("stage_backup_").expect("stage backup")
    ))
}

fn bytes(value: &Value) -> Vec<u8> {
    if let Some(text) = value.get("utf8").and_then(Value::as_str) {
        return text.as_bytes().to_vec();
    }
    let hex = value["hex"].as_str().expect("hex");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex byte"))
        .collect()
}

fn setup(root: &Path, case: &Value) -> BTreeMap<PathBuf, Vec<u8>> {
    let transaction = case
        .get("manifest")
        .and_then(|m| m.get("transaction_id"))
        .and_then(Value::as_str);
    let mut before = BTreeMap::new();
    for (name, entry) in case["files"].as_object().unwrap_or(&serde_json::Map::new()) {
        let destination = path(root, name, transaction);
        let content = bytes(entry);
        fs::write(&destination, &content).expect("write state");
        before.insert(destination, content);
    }
    if let Some(manifest) = case.get("manifest") {
        let destination = root.join("audit.jsonl.rotation.json");
        let content = serde_json::to_vec(manifest).expect("manifest");
        fs::write(&destination, &content).expect("write manifest");
        before.insert(destination, content);
    }
    before
}

fn trigger(root: &Path) -> Result<(), AuditError> {
    let log = AuditLog::new(root.join("audit.jsonl"), AuditLogConfig::default())?;
    AuditedPolicyStore::with_policy(POLICY, log).map(|_| ())
}

#[test]
fn tail_recovery_matches_shared_fixture() {
    for case in fixture()["tail_recovery"].as_array().expect("tail cases") {
        let directory = root(case["name"].as_str().unwrap());
        let before = setup(&directory, case);
        let expected = &case["expect"];
        match expected["error"].as_str() {
            Some(code) => {
                let error = trigger(&directory).expect_err("must fail");
                assert_eq!(error.to_string(), code);
                assert_eq!(
                    before
                        .keys()
                        .map(|p| (p.clone(), fs::read(p).unwrap()))
                        .collect::<BTreeMap<_, _>>(),
                    before
                );
            }
            None => {
                trigger(&directory).expect("recover");
                if let Some(prefix) = expected.get("active_prefix").and_then(Value::as_str) {
                    assert!(fs::read(directory.join("audit.jsonl"))
                        .unwrap()
                        .starts_with(prefix.as_bytes()));
                }
                for (name, prefix) in expected
                    .get("backup_prefixes")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                {
                    assert_eq!(
                        fs::read(path(&directory, name, None)).unwrap(),
                        prefix.as_str().unwrap().as_bytes()
                    );
                }
            }
        }
    }
}

#[test]
fn rotation_recovery_matches_shared_fixture() {
    for case in fixture()["rotation_recovery"]
        .as_array()
        .expect("rotation cases")
    {
        let directory = root(case["name"].as_str().unwrap());
        let before = setup(&directory, case);
        let expected = &case["expect"];
        match expected["error"].as_str() {
            Some(code) => {
                let error = trigger(&directory).expect_err("must fail");
                assert_eq!(error.to_string(), code);
                assert_eq!(
                    before
                        .keys()
                        .map(|p| (p.clone(), fs::read(p).unwrap()))
                        .collect::<BTreeMap<_, _>>(),
                    before
                );
            }
            None => {
                trigger(&directory).expect("recover");
                assert!(!directory.join("audit.jsonl.rotation.json").exists());
                for (name, content) in expected["backups"].as_object().unwrap() {
                    assert_eq!(
                        fs::read(path(&directory, name, None)).unwrap(),
                        content.as_str().unwrap().as_bytes()
                    );
                }
            }
        }
    }
}

#[test]
fn second_store_cannot_acquire_the_audit_lease() {
    let directory = root("lease");
    let path = directory.join("audit.jsonl");
    let first = AuditLog::new(&path, AuditLogConfig::default()).expect("log");
    let _store = AuditedPolicyStore::with_policy(POLICY, first).expect("first store");
    let second = AuditLog::new(&path, AuditLogConfig::default()).expect("log");
    assert!(matches!(
        AuditedPolicyStore::with_policy(POLICY, second),
        Err(AuditError::LockUnavailable)
    ));
}
