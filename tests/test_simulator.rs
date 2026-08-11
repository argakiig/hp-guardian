use hp_guard::{simulate_trace, SimulationPolicy};
use serde_json::{json, Value};
use std::fs;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> Value {
    serde_json::from_str(
        &fs::read_to_string("conformance/cases/simulator_v1.json").expect("read fixture"),
    )
    .expect("valid fixture")
}

fn jsonl(events: &[Value]) -> String {
    events
        .iter()
        .map(|event| serde_json::to_string(event).expect("serialize event"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

fn temporary_path(name: &str) -> std::path::PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "hp-guard-simulator-{name}-{}-{sequence}",
        std::process::id()
    ))
}

#[test]
fn simulates_shared_fixture_without_exposing_call_secrets() {
    let fixture = fixture();
    let baseline = SimulationPolicy::parse(fixture["baseline_policy"].as_str().expect("policy"))
        .expect("valid baseline policy");
    let trace = jsonl(fixture["trace"].as_array().expect("trace"));

    let reports = simulate_trace(&baseline, None, &trace).expect("valid trace");
    let actual: Vec<Value> = reports
        .iter()
        .map(|report| serde_json::to_value(report).expect("serialize report"))
        .collect();

    assert_eq!(
        actual,
        fixture["single_reports"]
            .as_array()
            .expect("reports")
            .to_vec()
    );
    let output = reports
        .iter()
        .map(|report| serde_json::to_string(report).expect("serialize JSONL record"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!output.contains("/tmp/x"));
    assert!(!output.contains("\"args\""));
    assert!(!output.contains("\"context\""));
}

#[test]
fn serializes_reports_in_the_specified_key_order() {
    let fixture = fixture();
    let baseline = SimulationPolicy::parse(fixture["baseline_policy"].as_str().expect("policy"))
        .expect("valid baseline policy");
    let trace = jsonl(&fixture["trace"].as_array().expect("trace")[..1]);

    let report = simulate_trace(&baseline, None, &trace)
        .expect("valid trace")
        .pop()
        .expect("report");

    assert_eq!(
        serde_json::to_string(&report).expect("serialize report"),
        "{\"version\":1,\"sequence\":1,\"event_id\":\"remove\",\"expected\":{\"policy\":{\"version\":1,\"sha256\":\"8a9221029667d9196eefd2b364e9cb2dfe098b2356acc777c8ebae09889a2e7e\"},\"decision\":\"deny\",\"matched_rules\":[0]},\"results\":[{\"policy\":{\"version\":1,\"sha256\":\"8a9221029667d9196eefd2b364e9cb2dfe098b2356acc777c8ebae09889a2e7e\"},\"decision\":\"deny\",\"matched_rules\":[0],\"matches_expected\":true}]}"
    );
}

#[test]
fn compares_two_policies_against_the_shared_fixture() {
    let fixture = fixture();
    let baseline = SimulationPolicy::parse(fixture["baseline_policy"].as_str().expect("policy"))
        .expect("valid baseline policy");
    let candidate = SimulationPolicy::parse(fixture["candidate_policy"].as_str().expect("policy"))
        .expect("valid candidate policy");
    let trace = jsonl(fixture["trace"].as_array().expect("trace"));

    let actual: Vec<Value> = simulate_trace(&baseline, Some(&candidate), &trace)
        .expect("valid trace")
        .iter()
        .map(|report| serde_json::to_value(report).expect("serialize report"))
        .collect();

    assert_eq!(
        actual,
        fixture["comparison_reports"]
            .as_array()
            .expect("reports")
            .to_vec()
    );
}

#[test]
fn rejects_shared_invalid_traces_with_stable_codes_and_line_numbers() {
    let fixture = fixture();
    let policy = SimulationPolicy::parse(fixture["baseline_policy"].as_str().expect("policy"))
        .expect("valid policy");

    for case in fixture["invalid_cases"].as_array().expect("invalid cases") {
        let error = simulate_trace(&policy, None, case["jsonl"].as_str().expect("jsonl"))
            .expect_err(case["name"].as_str().expect("case name"));
        assert_eq!(
            error.code(),
            case["error"]["code"].as_str().expect("error code")
        );
        assert_eq!(
            error.line_number(),
            case["error"]["line"].as_u64().expect("line") as usize
        );
    }
}

#[test]
fn rejects_unknown_fields_and_wrong_optional_shapes() {
    let policy = SimulationPolicy::parse("version: 1\n").expect("valid policy");
    for (trace, expected_code) in [
        (
            "{\"version\":1,\"sequence\":1,\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{}},\"extra\":true}\n",
            "invalid_trace_record",
        ),
        (
            "{\"version\":1,\"sequence\":1,\"event_id\":\"\",\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{}}}\n",
            "invalid_trace_record",
        ),
        (
            "{\"version\":1,\"sequence\":1,\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{\"scope\":1}}}\n",
            "invalid_trace_call",
        ),
        (
            "{\"version\":1,\"sequence\":1,\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{}},\"expected\":{\"policy\":{\"version\":1,\"sha256\":\"ABC\"},\"decision\":\"allow\",\"matched_rules\":[]}}\n",
            "invalid_trace_expected",
        ),
    ] {
        let error = simulate_trace(&policy, None, trace).expect_err("invalid trace");
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.line_number(), 1);
    }
}

#[test]
fn cli_validates_every_line_before_writing_any_stdout() {
    let directory = temporary_path("cli");
    fs::create_dir_all(&directory).expect("create directory");
    let policy_path = directory.join("baseline.yaml");
    let trace_path = directory.join("calls.jsonl");
    fs::write(&policy_path, "version: 1\n").expect("write policy");
    fs::write(
        &trace_path,
        "{\"version\":1,\"sequence\":1,\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{}}}\n{\"version\":1,\"sequence\":3,\"call\":{\"agent\":null,\"tool\":null,\"args\":[],\"user\":null,\"context\":{}}}\n",
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_hp-guard-simulate"))
        .args([
            "--policy",
            policy_path.to_str().expect("path"),
            "--trace",
            trace_path.to_str().expect("path"),
        ])
        .output()
        .expect("run CLI");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("JSON stderr"),
        json!({"code": "invalid_trace_sequence", "line": 2})
    );
}

#[test]
fn cli_emits_compact_jsonl_for_a_policy_comparison() {
    let fixture = fixture();
    let directory = temporary_path("comparison-cli");
    fs::create_dir_all(&directory).expect("create directory");
    let policy_path = directory.join("baseline.yaml");
    let candidate_path = directory.join("candidate.yaml");
    let trace_path = directory.join("calls.jsonl");
    fs::write(
        &policy_path,
        fixture["baseline_policy"]
            .as_str()
            .expect("baseline policy"),
    )
    .expect("write baseline");
    fs::write(
        &candidate_path,
        fixture["candidate_policy"]
            .as_str()
            .expect("candidate policy"),
    )
    .expect("write candidate");
    fs::write(
        &trace_path,
        jsonl(fixture["trace"].as_array().expect("trace")),
    )
    .expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_hp-guard-simulate"))
        .args([
            "--policy",
            policy_path.to_str().expect("path"),
            "--trace",
            trace_path.to_str().expect("path"),
            "--compare",
            candidate_path.to_str().expect("path"),
        ])
        .output()
        .expect("run CLI");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let reports = String::from_utf8(output.stdout)
        .expect("UTF-8 output")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("JSONL report"))
        .collect::<Vec<_>>();
    assert_eq!(
        reports,
        fixture["comparison_reports"]
            .as_array()
            .expect("comparison reports")
            .to_vec()
    );
}

#[test]
fn cli_reports_policy_failures_as_json_without_stdout() {
    let directory = temporary_path("invalid-policy-cli");
    fs::create_dir_all(&directory).expect("create directory");
    let policy_path = directory.join("baseline.yaml");
    let trace_path = directory.join("calls.jsonl");
    fs::write(&policy_path, "version: 2\n").expect("write policy");
    fs::write(&trace_path, "").expect("write trace");

    let output = Command::new(env!("CARGO_BIN_EXE_hp-guard-simulate"))
        .args([
            "--policy",
            policy_path.to_str().expect("path"),
            "--trace",
            trace_path.to_str().expect("path"),
        ])
        .output()
        .expect("run CLI");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).expect("JSON stderr"),
        json!({"code": "unsupported_version", "line": null})
    );
}
