use crate::models::{Action, Decision, PolicyCall, PolicyError};
use crate::{Engine, PolicyParser};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};

const TRACE_VERSION: i64 = 1;

/// A validated policy and its identity for offline simulation.
#[derive(Debug, Clone)]
pub struct SimulationPolicy {
    identity: PolicyIdentity,
    engine: Engine,
}

impl SimulationPolicy {
    pub fn parse(policy_text: &str) -> Result<Self, PolicyError> {
        let engine = PolicyParser::parse(policy_text)?;
        let digest = Sha256::digest(policy_text.as_bytes());
        Ok(Self {
            identity: PolicyIdentity {
                version: TRACE_VERSION,
                sha256: crate::util::to_hex(&digest),
            },
            engine,
        })
    }

    pub fn identity(&self) -> &PolicyIdentity {
        &self.identity
    }
}

/// The policy version and exact-text SHA-256 associated with a simulation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyIdentity {
    pub version: i64,
    pub sha256: String,
}

/// A normalized trace event. This is intentionally kept separate from reports
/// so raw call arguments and context cannot be serialized by report types.
#[derive(Debug, Clone)]
pub struct TraceEvent {
    sequence: u64,
    event_id: Option<String>,
    call: PolicyCall,
    expected: Option<ExpectedMetadata>,
}

/// Historical expectation metadata carried by a trace event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExpectedMetadata {
    pub policy: PolicyIdentity,
    pub decision: Action,
    pub matched_rules: Vec<usize>,
}

/// A report record produced for one trace event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulationReport {
    pub version: i64,
    pub sequence: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<ExpectedMetadata>,
    pub results: Vec<SimulationResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comparison: Option<SimulationComparison>,
}

/// A policy decision within a simulation report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulationResult {
    pub policy: PolicyIdentity,
    pub decision: Action,
    pub matched_rules: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub matches_expected: Option<bool>,
}

/// Differences between the baseline and candidate decisions for one event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SimulationComparison {
    pub action_changed: bool,
    pub matched_rules_changed: bool,
}

/// A stable, line-addressable trace validation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceError {
    code: TraceErrorCode,
    line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraceErrorCode {
    InvalidJson,
    InvalidRecord,
    UnsupportedVersion,
    InvalidSequence,
    InvalidCall,
    InvalidExpected,
}

impl TraceError {
    fn new(code: TraceErrorCode, line: usize) -> Self {
        Self { code, line }
    }

    pub const fn code(&self) -> &'static str {
        match self.code {
            TraceErrorCode::InvalidJson => "invalid_trace_json",
            TraceErrorCode::InvalidRecord => "invalid_trace_record",
            TraceErrorCode::UnsupportedVersion => "unsupported_trace_version",
            TraceErrorCode::InvalidSequence => "invalid_trace_sequence",
            TraceErrorCode::InvalidCall => "invalid_trace_call",
            TraceErrorCode::InvalidExpected => "invalid_trace_expected",
        }
    }

    pub const fn line_number(&self) -> usize {
        self.line
    }
}

impl Display for TraceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} at trace line {}", self.code(), self.line)
    }
}

impl Error for TraceError {}

/// Parses and fully validates a JSON Lines trace before any simulation output
/// is constructed.
pub fn parse_trace(trace: &str) -> Result<Vec<TraceEvent>, TraceError> {
    let mut events = Vec::new();
    let mut expected_sequence = 1;

    for (offset, line) in trace.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let line_number = offset + 1;
        let value: Value = serde_json::from_str(line)
            .map_err(|_| TraceError::new(TraceErrorCode::InvalidJson, line_number))?;
        let event = parse_event(&value, line_number)?;
        if event.sequence != expected_sequence {
            return Err(TraceError::new(
                TraceErrorCode::InvalidSequence,
                line_number,
            ));
        }
        expected_sequence += 1;
        events.push(event);
    }

    Ok(events)
}

/// Simulates an already validated policy set against a complete JSON Lines
/// trace. The function has no execution, audit, or persistent-state path.
pub fn simulate_trace(
    baseline: &SimulationPolicy,
    candidate: Option<&SimulationPolicy>,
    trace: &str,
) -> Result<Vec<SimulationReport>, TraceError> {
    let events = parse_trace(trace)?;
    Ok(events
        .iter()
        .map(|event| simulate_event(event, baseline, candidate))
        .collect())
}

fn simulate_event(
    event: &TraceEvent,
    baseline: &SimulationPolicy,
    candidate: Option<&SimulationPolicy>,
) -> SimulationReport {
    let mut results = vec![simulate_policy(baseline, event)];
    if let Some(candidate) = candidate {
        results.push(simulate_policy(candidate, event));
    }
    let comparison = candidate.map(|_| SimulationComparison {
        action_changed: results[0].decision != results[1].decision,
        matched_rules_changed: results[0].matched_rules != results[1].matched_rules,
    });

    SimulationReport {
        version: TRACE_VERSION,
        sequence: event.sequence,
        event_id: event.event_id.clone(),
        expected: event.expected.clone(),
        results,
        comparison,
    }
}

fn simulate_policy(policy: &SimulationPolicy, event: &TraceEvent) -> SimulationResult {
    let Decision {
        action,
        matched_rules,
    } = policy.engine.resolve_call(&event.call);
    let matches_expected = event.expected.as_ref().and_then(|expected| {
        (expected.policy == policy.identity)
            .then_some(expected.decision == action && expected.matched_rules == matched_rules)
    });

    SimulationResult {
        policy: policy.identity.clone(),
        decision: action,
        matched_rules,
        matches_expected,
    }
}

fn parse_event(value: &Value, line: usize) -> Result<TraceEvent, TraceError> {
    let fields = value
        .as_object()
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidRecord, line))?;
    require_exact_fields(
        fields,
        &["version", "sequence", "call"],
        &["event_id", "expected"],
    )
    .map_err(|_| TraceError::new(TraceErrorCode::InvalidRecord, line))?;

    let version = integer(fields.get("version").expect("required version"));
    if version != Some(TRACE_VERSION) {
        return Err(TraceError::new(TraceErrorCode::UnsupportedVersion, line));
    }
    let sequence = positive_integer(fields.get("sequence").expect("required sequence"))
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidSequence, line))?;
    let event_id = match fields.get("event_id") {
        Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
        Some(_) => return Err(TraceError::new(TraceErrorCode::InvalidRecord, line)),
        None => None,
    };
    let call = parse_call(fields.get("call").expect("required call"), line)?;
    let expected = fields
        .get("expected")
        .map(|value| parse_expected(value, line))
        .transpose()?;

    Ok(TraceEvent {
        sequence,
        event_id,
        call,
        expected,
    })
}

fn parse_call(value: &Value, line: usize) -> Result<PolicyCall, TraceError> {
    let fields = value
        .as_object()
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;
    require_exact_fields(fields, &["agent", "tool", "args", "user", "context"], &[])
        .map_err(|_| TraceError::new(TraceErrorCode::InvalidCall, line))?;

    let agent = nullable_string(fields.get("agent").expect("required agent"))
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;
    let tool = nullable_string(fields.get("tool").expect("required tool"))
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;
    let user = nullable_string(fields.get("user").expect("required user"))
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;
    let args = fields
        .get("args")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;
    let context = fields
        .get("context")
        .and_then(Value::as_object)
        .and_then(|values| {
            values
                .iter()
                .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
                .collect::<Option<BTreeMap<_, _>>>()
        })
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidCall, line))?;

    Ok(PolicyCall {
        agent,
        tool,
        args,
        user,
        context,
    })
}

fn parse_expected(value: &Value, line: usize) -> Result<ExpectedMetadata, TraceError> {
    let fields = value
        .as_object()
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidExpected, line))?;
    require_exact_fields(fields, &["policy", "decision", "matched_rules"], &[])
        .map_err(|_| TraceError::new(TraceErrorCode::InvalidExpected, line))?;

    let policy = parse_identity(fields.get("policy").expect("required policy"), line)?;
    let decision = fields
        .get("decision")
        .and_then(Value::as_str)
        .and_then(parse_action)
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidExpected, line))?;
    let matched_rules = fields
        .get("matched_rules")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(positive_or_zero_integer)
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidExpected, line))?;

    Ok(ExpectedMetadata {
        policy,
        decision,
        matched_rules,
    })
}

fn parse_identity(value: &Value, line: usize) -> Result<PolicyIdentity, TraceError> {
    let fields = value
        .as_object()
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidExpected, line))?;
    require_exact_fields(fields, &["version", "sha256"], &[])
        .map_err(|_| TraceError::new(TraceErrorCode::InvalidExpected, line))?;
    let version = integer(fields.get("version").expect("required version"));
    if version != Some(TRACE_VERSION) {
        return Err(TraceError::new(TraceErrorCode::InvalidExpected, line));
    }
    let sha256 = fields
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|value| is_lowercase_sha256(value))
        .map(str::to_owned)
        .ok_or_else(|| TraceError::new(TraceErrorCode::InvalidExpected, line))?;

    Ok(PolicyIdentity {
        version: TRACE_VERSION,
        sha256,
    })
}

fn require_exact_fields(
    fields: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> Result<(), ()> {
    if required.iter().any(|field| !fields.contains_key(*field)) {
        return Err(());
    }
    if fields
        .keys()
        .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err(());
    }
    Ok(())
}

fn nullable_string(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        Value::String(value) => Some(Some(value.clone())),
        _ => None,
    }
}

fn integer(value: &Value) -> Option<i64> {
    value.as_i64()
}

fn positive_integer(value: &Value) -> Option<u64> {
    value.as_u64().filter(|value| *value > 0)
}

fn positive_or_zero_integer(value: &Value) -> Option<usize> {
    usize::try_from(value.as_u64()?).ok()
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn parse_action(value: &str) -> Option<Action> {
    match value {
        "allow" => Some(Action::Allow),
        "deny" => Some(Action::Deny),
        "throttle" => Some(Action::Throttle),
        "log" => Some(Action::Log),
        "require_approval" => Some(Action::RequireApproval),
        "redirect" => Some(Action::Redirect),
        _ => None,
    }
}
