use crate::audit::AuthorizationMetadata;
use crate::models::{Action, PolicyCall};
use crate::simulator::PolicyIdentity;
use crate::AuditedPolicyStore;
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_IDENTIFIER_BYTES: usize = 256;

/// A complete, normalized request crossing the inline enforcement boundary.
#[derive(Debug, Clone)]
pub struct EnforcementRequest {
    pub caller_id: String,
    pub correlation_id: String,
    pub deadline_unix_ms: u64,
    pub call: PolicyCall,
}

impl EnforcementRequest {
    /// Parses a strict JSON-compatible request for hosts that receive request data dynamically.
    pub fn from_value(value: &Value) -> Result<Self, AdapterError> {
        let fields = value.as_object().ok_or(AdapterError::InvalidRequest)?;
        require_exact_fields(
            fields,
            &["caller_id", "correlation_id", "deadline_unix_ms", "call"],
        )?;
        let request = Self {
            caller_id: required_identifier(fields, "caller_id")?,
            correlation_id: required_identifier(fields, "correlation_id")?,
            deadline_unix_ms: fields
                .get("deadline_unix_ms")
                .and_then(Value::as_u64)
                .ok_or(AdapterError::InvalidRequest)?,
            call: parse_call(fields.get("call").expect("required call"))?,
        };
        request.validate()?;
        Ok(request)
    }

    fn validate(&self) -> Result<(), AdapterError> {
        valid_identifier(&self.caller_id)
            .then_some(())
            .ok_or(AdapterError::InvalidRequest)?;
        valid_identifier(&self.correlation_id)
            .then_some(())
            .ok_or(AdapterError::InvalidRequest)
    }
}

/// A stable failure from the enforcement boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterError {
    InvalidRequest,
    DeadlineExceeded,
    AuditWriteFailed,
}

impl AdapterError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::AuditWriteFailed => "audit_write_failed",
        }
    }
}

impl Display for AdapterError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for AdapterError {}

/// The normalized call data returned only for an allowed policy decision.
#[derive(Debug, Clone, Serialize)]
pub struct EffectCall {
    pub agent: Option<String>,
    pub tool: Option<String>,
    pub args: Vec<String>,
    pub user: Option<String>,
    pub context: BTreeMap<String, String>,
}

impl From<&PolicyCall> for EffectCall {
    fn from(call: &PolicyCall) -> Self {
        Self {
            agent: call.agent.clone(),
            tool: call.tool.clone(),
            args: call.args.clone(),
            user: call.user.clone(),
            context: call.context.clone(),
        }
    }
}

/// Data the host may execute after a successful authorization; this type has no executor path.
#[derive(Debug, Clone, Serialize)]
pub struct EffectRequest {
    pub caller_id: String,
    pub correlation_id: String,
    pub deadline_unix_ms: u64,
    pub policy: PolicyIdentity,
    pub decision: Action,
    pub matched_rules: Vec<usize>,
    pub call: EffectCall,
}

/// An audited policy response. `effect` is absent unless `decision` is `allow`.
#[derive(Debug, Clone, Serialize)]
pub struct EnforcementResponse {
    pub caller_id: String,
    pub correlation_id: String,
    pub deadline_unix_ms: u64,
    pub policy: PolicyIdentity,
    pub decision: Action,
    pub matched_rules: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<EffectRequest>,
}

/// Host-local enforcement boundary around an audited active policy.
pub struct InlineEnforcementAdapter {
    store: AuditedPolicyStore,
    now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl InlineEnforcementAdapter {
    pub fn new(store: AuditedPolicyStore) -> Self {
        Self::with_clock(
            store,
            Arc::new(|| {
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX)
            }),
        )
    }

    /// Supplies a deterministic clock for tests and hosts with a monotonic wall-clock source.
    pub fn with_clock(
        store: AuditedPolicyStore,
        now_unix_ms: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        Self { store, now_unix_ms }
    }

    /// Validates, audits, and returns data for the host to execute only after an allow decision.
    pub fn authorize(
        &mut self,
        request: EnforcementRequest,
    ) -> Result<EnforcementResponse, AdapterError> {
        request.validate()?;
        if request.deadline_unix_ms <= (self.now_unix_ms)() {
            return Err(AdapterError::DeadlineExceeded);
        }

        let authorization = self
            .store
            .authorize_with_metadata(
                &request.call,
                Some(AuthorizationMetadata {
                    correlation_id: request.correlation_id.clone(),
                    caller_id: request.caller_id.clone(),
                    deadline_unix_ms: request.deadline_unix_ms,
                }),
            )
            .map_err(|_| AdapterError::AuditWriteFailed)?;
        let policy = PolicyIdentity {
            version: authorization.snapshot.version,
            sha256: authorization.snapshot.digest.clone(),
        };
        let effect = (authorization.decision.action == Action::Allow).then(|| EffectRequest {
            caller_id: request.caller_id.clone(),
            correlation_id: request.correlation_id.clone(),
            deadline_unix_ms: request.deadline_unix_ms,
            policy: policy.clone(),
            decision: authorization.decision.action,
            matched_rules: authorization.decision.matched_rules.clone(),
            call: EffectCall::from(&request.call),
        });

        Ok(EnforcementResponse {
            caller_id: request.caller_id,
            correlation_id: request.correlation_id,
            deadline_unix_ms: request.deadline_unix_ms,
            policy,
            decision: authorization.decision.action,
            matched_rules: authorization.decision.matched_rules,
            effect,
        })
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_IDENTIFIER_BYTES
}

fn require_exact_fields(
    fields: &Map<String, Value>,
    required: &[&str],
) -> Result<(), AdapterError> {
    if required.iter().any(|field| !fields.contains_key(*field))
        || fields
            .keys()
            .any(|field| !required.contains(&field.as_str()))
    {
        return Err(AdapterError::InvalidRequest);
    }
    Ok(())
}

fn required_identifier(fields: &Map<String, Value>, field: &str) -> Result<String, AdapterError> {
    let value = fields
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| valid_identifier(value))
        .ok_or(AdapterError::InvalidRequest)?;
    Ok(value.to_owned())
}

fn parse_call(value: &Value) -> Result<PolicyCall, AdapterError> {
    let fields = value.as_object().ok_or(AdapterError::InvalidRequest)?;
    require_exact_fields(fields, &["agent", "tool", "args", "user", "context"])?;
    let nullable_string = |field: &str| match fields.get(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        _ => Err(AdapterError::InvalidRequest),
    };
    let args = fields
        .get("args")
        .and_then(Value::as_array)
        .and_then(|values| {
            values
                .iter()
                .map(|value| value.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or(AdapterError::InvalidRequest)?;
    let context = fields
        .get("context")
        .and_then(Value::as_object)
        .and_then(|values| {
            values
                .iter()
                .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
                .collect::<Option<BTreeMap<_, _>>>()
        })
        .ok_or(AdapterError::InvalidRequest)?;
    Ok(PolicyCall {
        agent: nullable_string("agent")?,
        tool: nullable_string("tool")?,
        args,
        user: nullable_string("user")?,
        context,
    })
}
