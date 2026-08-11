use crate::models::Decision;
use crate::models::PolicyCall;
use chrono::Utc;
use std::collections::HashMap;

/// Logs audit entries for policy decisions.
pub struct AuditLogger;

impl AuditLogger {
    pub fn log(&self, call: &PolicyCall, decision: &Decision) -> HashMap<String, String> {
        let mut entry = HashMap::new();
        entry.insert("timestamp".to_string(), Utc::now().to_rfc3339());
        entry.insert("agent".to_string(), call.agent.clone().unwrap_or_default());
        entry.insert("tool".to_string(), call.tool.clone().unwrap_or_default());
        entry.insert(
            "args".to_string(),
            serde_json::to_string(&call.args).unwrap_or_default(),
        );
        entry.insert(
            "decision".to_string(),
            format!("{:?}", decision.action).to_lowercase(),
        );
        entry.insert(
            "matched_rules".to_string(),
            serde_json::to_string(&decision.matched_rules).unwrap_or_default(),
        );
        entry
    }
}
