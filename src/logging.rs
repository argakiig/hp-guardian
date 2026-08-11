use crate::models::{AuditEntry, Decision, PolicyCall};
use chrono::Utc;

/// Logs audit entries for policy decisions.
pub struct AuditLogger;

impl AuditLogger {
    pub fn log(&self, call: &PolicyCall, decision: &Decision) -> AuditEntry {
        AuditEntry {
            timestamp: Utc::now(),
            agent: call.agent.clone(),
            tool: call.tool.clone(),
            args: call.args.clone(),
            decision: decision.action,
            matched_rules: decision.matched_rules.clone(),
        }
    }
}
