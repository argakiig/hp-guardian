from __future__ import annotations
from datetime import datetime, timezone
from .models import AuditEntry, PolicyCall
from .engine import Decision


class AuditLogger:
    def log(self, call: PolicyCall, decision: Decision) -> AuditEntry:
        return AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            agent=call.agent,
            tool=call.tool,
            args=list(call.args),
            decision=decision.action,
            matched_rules=list(decision.matched_rules),
        )
