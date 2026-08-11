from __future__ import annotations
from datetime import datetime, timezone
from .models import PolicyCall
from .engine import Decision


class AuditLogger:
    def log(self, call: PolicyCall, decision: Decision) -> dict:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent": call.agent,
            "tool": call.tool,
            "args": call.args,
            "decision": decision.action.value,
            "matched_rules": decision.matched_rules,
        }
