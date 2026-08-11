import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from hp_guard.models import PolicyCall, Action
from hp_guard.engine import Decision
from hp_guard.logging import AuditLogger


def test_audit_log_entry_created():
    logger = AuditLogger()
    call = PolicyCall(agent="bot", tool="curl", args=["--delete", "url"])
    decision = Decision(action=Action.DENY, matched_rules=[0])
    entry = logger.log(call, decision)
    assert entry["agent"] == "bot"
    assert entry["tool"] == "curl"
    assert entry["decision"] == "deny"
    assert entry["matched_rules"] == [0]
    assert "timestamp" in entry


def test_audit_log_entry_includes_args():
    logger = AuditLogger()
    call = PolicyCall(agent="bot", tool="write_file", args=["/tmp/test.txt"])
    decision = Decision(action=Action.ALLOW, matched_rules=[])
    entry = logger.log(call, decision)
    assert entry["args"] == ["/tmp/test.txt"]
