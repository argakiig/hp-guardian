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
    assert entry.agent == "bot"
    assert entry.tool == "curl"
    assert entry.decision == Action.DENY
    assert entry.matched_rules == [0]
    assert entry.timestamp
    assert entry.to_dict()["decision"] == "deny"


def test_audit_log_entry_includes_args():
    logger = AuditLogger()
    call = PolicyCall(agent="bot", tool="write_file", args=["/tmp/test.txt"])
    decision = Decision(action=Action.ALLOW, matched_rules=[])
    entry = logger.log(call, decision)
    assert entry.args == ["/tmp/test.txt"]


def test_audit_entry_snapshots_mutable_call_and_decision_fields():
    logger = AuditLogger()
    call = PolicyCall(args=["/tmp/test.txt"])
    decision = Decision(action=Action.DENY, matched_rules=[3])

    entry = logger.log(call, decision)
    call.args.append("later")
    decision.matched_rules.append(4)

    assert entry.args == ["/tmp/test.txt"]
    assert entry.matched_rules == [3]
