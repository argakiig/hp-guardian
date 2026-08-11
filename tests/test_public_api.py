import hp_guard

from hp_guard import (
    Action,
    AuditError,
    AuditEntry,
    AuditLog,
    AuditLogger,
    AuditedPolicyStore,
    Authorization,
    Decision,
    Engine,
    OutcomeStatus,
    PolicyCall,
    PolicyError,
    PolicyParser,
    PolicySnapshot,
    Rule,
)


def test_package_root_declares_and_exports_its_public_api():
    expected_exports = {
        "Action": Action,
        "AuditError": AuditError,
        "AuditEntry": AuditEntry,
        "AuditLog": AuditLog,
        "AuditLogger": AuditLogger,
        "AuditedPolicyStore": AuditedPolicyStore,
        "Authorization": Authorization,
        "Decision": Decision,
        "Engine": Engine,
        "OutcomeStatus": OutcomeStatus,
        "PolicyCall": PolicyCall,
        "PolicyError": PolicyError,
        "PolicyParser": PolicyParser,
        "PolicySnapshot": PolicySnapshot,
        "Rule": Rule,
    }

    assert set(hp_guard.__all__) == set(expected_exports)
    for name, exported in expected_exports.items():
        assert getattr(hp_guard, name) is exported
