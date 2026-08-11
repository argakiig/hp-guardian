import hp_guard

from hp_guard import (
    Action,
    AdapterError,
    AuditError,
    AuditEntry,
    AuditLog,
    AuditLogger,
    AuditedPolicyStore,
    EffectRequest,
    EnforcementRequest,
    EnforcementResponse,
    InlineEnforcementAdapter,
    Authorization,
    Decision,
    Engine,
    OutcomeStatus,
    PolicyCall,
    PolicyError,
    PolicyParser,
    PolicySnapshot,
    Rule,
    SimulationPolicy,
    SimulationReport,
    TraceError,
    simulate_trace,
)


def test_package_root_declares_and_exports_its_public_api():
    expected_exports = {
        "Action": Action,
        "AdapterError": AdapterError,
        "AuditError": AuditError,
        "AuditEntry": AuditEntry,
        "AuditLog": AuditLog,
        "AuditLogger": AuditLogger,
        "AuditedPolicyStore": AuditedPolicyStore,
        "EffectRequest": EffectRequest,
        "EnforcementRequest": EnforcementRequest,
        "EnforcementResponse": EnforcementResponse,
        "InlineEnforcementAdapter": InlineEnforcementAdapter,
        "Authorization": Authorization,
        "Decision": Decision,
        "Engine": Engine,
        "OutcomeStatus": OutcomeStatus,
        "PolicyCall": PolicyCall,
        "PolicyError": PolicyError,
        "PolicyParser": PolicyParser,
        "PolicySnapshot": PolicySnapshot,
        "Rule": Rule,
        "SimulationPolicy": SimulationPolicy,
        "SimulationReport": SimulationReport,
        "TraceError": TraceError,
        "simulate_trace": simulate_trace,
    }

    assert set(hp_guard.__all__) == set(expected_exports)
    for name, exported in expected_exports.items():
        assert getattr(hp_guard, name) is exported
