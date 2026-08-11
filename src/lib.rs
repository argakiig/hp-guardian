pub mod adapter;
pub mod audit;
pub mod conditions;
pub mod engine;
pub mod logging;
pub mod matching;
pub mod models;
pub mod parser;
pub mod simulator;
pub mod state;

// Re-export key types for convenience.
pub use adapter::{
    AdapterError, EffectCall, EffectRequest, EnforcementRequest, EnforcementResponse,
    InlineEnforcementAdapter,
};
pub use audit::{
    AuditError, AuditLog, AuditLogConfig, AuditedPolicyStore, Authorization, OutcomeStatus,
    PolicySnapshot,
};
pub use engine::Engine;
pub use logging::AuditLogger;
pub use models::{
    Action, AuditEntry, Condition, Decision, PolicyCall, PolicyError, RateLimit, Rule, TimeWindow,
};
pub use parser::PolicyParser;
pub use simulator::{
    parse_trace, simulate_trace, ExpectedMetadata, PolicyIdentity, SimulationComparison,
    SimulationPolicy, SimulationReport, SimulationResult, TraceError, TraceEvent,
};
pub use state::{InMemoryRateLimitStore, RateLimitStore, RateLimitedPolicyStore, StateError};
