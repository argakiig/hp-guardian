use crate::models::{Action, Decision, PolicyCall, PolicyError, RateLimit};
use crate::{Engine, PolicyParser};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Stable error emitted when a required state operation cannot be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateError;

impl StateError {
    pub const fn code(self) -> &'static str {
        "state_unavailable"
    }
}

impl Display for StateError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl Error for StateError {}

/// Stable identity for one policy rule and normalized call subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RateLimitKey {
    pub policy_digest: String,
    pub rule_index: usize,
    pub agent: Option<String>,
    pub user: Option<String>,
    pub tool: Option<String>,
}

/// Atomically consume a single fixed-window quota slot.
pub trait RateLimitStore: Send + Sync {
    fn check_and_consume(
        &self,
        key: &RateLimitKey,
        limit: RateLimit,
        now_seconds: u64,
    ) -> Result<bool, StateError>;
}

#[derive(Default)]
struct StateInner {
    last_now: Option<u64>,
    buckets: BTreeMap<RateLimitKey, (u64, u64)>,
}

/// A process-local, locked fixed-window quota store.
pub struct InMemoryRateLimitStore {
    inner: Mutex<StateInner>,
    max_keys: usize,
}

impl InMemoryRateLimitStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(max_keys: usize) -> Result<Self, StateError> {
        if max_keys == 0 {
            return Err(StateError);
        }
        Ok(Self {
            inner: Mutex::new(StateInner::default()),
            max_keys,
        })
    }
}

impl Default for InMemoryRateLimitStore {
    fn default() -> Self {
        Self {
            inner: Mutex::new(StateInner::default()),
            max_keys: 10_000,
        }
    }
}

impl RateLimitStore for InMemoryRateLimitStore {
    fn check_and_consume(
        &self,
        key: &RateLimitKey,
        limit: RateLimit,
        now_seconds: u64,
    ) -> Result<bool, StateError> {
        let mut inner = self.inner.lock().map_err(|_| StateError)?;
        if inner
            .last_now
            .is_some_and(|last_now| now_seconds < last_now)
        {
            return Err(StateError);
        }
        inner.last_now = Some(now_seconds);
        if !inner.buckets.contains_key(key) && inner.buckets.len() >= self.max_keys {
            return Err(StateError);
        }
        let window_start = now_seconds - now_seconds % limit.window_seconds;
        let (previous_start, mut count) =
            inner.buckets.get(key).copied().unwrap_or((window_start, 0));
        if previous_start != window_start {
            count = 0;
        }
        if count >= limit.max_calls {
            inner.buckets.insert(key.clone(), (window_start, count));
            return Ok(false);
        }
        inner.buckets.insert(key.clone(), (window_start, count + 1));
        Ok(true)
    }
}

/// Explicit stateful resolver for v2 policy rate limits.
pub struct RateLimitedPolicyStore {
    engine: Engine,
    policy_digest: String,
    state_store: Arc<dyn RateLimitStore>,
    now_monotonic_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
}

impl RateLimitedPolicyStore {
    pub fn with_policy(
        policy_text: &str,
        state_store: Arc<dyn RateLimitStore>,
    ) -> Result<Self, PolicyError> {
        let started = Instant::now();
        Self::with_clock(
            policy_text,
            state_store,
            Arc::new(move || started.elapsed().as_secs()),
        )
    }

    pub fn with_clock(
        policy_text: &str,
        state_store: Arc<dyn RateLimitStore>,
        now_monotonic_seconds: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Result<Self, PolicyError> {
        let engine = PolicyParser::parse_rate_limited(policy_text)?;
        Ok(Self {
            engine,
            policy_digest: format!("{:x}", Sha256::digest(policy_text.as_bytes())),
            state_store,
            now_monotonic_seconds,
        })
    }

    pub fn resolve(&self, call: &PolicyCall) -> Result<Decision, StateError> {
        let (decision, selected_rule) = self
            .engine
            .resolve_call_with_selected_rule_at(call, Utc::now());
        let Some(rule_index) = selected_rule else {
            return Ok(decision);
        };
        if decision.action != Action::Allow {
            return Ok(decision);
        }
        let Some(limit) = self.engine.rate_limits.get(&rule_index).copied() else {
            return Ok(decision);
        };
        let key = RateLimitKey {
            policy_digest: self.policy_digest.clone(),
            rule_index,
            agent: call.agent.clone(),
            user: call.user.clone(),
            tool: call.tool.clone(),
        };
        if self
            .state_store
            .check_and_consume(&key, limit, (self.now_monotonic_seconds)())?
        {
            Ok(decision)
        } else {
            Ok(Decision {
                action: Action::Throttle,
                matched_rules: decision.matched_rules,
            })
        }
    }
}
