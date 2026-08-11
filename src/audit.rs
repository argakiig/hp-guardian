use crate::models::{Action, Decision, PolicyCall, PolicyError};
use crate::{Engine, PolicyParser};
use chrono::{DateTime, Duration, Utc};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

static CORRELATION_NONCE: AtomicU64 = AtomicU64::new(1);

/// A validated policy and the identity of its exact source text.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub version: i64,
    pub digest: String,
    pub engine: Engine,
}

impl PolicySnapshot {
    fn parse(policy_text: &str) -> Result<Self, AuditError> {
        let engine = PolicyParser::parse(policy_text).map_err(AuditError::Policy)?;
        let digest = format!("{:x}", Sha256::digest(policy_text.as_bytes()));

        // PolicyParser currently accepts only v1. Version dispatch remains its
        // responsibility; the snapshot records the accepted language version.
        Ok(Self {
            version: 1,
            digest,
            engine,
        })
    }
}

/// Bounded terminal states that an executor may report after authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeStatus {
    Succeeded,
    Failed,
    TimedOut,
}

const MAX_OUTCOME_DETAIL_BYTES: usize = 1024;

/// Configuration for bounded, host-local audit-file rotation.
#[derive(Debug, Clone)]
pub struct AuditLogConfig {
    pub max_bytes: Option<u64>,
    pub max_age: Option<Duration>,
    pub max_rotated_files: usize,
}

impl Default for AuditLogConfig {
    fn default() -> Self {
        Self {
            max_bytes: None,
            max_age: None,
            max_rotated_files: 5,
        }
    }
}

/// Errors which prevent durable audit evidence or safe policy enforcement.
#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
    Serialization(serde_json::Error),
    Policy(PolicyError),
    NoActivePolicy,
    InvalidConfiguration {
        field: &'static str,
    },
    OutcomeDetailTooLong {
        max_bytes: usize,
        actual_bytes: usize,
    },
}

impl Display for AuditError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "audit storage error: {error}"),
            Self::Serialization(error) => write!(formatter, "audit serialization error: {error}"),
            Self::Policy(error) => write!(formatter, "policy validation error: {error}"),
            Self::NoActivePolicy => write!(formatter, "no active policy snapshot"),
            Self::InvalidConfiguration { field } => {
                write!(formatter, "invalid audit rotation configuration: {field}")
            }
            Self::OutcomeDetailTooLong {
                max_bytes,
                actual_bytes,
            } => write!(
                formatter,
                "outcome detail is {actual_bytes} bytes; maximum is {max_bytes} bytes"
            ),
        }
    }
}

impl Error for AuditError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Serialization(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::NoActivePolicy
            | Self::InvalidConfiguration { .. }
            | Self::OutcomeDetailTooLong { .. } => None,
        }
    }
}

/// Append-only JSON Lines audit storage for a trusted host.
pub struct AuditLog {
    path: PathBuf,
    config: AuditLogConfig,
    now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>, config: AuditLogConfig) -> Result<Self, AuditError> {
        Self::with_clock(path, config, Arc::new(Utc::now))
    }

    /// Allows deterministic rotation tests without changing production time.
    pub fn with_clock(
        path: impl Into<PathBuf>,
        config: AuditLogConfig,
        now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    ) -> Result<Self, AuditError> {
        validate_config(&config)?;
        Ok(Self {
            path: path.into(),
            config,
            now,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        let mut encoded = serde_json::to_vec(record).map_err(AuditError::Serialization)?;
        encoded.push(b'\n');
        self.prune_expired_backups()?;
        self.rotate_before_append(encoded.len() as u64)?;

        let mut file = open_append(&self.path).map_err(AuditError::Io)?;
        set_owner_only_permissions(&file).map_err(AuditError::Io)?;
        file.write_all(&encoded).map_err(AuditError::Io)?;
        file.sync_data().map_err(AuditError::Io)
    }

    fn rotate_before_append(&self, next_record_bytes: u64) -> Result<(), AuditError> {
        validate_regular_or_absent(&self.path).map_err(AuditError::Io)?;
        let Ok(metadata) = fs::metadata(&self.path) else {
            return Ok(());
        };
        let non_empty = metadata.len() > 0;
        let size_exceeded = self
            .config
            .max_bytes
            .is_some_and(|limit| metadata.len().saturating_add(next_record_bytes) > limit);
        let age_exceeded = self.config.max_age.is_some_and(|limit| {
            metadata
                .modified()
                .ok()
                .map(|modified| {
                    let modified: DateTime<Utc> = modified.into();
                    (self.now)().signed_duration_since(modified) >= limit
                })
                .unwrap_or(false)
        });

        if non_empty && (size_exceeded || age_exceeded) {
            self.rotate_current()?;
            self.prune_expired_backups()?;
        }
        Ok(())
    }

    fn prune_expired_backups(&self) -> Result<(), AuditError> {
        let Some(max_age) = self.config.max_age else {
            return Ok(());
        };
        for index in 1..=self.config.max_rotated_files {
            let backup = self.backup_path(index);
            validate_regular_or_absent(&backup).map_err(AuditError::Io)?;
            let Ok(metadata) = fs::metadata(&backup) else {
                continue;
            };
            let expired = metadata
                .modified()
                .ok()
                .map(|modified| {
                    let modified: DateTime<Utc> = modified.into();
                    (self.now)().signed_duration_since(modified) >= max_age
                })
                .unwrap_or(false);
            if expired {
                fs::remove_file(backup).map_err(AuditError::Io)?;
            }
        }
        Ok(())
    }

    fn rotate_current(&self) -> Result<(), AuditError> {
        validate_regular_or_absent(&self.path).map_err(AuditError::Io)?;
        for index in 1..=self.config.max_rotated_files {
            validate_regular_or_absent(&self.backup_path(index)).map_err(AuditError::Io)?;
        }

        let oldest = self.backup_path(self.config.max_rotated_files);
        if oldest.exists() {
            fs::remove_file(&oldest).map_err(AuditError::Io)?;
        }
        for index in (1..self.config.max_rotated_files).rev() {
            let source = self.backup_path(index);
            if source.exists() {
                fs::rename(source, self.backup_path(index + 1)).map_err(AuditError::Io)?;
            }
        }
        fs::rename(&self.path, self.backup_path(1)).map_err(AuditError::Io)
    }

    fn backup_path(&self, index: usize) -> PathBuf {
        PathBuf::from(format!("{}.{}", self.path.display(), index))
    }
}

fn validate_config(config: &AuditLogConfig) -> Result<(), AuditError> {
    if config.max_bytes == Some(0) {
        return Err(AuditError::InvalidConfiguration { field: "max_bytes" });
    }
    if config.max_age.is_some_and(|age| age <= Duration::zero()) {
        return Err(AuditError::InvalidConfiguration { field: "max_age" });
    }
    if config.max_rotated_files == 0 {
        return Err(AuditError::InvalidConfiguration {
            field: "max_rotated_files",
        });
    }
    Ok(())
}

#[cfg(unix)]
fn open_append(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    validate_regular_or_absent(path)?;
    OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_append(path: &Path) -> std::io::Result<File> {
    validate_regular_or_absent(path)?;
    OpenOptions::new().create(true).append(true).open(path)
}

fn validate_regular_or_absent(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing symlinked audit path: {}", path.display()),
        )),
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("refusing non-regular audit path: {}", path.display()),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_file: &File) -> std::io::Result<()> {
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditEvent {
    Activation,
    Authorization,
    Outcome,
}

#[derive(Serialize)]
struct AuditRecord {
    timestamp: DateTime<Utc>,
    event: AuditEvent,
    correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    caller_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    deadline_unix_ms: Option<u64>,
    policy_version: i64,
    policy_digest: String,
    agent: Option<String>,
    tool: Option<String>,
    user: Option<String>,
    decision: Option<Action>,
    matched_rules: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_status: Option<OutcomeStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    outcome_detail: Option<Option<String>>,
}

impl AuditRecord {
    fn activation(snapshot: &PolicySnapshot, timestamp: DateTime<Utc>) -> Self {
        Self {
            timestamp,
            event: AuditEvent::Activation,
            correlation_id: None,
            caller_id: None,
            deadline_unix_ms: None,
            policy_version: snapshot.version,
            policy_digest: snapshot.digest.clone(),
            agent: None,
            tool: None,
            user: None,
            decision: None,
            matched_rules: Vec::new(),
            outcome_status: None,
            outcome_detail: None,
        }
    }

    fn authorization(
        snapshot: &PolicySnapshot,
        correlation_id: String,
        caller_id: Option<String>,
        deadline_unix_ms: Option<u64>,
        call: &PolicyCall,
        decision: &Decision,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            timestamp,
            event: AuditEvent::Authorization,
            correlation_id: Some(correlation_id),
            caller_id,
            deadline_unix_ms,
            policy_version: snapshot.version,
            policy_digest: snapshot.digest.clone(),
            agent: call.agent.clone(),
            tool: call.tool.clone(),
            user: call.user.clone(),
            decision: Some(decision.action),
            matched_rules: decision.matched_rules.clone(),
            outcome_status: None,
            outcome_detail: None,
        }
    }

    fn outcome(
        authorization: &Authorization,
        status: OutcomeStatus,
        detail: Option<String>,
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            timestamp,
            event: AuditEvent::Outcome,
            correlation_id: Some(authorization.correlation_id.clone()),
            caller_id: authorization.caller_id.clone(),
            deadline_unix_ms: authorization.deadline_unix_ms,
            policy_version: authorization.snapshot.version,
            policy_digest: authorization.snapshot.digest.clone(),
            agent: authorization.agent.clone(),
            tool: authorization.tool.clone(),
            user: authorization.user.clone(),
            decision: Some(authorization.decision.action),
            matched_rules: authorization.decision.matched_rules.clone(),
            outcome_status: Some(status),
            outcome_detail: Some(detail),
        }
    }
}

/// A decision which is safe for a future tool adapter to act on only after it
/// has been returned successfully.
#[derive(Debug, Clone)]
pub struct Authorization {
    pub correlation_id: String,
    pub snapshot: PolicySnapshot,
    pub decision: Decision,
    pub agent: Option<String>,
    pub tool: Option<String>,
    pub user: Option<String>,
    caller_id: Option<String>,
    deadline_unix_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct AuthorizationMetadata {
    pub correlation_id: String,
    pub caller_id: String,
    pub deadline_unix_ms: u64,
}

/// Owns the active policy snapshot and its mandatory audit boundary.
pub struct AuditedPolicyStore {
    audit_log: AuditLog,
    active_snapshot: Option<PolicySnapshot>,
}

impl AuditedPolicyStore {
    pub fn new(audit_log: AuditLog) -> Self {
        Self {
            audit_log,
            active_snapshot: None,
        }
    }

    pub fn with_policy(policy_text: &str, audit_log: AuditLog) -> Result<Self, AuditError> {
        let mut store = Self::new(audit_log);
        store.reload(policy_text)?;
        Ok(store)
    }

    pub fn active_snapshot(&self) -> Option<&PolicySnapshot> {
        self.active_snapshot.as_ref()
    }

    /// Validates and audits activation before atomically replacing the snapshot.
    pub fn reload(&mut self, policy_text: &str) -> Result<(), AuditError> {
        let candidate = PolicySnapshot::parse(policy_text)?;
        let record = AuditRecord::activation(&candidate, (self.audit_log.now)());
        self.audit_log.append(&record)?;
        self.active_snapshot = Some(candidate);
        Ok(())
    }

    /// Resolves and durably records authorization before returning a decision.
    pub fn authorize(&mut self, call: &PolicyCall) -> Result<Authorization, AuditError> {
        self.authorize_with_metadata(call, None)
    }

    pub(crate) fn authorize_with_metadata(
        &mut self,
        call: &PolicyCall,
        metadata: Option<AuthorizationMetadata>,
    ) -> Result<Authorization, AuditError> {
        let snapshot = self
            .active_snapshot
            .as_ref()
            .ok_or(AuditError::NoActivePolicy)?;
        let decision = snapshot.engine.resolve_call(call);
        let correlation_id = metadata
            .as_ref()
            .map(|metadata| metadata.correlation_id.clone())
            .unwrap_or_else(next_correlation_id);
        let record = AuditRecord::authorization(
            snapshot,
            correlation_id.clone(),
            metadata.as_ref().map(|metadata| metadata.caller_id.clone()),
            metadata.as_ref().map(|metadata| metadata.deadline_unix_ms),
            call,
            &decision,
            (self.audit_log.now)(),
        );
        self.audit_log.append(&record)?;

        Ok(Authorization {
            correlation_id,
            snapshot: snapshot.clone(),
            decision,
            agent: call.agent.clone(),
            tool: call.tool.clone(),
            user: call.user.clone(),
            caller_id: metadata.as_ref().map(|metadata| metadata.caller_id.clone()),
            deadline_unix_ms: metadata.as_ref().map(|metadata| metadata.deadline_unix_ms),
        })
    }

    /// Records a bounded executor result correlated to a prior authorization.
    pub fn record_outcome(
        &mut self,
        authorization: &Authorization,
        status: OutcomeStatus,
        detail: Option<&str>,
    ) -> Result<(), AuditError> {
        let detail = detail.map(str::to_owned);
        if let Some(detail) = &detail {
            if detail.len() > MAX_OUTCOME_DETAIL_BYTES {
                return Err(AuditError::OutcomeDetailTooLong {
                    max_bytes: MAX_OUTCOME_DETAIL_BYTES,
                    actual_bytes: detail.len(),
                });
            }
        }
        let record = AuditRecord::outcome(authorization, status, detail, (self.audit_log.now)());
        self.audit_log.append(&record)
    }
}

fn next_correlation_id() -> String {
    let timestamp_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let nonce = CORRELATION_NONCE.fetch_add(1, Ordering::Relaxed);
    format!("auth-{}-{timestamp_nanos}-{nonce}", std::process::id())
}
