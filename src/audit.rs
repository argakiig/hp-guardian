use crate::models::{Action, Decision, PolicyCall, PolicyError};
use crate::{Engine, PolicyParser};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
        let digest = crate::util::to_hex(&Sha256::digest(policy_text.as_bytes()));

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
    LockUnavailable,
    Corrupt,
    RecoveryFailed,
    RecoveryUnsupported,
    Closed,
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
            Self::LockUnavailable => formatter.write_str("audit_lock_unavailable"),
            Self::Corrupt => formatter.write_str("audit_corrupt"),
            Self::RecoveryFailed => formatter.write_str("audit_recovery_failed"),
            Self::RecoveryUnsupported => formatter.write_str("audit_recovery_unsupported"),
            Self::Closed => formatter.write_str("audit_closed"),
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
            | Self::OutcomeDetailTooLong { .. }
            | Self::LockUnavailable
            | Self::Corrupt
            | Self::RecoveryFailed
            | Self::RecoveryUnsupported
            | Self::Closed => None,
        }
    }
}

/// Append-only JSON Lines audit storage for a trusted host.
pub struct AuditLog {
    path: PathBuf,
    config: AuditLogConfig,
    now: Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    lease: Mutex<Option<File>>,
    recovery_complete: AtomicBool,
    closed: AtomicBool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RotationManifest {
    format_version: u8,
    transaction_id: String,
    max_rotated_files: usize,
    operation: String,
    phase: String,
    present: RotationPresent,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RotationPresent {
    active: bool,
    backups: Vec<usize>,
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
            lease: Mutex::new(None),
            recovery_complete: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn append(&self, record: &AuditRecord) -> Result<(), AuditError> {
        self.ensure_ready()?;
        let mut encoded = serde_json::to_vec(record).map_err(AuditError::Serialization)?;
        encoded.push(b'\n');
        self.prune_expired_backups()?;
        self.rotate_before_append(encoded.len() as u64)?;

        let mut file = open_append(&self.path).map_err(AuditError::Io)?;
        set_owner_only_permissions(&file).map_err(AuditError::Io)?;
        file.write_all(&encoded).map_err(AuditError::Io)?;
        file.sync_data().map_err(AuditError::Io)?;
        sync_parent(&self.path).map_err(AuditError::Io)
    }

    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        if let Ok(mut lease) = self.lease.lock() {
            *lease = None;
        }
    }

    fn ensure_ready(&self) -> Result<(), AuditError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(AuditError::Closed);
        }
        let mut lease = self.lease.lock().map_err(|_| AuditError::RecoveryFailed)?;
        if lease.is_none() {
            *lease = Some(acquire_lease(&self.path)?);
        }
        drop(lease);
        if !self.recovery_complete.swap(true, Ordering::AcqRel) {
            if let Err(error) = self.recover_tails() {
                self.recovery_complete.store(false, Ordering::Release);
                return Err(error);
            }
        }
        Ok(())
    }

    fn recover_tails(&self) -> Result<(), AuditError> {
        let manifest = PathBuf::from(format!("{}.rotation.json", self.path.display()));
        validate_regular_or_absent(&manifest).map_err(AuditError::Io)?;
        if manifest.exists() {
            self.recover_manifest(&manifest)?;
        }
        if self
            .path
            .parent()
            .unwrap_or(Path::new("."))
            .read_dir()
            .map_err(AuditError::Io)?
            .any(|entry| {
                entry.ok().is_some_and(|entry| {
                    entry.file_name().to_string_lossy().starts_with(&format!(
                        "{}.rotation.",
                        self.path.file_name().unwrap().to_string_lossy()
                    ))
                })
            })
        {
            return Err(AuditError::RecoveryFailed);
        }
        let mut paths = vec![self.path.clone()];
        for index in 1..=self.config.max_rotated_files {
            paths.push(self.backup_path(index));
        }
        for path in paths {
            validate_regular_or_absent(&path).map_err(AuditError::Io)?;
            if path.exists() {
                recover_tail(&path)?;
            }
        }
        Ok(())
    }

    fn recover_manifest(&self, manifest_path: &Path) -> Result<(), AuditError> {
        let manifest: RotationManifest = serde_json::from_slice(&read_regular(manifest_path)?)
            .map_err(|_| AuditError::RecoveryFailed)?;
        if manifest.format_version != 1
            || manifest.operation != "rotate"
            || !matches!(manifest.phase.as_str(), "staging" | "installing")
            || !manifest.present.active
            || manifest.max_rotated_files == 0
            || !manifest
                .transaction_id
                .replace('-', "")
                .chars()
                .all(|c| c.is_ascii_alphanumeric())
            || manifest
                .present
                .backups
                .iter()
                .any(|index| *index == 0 || *index > manifest.max_rotated_files)
        {
            return Err(AuditError::RecoveryFailed);
        }
        let mut backups = manifest.present.backups.clone();
        backups.sort_unstable();
        backups.dedup();
        if backups != manifest.present.backups {
            return Err(AuditError::RecoveryFailed);
        }

        if manifest.phase == "staging" {
            self.stage_slot(&manifest.transaction_id, "active", true)?;
            for index in 1..=manifest.max_rotated_files {
                self.stage_slot(
                    &manifest.transaction_id,
                    &format!("backup_{index}"),
                    backups.contains(&index),
                )?;
            }
            let mut installing = manifest.clone();
            installing.phase = "installing".into();
            self.write_manifest(manifest_path, &installing)?;
        }
        for index in 1..=manifest.max_rotated_files {
            let source = if index == 1 {
                "active".to_string()
            } else {
                format!("backup_{}", index - 1)
            };
            let expected = source == "active" || backups.contains(&source[7..].parse().unwrap());
            self.install_slot(&manifest.transaction_id, &source, index, expected)?;
        }
        let oldest = self.staging_path(
            &manifest.transaction_id,
            &format!("backup_{}", manifest.max_rotated_files),
        );
        if regular_exists(&oldest)? {
            fs::remove_file(oldest).map_err(AuditError::Io)?;
            sync_parent(&self.path).map_err(AuditError::Io)?;
        }
        fs::remove_file(manifest_path).map_err(AuditError::Io)?;
        sync_parent(&self.path).map_err(AuditError::Io)
    }

    fn stage_slot(&self, transaction: &str, slot: &str, expected: bool) -> Result<(), AuditError> {
        let source = if slot == "active" {
            self.path.clone()
        } else {
            self.backup_path(slot[7..].parse().unwrap())
        };
        let stage = self.staging_path(transaction, slot);
        let source_exists = regular_exists(&source)?;
        let stage_exists = regular_exists(&stage)?;
        if !expected {
            return if source_exists || stage_exists {
                Err(AuditError::RecoveryFailed)
            } else {
                Ok(())
            };
        }
        if source_exists && stage_exists {
            return Err(AuditError::RecoveryFailed);
        }
        if source_exists {
            fs::rename(source, stage).map_err(AuditError::Io)?;
            sync_parent(&self.path).map_err(AuditError::Io)
        } else if stage_exists {
            Ok(())
        } else {
            Err(AuditError::RecoveryFailed)
        }
    }

    fn install_slot(
        &self,
        transaction: &str,
        source: &str,
        target_index: usize,
        expected: bool,
    ) -> Result<(), AuditError> {
        let stage = self.staging_path(transaction, source);
        let target = self.backup_path(target_index);
        let stage_exists = regular_exists(&stage)?;
        let target_exists = regular_exists(&target)?;
        if !expected {
            return if stage_exists || target_exists {
                Err(AuditError::RecoveryFailed)
            } else {
                Ok(())
            };
        }
        if stage_exists && target_exists {
            return Err(AuditError::RecoveryFailed);
        }
        if stage_exists {
            fs::rename(stage, target).map_err(AuditError::Io)?;
            sync_parent(&self.path).map_err(AuditError::Io)
        } else if target_exists {
            Ok(())
        } else {
            Err(AuditError::RecoveryFailed)
        }
    }

    fn staging_path(&self, transaction: &str, slot: &str) -> PathBuf {
        let suffix = if slot == "active" {
            "active".into()
        } else {
            format!("backup.{}", &slot[7..])
        };
        PathBuf::from(format!(
            "{}.rotation.{transaction}.{suffix}",
            self.path.display()
        ))
    }

    fn write_manifest(&self, path: &Path, manifest: &RotationManifest) -> Result<(), AuditError> {
        let temporary = PathBuf::from(format!(
            "{}.tmp.{}",
            path.display(),
            manifest.transaction_id
        ));
        if regular_exists(&temporary)? {
            return Err(AuditError::RecoveryFailed);
        }
        let mut file = create_new_nofollow(&temporary).map_err(AuditError::Io)?;
        sync_parent(&self.path).map_err(AuditError::Io)?;
        file.write_all(&serde_json::to_vec(manifest).map_err(AuditError::Serialization)?)
            .map_err(AuditError::Io)?;
        file.sync_all().map_err(AuditError::Io)?;
        fs::rename(temporary, path).map_err(AuditError::Io)?;
        sync_parent(&self.path).map_err(AuditError::Io)
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
                sync_parent(&self.path).map_err(AuditError::Io)?;
            }
        }
        Ok(())
    }

    fn rotate_current(&self) -> Result<(), AuditError> {
        let manifest_path = PathBuf::from(format!("{}.rotation.json", self.path.display()));
        let manifest = RotationManifest {
            format_version: 1,
            transaction_id: format!(
                "{:x}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ),
            max_rotated_files: self.config.max_rotated_files,
            operation: "rotate".into(),
            phase: "staging".into(),
            present: RotationPresent {
                active: true,
                backups: (1..=self.config.max_rotated_files)
                    .map(|index| Ok((index, regular_exists(&self.backup_path(index))?)))
                    .collect::<Result<Vec<_>, AuditError>>()?
                    .into_iter()
                    .filter_map(|(index, exists)| exists.then_some(index))
                    .collect(),
            },
        };
        self.write_manifest(&manifest_path, &manifest)?;
        self.recover_manifest(&manifest_path)
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
fn acquire_lease(path: &Path) -> Result<File, AuditError> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;

    let parent = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(AuditError::Io)?;
    let lock_path = PathBuf::from(format!("{}.lock", path.display()));
    validate_regular_or_absent(&lock_path).map_err(AuditError::Io)?;
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&lock_path)
        .map_err(AuditError::Io)?;
    set_owner_only_permissions(&file).map_err(AuditError::Io)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let error = std::io::Error::last_os_error();
        return if error.kind() == std::io::ErrorKind::WouldBlock {
            Err(AuditError::LockUnavailable)
        } else {
            Err(AuditError::Io(error))
        };
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)?;
    Ok(file)
}

#[cfg(not(unix))]
fn acquire_lease(_path: &Path) -> Result<File, AuditError> {
    Err(AuditError::RecoveryUnsupported)
}

fn recover_tail(path: &Path) -> Result<(), AuditError> {
    validate_regular_or_absent(path).map_err(AuditError::Io)?;
    let mut content = Vec::new();
    let mut read_file = open_read_nofollow(path).map_err(AuditError::Io)?;
    read_file
        .read_to_end(&mut content)
        .map_err(AuditError::Io)?;
    let last_newline = content.iter().rposition(|byte| *byte == b'\n');
    let complete_end = last_newline.map_or(0, |index| index + 1);
    let records = if complete_end == 0 {
        &[]
    } else {
        &content[..complete_end - 1]
    };
    for line in records.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            return Err(AuditError::Corrupt);
        }
        let value: serde_json::Value =
            serde_json::from_slice(line).map_err(|_| AuditError::Corrupt)?;
        if !value.is_object() {
            return Err(AuditError::Corrupt);
        }
    }
    let tail = &content[complete_end..];
    if tail.is_empty() {
        return Ok(());
    }
    let tail_text = std::str::from_utf8(tail).map_err(|_| AuditError::Corrupt)?;
    if serde_json::from_str::<serde_json::Value>(tail_text).is_ok() {
        return Err(AuditError::Corrupt);
    }
    let file = open_write_nofollow(path).map_err(AuditError::Io)?;
    file.set_len(complete_end as u64).map_err(AuditError::Io)?;
    file.sync_all().map_err(AuditError::Io)?;
    File::open(path.parent().unwrap_or(Path::new(".")))
        .and_then(|directory| directory.sync_all())
        .map_err(AuditError::Io)
}

fn read_regular(path: &Path) -> Result<Vec<u8>, AuditError> {
    validate_regular_or_absent(path).map_err(AuditError::Io)?;
    let mut bytes = Vec::new();
    open_read_nofollow(path)
        .map_err(AuditError::Io)?
        .read_to_end(&mut bytes)
        .map_err(AuditError::Io)?;
    Ok(bytes)
}

#[cfg(unix)]
fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(unix)]
fn open_write_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_read_nofollow(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(not(unix))]
fn open_write_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).open(path)
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

#[cfg(unix)]
fn create_new_nofollow(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_new_nofollow(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().create_new(true).write(true).open(path)
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

fn regular_exists(path: &Path) -> Result<bool, AuditError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(AuditError::RecoveryFailed),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(AuditError::Io(error)),
    }
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()
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

    pub fn close(&self) {
        self.audit_log.close();
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
