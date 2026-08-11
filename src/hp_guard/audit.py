from __future__ import annotations

import hashlib
import json
import os
import stat
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    import fcntl
except ImportError:  # pragma: no cover - the durable-log contract is Unix-only
    fcntl = None

from .engine import Decision, Engine
from .models import PolicyCall
from .parser import PolicyParser


class AuditError(Exception):
    """A required local audit operation failed, so enforcement must stop."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class OutcomeStatus(Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


@dataclass(frozen=True)
class PolicySnapshot:
    version: int
    digest: str


@dataclass(frozen=True)
class _ActivePolicy:
    engine: Engine
    snapshot: PolicySnapshot


@dataclass(frozen=True)
class Authorization:
    correlation_id: str
    snapshot: PolicySnapshot
    decision: Decision
    agent: str | None
    tool: str | None
    user: str | None
    caller_id: str | None = None
    deadline_unix_ms: int | None = None


class AuditLog:
    """A host-local, append-only JSON Lines audit file."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_bytes: int | None = None,
        max_age: timedelta | None = None,
        max_rotated_files: int = 5,
        now: Callable[[], datetime] | None = None,
    ):
        if max_bytes is not None and max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        if max_age is not None and max_age <= timedelta(0):
            raise ValueError("max_age must be positive")
        if max_rotated_files < 1:
            raise ValueError("max_rotated_files must be at least 1")
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.max_age = max_age
        self.max_rotated_files = max_rotated_files
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()
        self._lease_descriptor: int | None = None
        self._closed = False
        self._recovery_complete = False

    def append(self, record: Mapping[str, Any]) -> None:
        payload = dict(record)
        payload.setdefault("timestamp", _format_timestamp(self._now()))
        try:
            line = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        except (TypeError, UnicodeError, ValueError) as error:
            raise AuditError("audit_write_failed", f"audit record is not JSON serializable: {error}") from error

        try:
            with self._lock:
                self._ensure_ready()
                self._prune_expired_rotated_files()
                if self._should_rotate(len(line)):
                    self._rotate()
                    self._prune_expired_rotated_files()
                self._append_line(line)
        except AuditError:
            raise
        except OSError as error:
            raise AuditError("audit_write_failed", f"unable to append audit record: {error}") from error

    def close(self) -> None:
        """Release the exclusive durable-log lease held by this instance."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            if self._lease_descriptor is not None:
                try:
                    if fcntl is not None:
                        fcntl.flock(self._lease_descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(self._lease_descriptor)
                    self._lease_descriptor = None

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _ensure_ready(self) -> None:
        if self._closed:
            raise AuditError("audit_closed", "audit log is closed")
        if self._lease_descriptor is None:
            self._acquire_lease()
        if not self._recovery_complete:
            self._recover_tails()
            self._recovery_complete = True

    def _acquire_lease(self) -> None:
        if fcntl is None or not hasattr(os, "O_NOFOLLOW"):
            raise AuditError(
                "audit_recovery_unsupported",
                "durable audit recovery requires Unix no-follow file locking",
            )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f"{self.path.name}.lock")
        self._regular_file_metadata(lock_path)
        descriptor = os.open(os.fspath(lock_path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditError("audit_write_failed", f"audit path must be a regular file: {lock_path}")
            os.fchmod(descriptor, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise AuditError("audit_lock_unavailable", "another process owns the audit log") from error
        except BaseException:
            os.close(descriptor)
            raise
        self._lease_descriptor = descriptor
        self._sync_parent()

    def _recover_tails(self) -> None:
        manifest = self.path.with_name(f"{self.path.name}.rotation.json")
        if self._regular_file_metadata(manifest) is not None:
            self._recover_manifest(manifest)
        staging = list(self.path.parent.glob(f"{self.path.name}.rotation.*"))
        if staging:
            raise AuditError("audit_recovery_failed", "unexpected audit rotation staging file")
        paths = [self.path]
        paths.extend(sorted(self.path.parent.glob(f"{self.path.name}.[0-9]*")))
        for path in paths:
            if self._regular_file_metadata(path) is not None:
                self._recover_file_tail(path)

    def _recover_file_tail(self, path: Path) -> None:
        descriptor = self._open_existing_read(path)
        try:
            content = bytearray()
            while chunk := os.read(descriptor, 64 * 1024):
                content.extend(chunk)
        finally:
            os.close(descriptor)

        last_newline = content.rfind(b"\n")
        complete = content if last_newline == len(content) - 1 else content[: last_newline + 1]
        for line in complete.splitlines():
            self._validate_json_line(line, path)
        tail = content[last_newline + 1 :]
        if not tail:
            return
        try:
            decoded = tail.decode("utf-8")
        except UnicodeDecodeError as error:
            raise AuditError("audit_corrupt", f"audit log contains invalid UTF-8: {path}") from error
        try:
            value = json.loads(decoded)
        except json.JSONDecodeError:
            self._truncate_and_sync(path, last_newline + 1)
            return
        if not isinstance(value, dict):
            raise AuditError("audit_corrupt", f"audit log contains a non-object record: {path}")
        raise AuditError("audit_corrupt", f"audit log record is missing its newline: {path}")

    def _recover_manifest(self, manifest_path: Path) -> None:
        manifest = self._read_manifest(manifest_path)
        transaction_id = manifest["transaction_id"]
        max_rotated_files = manifest["max_rotated_files"]
        present_backups = set(manifest["present"]["backups"])

        if manifest["phase"] == "staging":
            for slot in ["active", *(f"backup_{index}" for index in range(1, max_rotated_files + 1))]:
                expected = slot == "active" or int(slot.removeprefix("backup_")) in present_backups
                self._stage_rotation_slot(transaction_id, slot, expected)
            manifest["phase"] = "installing"
            self._write_manifest(manifest_path, manifest)

        for index in range(1, max_rotated_files + 1):
            source = "active" if index == 1 else f"backup_{index - 1}"
            expected = source == "active" or int(source.removeprefix("backup_")) in present_backups
            self._install_rotation_slot(transaction_id, source, f"backup_{index}", expected)

        old_backup = self._rotation_staging_path(transaction_id, f"backup_{max_rotated_files}")
        if self._regular_file_metadata(old_backup) is not None:
            old_backup.unlink()
            self._sync_parent()
        manifest_path.unlink()
        self._sync_parent()

    def _read_manifest(self, path: Path) -> dict[str, Any]:
        descriptor = self._open_existing_read(path)
        try:
            payload = bytearray()
            while chunk := os.read(descriptor, 64 * 1024):
                payload.extend(chunk)
        finally:
            os.close(descriptor)
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditError("audit_recovery_failed", "audit rotation manifest is invalid") from error
        if not isinstance(value, dict) or set(value) != {
            "format_version",
            "transaction_id",
            "max_rotated_files",
            "operation",
            "phase",
            "present",
        }:
            raise AuditError("audit_recovery_failed", "audit rotation manifest has an invalid shape")
        if (
            value["format_version"] != 1
            or not isinstance(value["transaction_id"], str)
            or not value["transaction_id"].replace("-", "").isalnum()
            or value["operation"] != "rotate"
            or value["phase"] not in {"staging", "installing"}
            or type(value["max_rotated_files"]) is not int
            or value["max_rotated_files"] < 1
            or not isinstance(value["present"], dict)
            or set(value["present"]) != {"active", "backups"}
            or value["present"]["active"] is not True
            or not isinstance(value["present"]["backups"], list)
        ):
            raise AuditError("audit_recovery_failed", "audit rotation manifest has invalid fields")
        backups = value["present"]["backups"]
        if (
            any(type(index) is not int or not 1 <= index <= value["max_rotated_files"] for index in backups)
            or backups != sorted(set(backups))
        ):
            raise AuditError("audit_recovery_failed", "audit rotation manifest has invalid backup slots")
        return value

    def _stage_rotation_slot(self, transaction_id: str, slot: str, expected: bool) -> None:
        source = self.path if slot == "active" else self._rotated_path(int(slot.removeprefix("backup_")))
        staging = self._rotation_staging_path(transaction_id, slot)
        source_exists = self._regular_file_metadata(source) is not None
        staging_exists = self._regular_file_metadata(staging) is not None
        if not expected:
            if source_exists or staging_exists:
                raise AuditError("audit_recovery_failed", "unexpected audit rotation source")
            return
        if source_exists and staging_exists:
            raise AuditError("audit_recovery_failed", "ambiguous audit rotation staging state")
        if source_exists:
            os.replace(source, staging)
            self._sync_parent()
        elif not staging_exists:
            raise AuditError("audit_recovery_failed", "audit rotation source is missing")

    def _install_rotation_slot(self, transaction_id: str, source_slot: str, target_slot: str, expected: bool) -> None:
        staging = self._rotation_staging_path(transaction_id, source_slot)
        target = self._rotated_path(int(target_slot.removeprefix("backup_")))
        staging_exists = self._regular_file_metadata(staging) is not None
        target_exists = self._regular_file_metadata(target) is not None
        if not expected:
            if staging_exists or target_exists:
                raise AuditError("audit_recovery_failed", "unexpected audit rotation target")
            return
        if staging_exists and target_exists:
            raise AuditError("audit_recovery_failed", "ambiguous audit rotation installation state")
        if staging_exists:
            os.replace(staging, target)
            self._sync_parent()
        elif not target_exists:
            raise AuditError("audit_recovery_failed", "audit rotation target is missing")

    def _rotation_staging_path(self, transaction_id: str, slot: str) -> Path:
        if slot == "active":
            suffix = "active"
        else:
            suffix = f"backup.{slot.removeprefix('backup_')}"
        return self.path.with_name(f"{self.path.name}.rotation.{transaction_id}.{suffix}")

    def _write_manifest(self, path: Path, manifest: Mapping[str, Any]) -> None:
        temporary = path.with_name(f"{path.name}.tmp.{manifest['transaction_id']}")
        if self._regular_file_metadata(temporary) is not None:
            raise AuditError("audit_recovery_failed", "unexpected audit rotation manifest temporary file")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            payload = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise OSError("unable to write audit rotation manifest")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        self._sync_parent()

    @staticmethod
    def _validate_json_line(line: bytes, path: Path) -> None:
        if not line:
            raise AuditError("audit_corrupt", f"audit log contains an empty record: {path}")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AuditError("audit_corrupt", f"audit log contains an invalid record: {path}") from error
        if not isinstance(value, dict):
            raise AuditError("audit_corrupt", f"audit log contains a non-object record: {path}")

    def _truncate_and_sync(self, path: Path, length: int) -> None:
        descriptor = self._open_existing_write(path)
        try:
            os.ftruncate(descriptor, length)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._sync_parent()

    def _open_existing_read(self, path: Path) -> int:
        self._regular_file_metadata(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditError("audit_write_failed", f"audit path must be a regular file: {path}")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _open_existing_write(self, path: Path) -> int:
        self._regular_file_metadata(path)
        descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditError("audit_write_failed", f"audit path must be a regular file: {path}")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _sync_parent(self) -> None:
        descriptor = os.open(self.path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _should_rotate(self, line_size: int) -> bool:
        metadata = self._regular_file_metadata(self.path)
        if metadata is None:
            return False
        size = metadata.st_size
        if self.max_bytes is not None and size > 0 and size + line_size > self.max_bytes:
            return True
        if self.max_age is not None:
            modified = datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
            if self._now().astimezone(timezone.utc) - modified >= self.max_age:
                return True
        return False

    def _rotate(self) -> None:
        if self._regular_file_metadata(self.path) is None:
            raise AuditError("audit_write_failed", "active audit file disappeared during rotation")
        manifest_path = self.path.with_name(f"{self.path.name}.rotation.json")
        if self._regular_file_metadata(manifest_path) is not None:
            raise AuditError("audit_recovery_failed", "audit rotation manifest already exists")
        manifest = {
            "format_version": 1,
            "transaction_id": uuid.uuid4().hex,
            "max_rotated_files": self.max_rotated_files,
            "operation": "rotate",
            "phase": "staging",
            "present": {
                "active": True,
                "backups": [
                    index
                    for index in range(1, self.max_rotated_files + 1)
                    if self._regular_file_metadata(self._rotated_path(index)) is not None
                ],
            },
        }
        self._write_manifest(manifest_path, manifest)
        self._recover_manifest(manifest_path)

    def _prune_expired_rotated_files(self) -> None:
        if self.max_age is None:
            return
        now = self._now().astimezone(timezone.utc)
        for index in range(1, self.max_rotated_files + 1):
            rotated = self._rotated_path(index)
            metadata = self._regular_file_metadata(rotated)
            if metadata is None:
                continue
            modified = datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
            if now - modified >= self.max_age:
                rotated.unlink()
                self._sync_parent()

    def _rotated_path(self, index: int) -> Path:
        return self.path.with_name(f"{self.path.name}.{index}")

    @staticmethod
    def _regular_file_metadata(path: Path) -> os.stat_result | None:
        try:
            metadata = os.lstat(path)
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(metadata.st_mode):
            raise AuditError("audit_write_failed", f"audit path must be a regular file: {path}")
        return metadata

    def _append_line(self, line: bytes) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuditError("audit_write_failed", f"audit path must be a regular file: {self.path}")
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(line)
            while remaining:
                written = os.write(descriptor, remaining)
                if written == 0:
                    raise OSError("unable to write audit record")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._sync_parent()


class AuditedPolicyStore:
    """Owns the active policy snapshot and its required local audit boundary."""

    def __init__(self, policy_text: str, audit_log: AuditLog):
        self._audit_log = audit_log
        self._lock = threading.RLock()
        candidate = self._build_snapshot(policy_text)
        self._append_activation(candidate)
        self._active_policy = candidate

    @property
    def active_snapshot(self) -> PolicySnapshot:
        with self._lock:
            return self._active_policy.snapshot

    def reload(self, policy_text: str) -> PolicySnapshot:
        candidate = self._build_snapshot(policy_text)
        with self._lock:
            self._append_activation(candidate)
            self._active_policy = candidate
            return candidate.snapshot

    def authorize(self, call: PolicyCall) -> Authorization:
        return self._authorize_with_metadata(call, correlation_id=str(uuid.uuid4()))

    def _authorize_with_metadata(
        self,
        call: PolicyCall,
        *,
        correlation_id: str,
        caller_id: str | None = None,
        deadline_unix_ms: int | None = None,
    ) -> Authorization:
        with self._lock:
            active_policy = self._active_policy
            decision = active_policy.engine.resolve_call(call)
            authorization = Authorization(
                correlation_id=correlation_id,
                snapshot=active_policy.snapshot,
                decision=decision,
                agent=call.agent,
                tool=call.tool,
                user=call.user,
                caller_id=caller_id,
                deadline_unix_ms=deadline_unix_ms,
            )
            self._audit_log.append(
                _record(
                    event="authorization",
                    snapshot=active_policy.snapshot,
                    correlation_id=authorization.correlation_id,
                    agent=call.agent,
                    tool=call.tool,
                    user=call.user,
                    decision=decision,
                    caller_id=caller_id,
                    deadline_unix_ms=deadline_unix_ms,
                )
            )
        return authorization

    def record_outcome(
        self,
        authorization: Authorization,
        status: OutcomeStatus,
        detail: str | None = None,
    ) -> None:
        if not isinstance(status, OutcomeStatus):
            raise ValueError("status must be an OutcomeStatus")
        if detail is not None:
            if not isinstance(detail, str):
                raise ValueError("detail must be a string")
            if len(detail.encode("utf-8")) > 1024:
                raise ValueError("detail must be at most 1024 UTF-8 bytes")
        record = _record(
            event="outcome",
            snapshot=authorization.snapshot,
            correlation_id=authorization.correlation_id,
            agent=authorization.agent,
            tool=authorization.tool,
            user=authorization.user,
            decision=authorization.decision,
            caller_id=authorization.caller_id,
            deadline_unix_ms=authorization.deadline_unix_ms,
        )
        record["outcome_status"] = status.value
        record["outcome_detail"] = detail
        self._audit_log.append(record)

    @staticmethod
    def _build_snapshot(policy_text: str) -> _ActivePolicy:
        engine = PolicyParser.parse(policy_text)
        return _ActivePolicy(
            engine=engine,
            snapshot=PolicySnapshot(
                version=1,
                digest=hashlib.sha256(policy_text.encode("utf-8")).hexdigest(),
            ),
        )

    def _append_activation(self, policy: _ActivePolicy) -> None:
        self._audit_log.append(_record(event="activation", snapshot=policy.snapshot))


def _record(
    *,
    event: str,
    snapshot: PolicySnapshot,
    correlation_id: str | None = None,
    agent: str | None = None,
    tool: str | None = None,
    user: str | None = None,
    decision: Decision | None = None,
    caller_id: str | None = None,
    deadline_unix_ms: int | None = None,
) -> dict[str, Any]:
    record = {
        "event": event,
        "correlation_id": correlation_id,
        "policy_version": snapshot.version,
        "policy_digest": snapshot.digest,
        "agent": agent,
        "tool": tool,
        "user": user,
        "decision": decision.action.value if decision else None,
        "matched_rules": list(decision.matched_rules) if decision else [],
    }
    if caller_id is not None:
        record["caller_id"] = caller_id
    if deadline_unix_ms is not None:
        record["deadline_unix_ms"] = deadline_unix_ms
    return record


def _format_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
