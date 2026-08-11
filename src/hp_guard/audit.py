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

    def append(self, record: Mapping[str, Any]) -> None:
        payload = dict(record)
        payload.setdefault("timestamp", _format_timestamp(self._now()))
        try:
            line = (json.dumps(payload, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        except (TypeError, ValueError) as error:
            raise AuditError("audit_write_failed", f"audit record is not JSON serializable: {error}") from error

        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                self._prune_expired_rotated_files()
                if self._should_rotate(len(line)):
                    self._rotate()
                    self._prune_expired_rotated_files()
                self._append_line(line)
        except AuditError:
            raise
        except OSError as error:
            raise AuditError("audit_write_failed", f"unable to append audit record: {error}") from error

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
        oldest = self._rotated_path(self.max_rotated_files)
        if self._regular_file_metadata(oldest) is not None:
            oldest.unlink()
        for index in range(self.max_rotated_files - 1, 0, -1):
            source = self._rotated_path(index)
            if self._regular_file_metadata(source) is not None:
                os.replace(source, self._rotated_path(index + 1))
        if self._regular_file_metadata(self.path) is None:
            raise AuditError("audit_write_failed", "active audit file disappeared during rotation")
        os.replace(self.path, self._rotated_path(1))

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
