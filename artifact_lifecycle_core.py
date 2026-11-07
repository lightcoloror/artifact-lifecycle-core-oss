#!/usr/bin/env python3
"""Portable, fail-closed artifact lifecycle contracts and bounded local CLI.

This module consolidates the read-only audit patterns from the 2026-08-23
artifact retention audit and the immutable-plan/receipt patterns from the
self-media artifact lifecycle adapter. It does not run a background service
and never performs automatic purge.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import sysconfig
import uuid
from pathlib import Path
from typing import Any, Iterable


SCHEMA_VERSION = "artifact-lifecycle-manifest.v1"
PROFILE_SCHEMA_VERSION = "artifact-lifecycle-profiles.v1"
PLAN_SCHEMA_VERSION = "artifact-lifecycle-operation-plan.v1"
RECEIPT_SCHEMA_VERSION = "artifact-lifecycle-operation-receipt.v1"
APPROVAL_SCHEMA_VERSION = "artifact-lifecycle-approval.v1"
SELF_MEDIA_V2 = "self-media-artifact-lifecycle-manifest.v2"
MIB = 1024 ** 2
GIB = 1024 ** 3
MIN_FREE_BYTES = 512 * MIB
WARN_FREE_BYTES = 5 * GIB
OUTPUT_HEADROOM_MULTIPLIER = 1.25
# Kept for callers that still pass an explicit ratio during migration. The
# default policy no longer reserves a percentage of the whole volume.
MIN_FREE_RATIO = 0.0
LARGE_OUTPUT_PROFILES = {"media", "document_render", "build_dist"}
PURGE_ERROR = "PURGE_DISABLED_BY_POLICY"

LIFECYCLE_STATES = {
    "created", "candidate", "verified", "failed", "superseded", "locked",
    "expired", "retired", "quarantined", "purged",
}
STORAGE_STATES = {"present", "quarantined", "missing", "purged"}
PROTECTED_ROLES = {
    "authoritative_input", "source_code", "runtime_state", "secret_or_account_state",
    "final_deliverable", "evidence_receipt_manifest",
}
PROFILE_IDS = {
    "media", "document_render", "research_evidence", "source_review", "build_dist", "test_cache", "sync_logs"
}


class LifecycleError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_time(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def canonical_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LifecycleError("JSON_READ_FAILED", f"{path}: {exc}") from exc
    if not isinstance(value, dict):
        raise LifecycleError("JSON_OBJECT_REQUIRED", str(path))
    return value


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        if read_json(path) != value:
            raise LifecycleError("ATOMIC_READBACK_MISMATCH", str(path))
    finally:
        try:
            temp.unlink(missing_ok=True)
        except OSError:
            pass


def attach_hash(value: dict[str, Any], field: str) -> dict[str, Any]:
    result = dict(value)
    result.pop(field, None)
    result[field] = canonical_sha256(result)
    return result


def verify_hash(value: dict[str, Any], field: str) -> bool:
    expected = value.get(field)
    payload = dict(value)
    payload.pop(field, None)
    return isinstance(expected, str) and expected == canonical_sha256(payload)


def resolve_root(path: str | Path) -> Path:
    root = Path(path).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise LifecycleError("ROOT_NOT_DIRECTORY", str(root))
    assert_no_reparse(root, root)
    return root


def is_under(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


def _is_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LifecycleError("PATH_ACCESS_DENIED", f"{path}: {exc}") from exc
    attrs = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return path.is_symlink() or bool(attrs & flag)


def assert_no_reparse(path: Path, root: Path) -> None:
    if not is_under(path, root):
        raise LifecycleError("PATH_OUTSIDE_ROOT", str(path))
    current = path
    while True:
        if _is_reparse(current):
            raise LifecycleError("REPARSE_POINT_BLOCKED", str(current))
        if current == root:
            break
        current = current.parent


def volume_identity(path: Path) -> int:
    try:
        return int(path.stat().st_dev)
    except OSError as exc:
        raise LifecycleError("PATH_ACCESS_DENIED", f"{path}: {exc}") from exc


def directory_identity(path: Path) -> dict[str, Any]:
    info = path.stat()
    return {
        "resolved_path": str(path.resolve(strict=True)),
        "volume_id": int(info.st_dev),
        "file_id": int(info.st_ino),
    }


def free_space_status(
    path: Path,
    minimum_ratio: float | None = None,
    *,
    minimum_free_bytes: int = MIN_FREE_BYTES,
    warning_free_bytes: int = WARN_FREE_BYTES,
    estimated_output_bytes: int = 0,
    output_headroom_multiplier: float = OUTPUT_HEADROOM_MULTIPLIER,
) -> dict[str, Any]:
    if minimum_ratio is not None and not 0 <= minimum_ratio <= 1:
        raise LifecycleError("DISK_POLICY_RATIO_INVALID")
    if minimum_free_bytes < 0 or warning_free_bytes < 0 or estimated_output_bytes < 0:
        raise LifecycleError("DISK_POLICY_BYTES_INVALID")
    if output_headroom_multiplier < 1:
        raise LifecycleError("DISK_POLICY_HEADROOM_INVALID")
    usage = shutil.disk_usage(path)
    ratio = 0.0 if usage.total <= 0 else usage.free / usage.total
    ratio_floor_bytes = math.ceil(usage.total * minimum_ratio) if minimum_ratio else 0
    output_reserve_bytes = math.ceil(estimated_output_bytes * output_headroom_multiplier)
    required_free_bytes = max(minimum_free_bytes, ratio_floor_bytes) + output_reserve_bytes
    blocked = usage.free < required_free_bytes
    warned = not blocked and usage.free < warning_free_bytes
    return {
        "status": "blocked_low_disk" if blocked else ("low_disk_allowed" if warned else "ok"),
        "policy_mode": "absolute_reserve_plus_estimated_output",
        "free_ratio": round(ratio, 6),
        "minimum_free_ratio": minimum_ratio,
        "total_bytes": usage.total,
        "free_bytes": usage.free,
        "minimum_free_bytes": minimum_free_bytes,
        "warning_free_bytes": warning_free_bytes,
        "estimated_output_bytes": estimated_output_bytes,
        "output_headroom_multiplier": output_headroom_multiplier,
        "output_reserve_bytes": output_reserve_bytes,
        "required_free_bytes": required_free_bytes,
        "free_after_estimated_output_bytes": usage.free - estimated_output_bytes,
        "warning_only": warned,
    }


def validate_profiles(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if value.get("schema_version") != PROFILE_SCHEMA_VERSION:
        errors.append("profile_schema_version_invalid")
    profiles = value.get("profiles")
    if not isinstance(profiles, list):
        return errors + ["profiles_array_required"]
    ids = {item.get("profile_id") for item in profiles if isinstance(item, dict)}
    if ids != PROFILE_IDS:
        errors.append(f"profile_ids_mismatch:{sorted(str(item) for item in ids)}")
    for item in profiles:
        if not isinstance(item, dict):
            errors.append("profile_object_required")
            continue
        if item.get("automatic_purge") is not False or item.get("cleanup_mode") != "plan_only":
            errors.append(f"unsafe_profile:{item.get('profile_id')}")
        minimum_bytes = item.get("minimum_free_bytes")
        warning_bytes = item.get("warning_free_bytes")
        headroom = item.get("output_headroom_multiplier")
        if not isinstance(minimum_bytes, int) or minimum_bytes < 0:
            errors.append(f"minimum_free_bytes_invalid:{item.get('profile_id')}")
        minimum_value = minimum_bytes if isinstance(minimum_bytes, int) else 0
        if not isinstance(warning_bytes, int) or warning_bytes < max(minimum_value, 0):
            errors.append(f"warning_free_bytes_invalid:{item.get('profile_id')}")
        if not isinstance(headroom, (int, float)) or headroom < 1:
            errors.append(f"output_headroom_multiplier_invalid:{item.get('profile_id')}")
    return errors


def validate_manifest(value: dict[str, Any]) -> list[str]:
    if value.get("schema_version") == SELF_MEDIA_V2:
        try:
            value = convert_self_media_v2(value)
        except LifecycleError as exc:
            return [exc.code]
    errors: list[str] = []
    required_top = {
        "schema_version", "manifest_id", "closure_run_id", "producer_tool_id", "owner_lane",
        "root_identity", "profile_id", "cleanup_mode", "automatic_purge", "artifacts", "manifest_sha256",
    }
    if missing := sorted(required_top - set(value)):
        errors.append(f"manifest_fields_missing:{','.join(missing)}")
    if value.get("schema_version") != SCHEMA_VERSION:
        errors.append("manifest_schema_version_invalid")
    if value.get("profile_id") not in PROFILE_IDS:
        errors.append("profile_id_invalid")
    if value.get("cleanup_mode") != "plan_only" or value.get("automatic_purge") is not False:
        errors.append("unsafe_cleanup_policy")
    if value.get("manifest_sha256") and not verify_hash(value, "manifest_sha256"):
        errors.append("manifest_hash_drift")
    seen: set[str] = set()
    artifact_required = {
        "artifact_id", "closure_run_id", "producer_tool_id", "owner_lane", "path", "artifact_role",
        "digest", "bytes", "lifecycle_state", "storage_state", "depends_on", "referenced_by",
        "sensitivity", "rebuild_proof", "minimum_keep_until", "pin", "file_identity",
    }
    for item in value.get("artifacts", []):
        if not isinstance(item, dict):
            errors.append("artifact_object_required")
            continue
        artifact_id = item.get("artifact_id")
        if artifact_id in seen:
            errors.append(f"artifact_id_duplicate:{artifact_id}")
        seen.add(str(artifact_id))
        if missing := sorted(artifact_required - set(item)):
            errors.append(f"artifact_fields_missing:{artifact_id}:{','.join(missing)}")
        if item.get("lifecycle_state") not in LIFECYCLE_STATES:
            errors.append(f"lifecycle_state_invalid:{artifact_id}")
        if item.get("storage_state") not in STORAGE_STATES:
            errors.append(f"storage_state_invalid:{artifact_id}")
        digest = item.get("digest")
        if not isinstance(digest, dict) or digest.get("algorithm") != "sha256" or len(str(digest.get("value", ""))) != 64:
            errors.append(f"digest_invalid:{artifact_id}")
    return sorted(set(errors))


def load_manifest(path: Path) -> dict[str, Any]:
    value = read_json(path)
    if value.get("schema_version") == SELF_MEDIA_V2:
        value = convert_self_media_v2(value)
    errors = validate_manifest(value)
    if errors:
        raise LifecycleError("MANIFEST_INVALID", ";".join(errors))
    return value


def convert_self_media_v2(value: dict[str, Any]) -> dict[str, Any]:
    """Map the existing self-media v2 contract into the generic v1 view."""
    status_map = {
        "created": "created", "candidate": "candidate", "qa_pass": "verified",
        "qa_fail": "failed", "locked": "locked", "superseded": "superseded",
        "quarantine": "quarantined", "purged": "purged",
    }
    role_map = {
        "raw_source": "authoritative_input", "reviewed_source": "authoritative_input",
        "fine_cut": "reproducible_derived", "candidate": "reproducible_derived",
        "locked_master": "final_deliverable", "final": "final_deliverable",
        "recipe": "evidence_receipt_manifest", "receipt": "evidence_receipt_manifest",
        "cache": "cache_build_test_temp", "proxy": "cache_build_test_temp",
        "frame_extract": "cache_build_test_temp", "chunk": "cache_build_test_temp",
        "browser_profile": "secret_or_account_state", "other": "unknown",
    }
    artifacts = []
    for item in value.get("artifacts", []):
        digest = item.get("source_sha256") or ("0" * 64)
        artifacts.append({
            "artifact_id": item.get("artifact_id"),
            "closure_run_id": value.get("manifest_id"),
            "producer_tool_id": "self-media-artifact-lifecycle",
            "owner_lane": "content-creation-self-media",
            "path": item.get("path"),
            "artifact_role": role_map.get(item.get("artifact_kind"), "unknown"),
            "digest": {"algorithm": "sha256", "value": digest, "status": "declared" if item.get("source_sha256") else "unknown"},
            "bytes": int(item.get("bytes", 0)),
            "lifecycle_state": status_map.get(item.get("status"), "created"),
            "storage_state": "purged" if item.get("status") == "purged" else ("quarantined" if item.get("status") == "quarantine" else "present"),
            "depends_on": list(item.get("depends_on", [])),
            "referenced_by": list(item.get("referenced_by", [])),
            "sensitivity": "unknown",
            "rebuild_proof": {"status": "unknown", "command": None, "input_hashes": [], "dependency_lock": None, "verification_ref": None},
            "minimum_keep_until": item.get("delete_after"),
            "pin": item.get("status") == "locked" or item.get("artifact_kind") in {"raw_source", "reviewed_source", "final", "recipe"},
            "file_identity": {"volume_id": None, "file_id": None, "hardlink_count": None, "observed_links": None},
        })
    result = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": f"compat-{value.get('manifest_id', 'self-media-v2')}",
        "closure_run_id": value.get("manifest_id", "self-media-v2"),
        "producer_tool_id": "self-media-artifact-lifecycle",
        "owner_lane": "content-creation-self-media",
        "root_identity": {"resolved_path": value.get("workspace_ref", "compatibility_view"), "volume_id": None, "file_id": None},
        "profile_id": "media",
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "compatibility_source": SELF_MEDIA_V2,
        "artifacts": artifacts,
    }
    return attach_hash(result, "manifest_sha256")


def _walk_files(root: Path, max_files: int) -> Iterable[tuple[Path, list[str]]]:
    count = 0
    stack = [root]
    while stack:
        directory = stack.pop()
        assert_no_reparse(directory, root)
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name.casefold())
        except OSError as exc:
            yield directory, [f"PATH_ACCESS_DENIED:{exc}"]
            continue
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink() or _is_reparse(path):
                yield path, ["REPARSE_POINT_BLOCKED"]
                continue
            if entry.is_dir(follow_symlinks=False):
                stack.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                continue
            count += 1
            if count > max_files:
                raise LifecycleError("SCAN_FILE_LIMIT_EXCEEDED", str(max_files))
            yield path, []


def scan_root(
    root: Path,
    *,
    profile_id: str,
    producer_tool_id: str,
    owner_lane: str,
    closure_run_id: str,
    max_files: int,
    checkpoint: Path,
) -> dict[str, Any]:
    if profile_id not in PROFILE_IDS:
        raise LifecycleError("PROFILE_NOT_FOUND", profile_id)
    checkpoint.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(checkpoint)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, digest TEXT, bytes INTEGER, dev INTEGER, ino INTEGER, nlink INTEGER, errors TEXT)")
    artifacts: list[dict[str, Any]] = []
    scan_errors: list[dict[str, str]] = []
    hardlink_observed: dict[tuple[int, int], int] = {}
    records: list[tuple[Path, os.stat_result, str, list[str]]] = []
    for path, errors in _walk_files(root, max_files):
        if errors:
            scan_errors.append({"path": str(path), "error": errors[0]})
            connection.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?)", (str(path), None, 0, 0, 0, 0, json.dumps(errors)))
            continue
        try:
            info = path.stat()
            digest = sha256_file(path)
        except (OSError, LifecycleError) as exc:
            scan_errors.append({"path": str(path), "error": f"PATH_ACCESS_DENIED:{exc}"})
            connection.execute("INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?)", (str(path), None, 0, 0, 0, 0, json.dumps([f"PATH_ACCESS_DENIED:{exc}"])))
            continue
        key = (int(info.st_dev), int(info.st_ino))
        hardlink_observed[key] = hardlink_observed.get(key, 0) + 1
        records.append((path, info, digest, errors))
        # Windows file IDs may exceed SQLite's signed 64-bit INTEGER range.
        # Store device/inode identities as lossless decimal text in the dynamic
        # SQLite columns while keeping numeric values in the JSON contract.
        connection.execute(
            "INSERT OR REPLACE INTO files VALUES(?,?,?,?,?,?,?)",
            (str(path), digest, info.st_size, str(info.st_dev), str(info.st_ino), info.st_nlink, "[]"),
        )
    connection.commit()
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    connection.close()
    if integrity != "ok":
        raise LifecycleError("SQLITE_INTEGRITY_FAILED", str(integrity))
    for path, info, digest, _ in records:
        relative = path.relative_to(root).as_posix()
        key = (int(info.st_dev), int(info.st_ino))
        role = "cache_build_test_temp" if profile_id == "test_cache" else ("evidence_receipt_manifest" if profile_id in {"research_evidence", "source_review", "sync_logs"} else "reproducible_derived")
        artifacts.append({
            "artifact_id": f"artifact-{hashlib.sha256(relative.encode('utf-8')).hexdigest()[:20]}",
            "closure_run_id": closure_run_id,
            "producer_tool_id": producer_tool_id,
            "owner_lane": owner_lane,
            "path": relative,
            "artifact_role": role,
            "digest": {"algorithm": "sha256", "value": digest, "status": "verified"},
            "bytes": int(info.st_size),
            "lifecycle_state": "candidate",
            "storage_state": "present",
            "depends_on": [],
            "referenced_by": [],
            "sensitivity": "unknown",
            "rebuild_proof": {"status": "unknown", "command": None, "input_hashes": [], "dependency_lock": None, "verification_ref": None},
            "minimum_keep_until": None,
            "pin": role in PROTECTED_ROLES,
            "file_identity": {
                "volume_id": int(info.st_dev), "file_id": int(info.st_ino),
                "hardlink_count": int(info.st_nlink), "observed_links": hardlink_observed[key],
            },
        })
    payload = {
        "schema_version": SCHEMA_VERSION,
        "manifest_id": f"manifest-{canonical_sha256([item['artifact_id'] for item in artifacts])[:20]}",
        "closure_run_id": closure_run_id,
        "producer_tool_id": producer_tool_id,
        "owner_lane": owner_lane,
        "root_identity": directory_identity(root),
        "profile_id": profile_id,
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "scan": {
            "checked_at": max(
                (dt.datetime.fromtimestamp(item[1].st_mtime, dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z") for item in records),
                default="1970-01-01T00:00:00Z",
            ),
            "checkpoint": checkpoint.name,
            "sqlite_integrity": integrity,
            "max_files": max_files,
            "errors": scan_errors,
        },
        "artifacts": artifacts,
    }
    return attach_hash(payload, "manifest_sha256")


def git_status(root: Path) -> str:
    probe = subprocess.run(
        ["git", "-C", str(root), "status", "--porcelain=v1"],
        text=True, encoding="utf-8", errors="replace", capture_output=True, timeout=10, check=False,
    )
    if probe.returncode != 0:
        return "not_repository"
    return "dirty" if probe.stdout.strip() else "clean"


def artifact_path(root: Path, item: dict[str, Any]) -> Path:
    relative = Path(str(item["path"]))
    if relative.is_absolute() or ".." in relative.parts:
        raise LifecycleError("PATH_OUTSIDE_ROOT", str(relative))
    target = (root / relative).resolve(strict=False)
    if not is_under(target, root):
        raise LifecycleError("PATH_OUTSIDE_ROOT", str(target))
    if target.exists():
        assert_no_reparse(target, root)
    return target


def _rebuild_complete(item: dict[str, Any]) -> bool:
    proof = item.get("rebuild_proof") or {}
    return (
        proof.get("status") == "verified"
        and bool(proof.get("command"))
        and bool(proof.get("input_hashes"))
        and bool(proof.get("dependency_lock"))
        and bool(proof.get("verification_ref"))
    )


def plan_operation(
    manifest: dict[str, Any], root: Path, quarantine_root: Path, operation: str,
    *, owner_state: str, process_state: str, dispatch_state: str,
) -> dict[str, Any]:
    if operation not in {"quarantine", "purge"}:
        raise LifecycleError("OPERATION_INVALID", operation)
    if volume_identity(root) != volume_identity(quarantine_root):
        raise LifecycleError("CROSS_VOLUME_BLOCKED", f"{root} -> {quarantine_root}")
    assert_no_reparse(quarantine_root, quarantine_root)
    git = git_status(root)
    entries = []
    manifest_scan_errors = list((manifest.get("scan") or {}).get("errors", []))
    for item in manifest["artifacts"]:
        blockers: set[str] = set()
        source = artifact_path(root, item)
        if not source.exists():
            blockers.add("artifact_missing")
        if item.get("pin"):
            blockers.add("artifact_pinned")
        if item.get("artifact_role") in PROTECTED_ROLES:
            blockers.add(f"protected_role:{item.get('artifact_role')}")
        if item.get("referenced_by"):
            blockers.add("authoritative_reference_present")
        if item.get("lifecycle_state") not in {"failed", "superseded", "expired", "quarantined"}:
            blockers.add("lifecycle_state_not_eligible")
        if item.get("artifact_role") not in {"cache_build_test_temp", "duplicate_or_obsolete"} and not _rebuild_complete(item):
            blockers.add("rebuild_proof_incomplete")
        keep_until = item.get("minimum_keep_until")
        if keep_until:
            try:
                if parse_time(keep_until) > parse_time(utc_now()):
                    blockers.add("minimum_keep_not_elapsed")
            except ValueError:
                blockers.add("minimum_keep_invalid")
        identity = item.get("file_identity") or {}
        if int(identity.get("hardlink_count") or 1) != int(identity.get("observed_links") or 0):
            blockers.add("hardlink_coverage_incomplete")
        if owner_state != "idle_confirmed":
            blockers.add("owner_not_idle_confirmed")
        if process_state != "idle_confirmed":
            blockers.add("active_process_not_cleared")
        if dispatch_state != "none_active":
            blockers.add("dispatch_not_cleared")
        if git == "dirty":
            blockers.add("git_dirty")
        if manifest_scan_errors:
            blockers.add("scan_errors_present")
        if operation == "purge":
            blockers.add("automatic_purge_disabled")
            if item.get("storage_state") != "quarantined":
                blockers.add("artifact_not_quarantined")
        target = quarantine_root / manifest["manifest_id"] / item["artifact_id"] / source.name
        entries.append({
            "artifact_id": item["artifact_id"],
            "source_path": str(source),
            "quarantine_path": str(target),
            "digest": item["digest"],
            "bytes": item["bytes"],
            "eligible": not blockers,
            "blocking_gates": sorted(blockers),
        })
    plan_seed = {
        "operation": operation,
        "manifest_sha256": manifest["manifest_sha256"],
        "closure_run_id": manifest["closure_run_id"],
        "root_identity": directory_identity(root),
        "quarantine_root_identity": directory_identity(quarantine_root),
        "entries": entries,
    }
    payload = {
        "schema_version": PLAN_SCHEMA_VERSION,
        "plan_id": f"plan-{canonical_sha256(plan_seed)[:20]}",
        "operation": operation,
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "created_at": (manifest.get("scan") or {}).get("checked_at", "1970-01-01T00:00:00Z"),
        "manifest_sha256": manifest["manifest_sha256"],
        "closure_run_id": manifest["closure_run_id"],
        "root_identity": directory_identity(root),
        "quarantine_root_identity": directory_identity(quarantine_root),
        "gate_evidence": {"owner_state": owner_state, "process_state": process_state, "dispatch_state": dispatch_state, "git_state": git},
        "entries": entries,
        "authorization_state": "not_authorized",
        "boundary": "Immutable plan metadata only; this object grants no execution or purge authority.",
    }
    return attach_hash(payload, "plan_sha256")


def validate_plan(plan: dict[str, Any]) -> list[str]:
    errors = []
    if plan.get("schema_version") != PLAN_SCHEMA_VERSION:
        errors.append("plan_schema_version_invalid")
    if not verify_hash(plan, "plan_sha256"):
        errors.append("plan_hash_drift")
    if plan.get("cleanup_mode") != "plan_only" or plan.get("automatic_purge") is not False:
        errors.append("unsafe_plan_policy")
    if plan.get("authorization_state") != "not_authorized":
        errors.append("plan_must_not_authorize_execution")
    seen_sources: set[str] = set()
    for entry in plan.get("entries", []):
        source = os.path.normcase(entry.get("source_path", ""))
        if source in seen_sources:
            errors.append("duplicate_plan_source")
        seen_sources.add(source)
        if entry.get("eligible") == bool(entry.get("blocking_gates")):
            errors.append(f"eligibility_blocker_conflict:{entry.get('artifact_id')}")
    return sorted(set(errors))


def verify_plan(plan: dict[str, Any], manifest: dict[str, Any], root: Path, quarantine_root: Path) -> dict[str, Any]:
    errors = validate_plan(plan)
    if plan.get("manifest_sha256") != manifest.get("manifest_sha256"):
        errors.append("manifest_hash_drift")
    if plan.get("root_identity") != directory_identity(root):
        errors.append("root_identity_drift")
    if plan.get("quarantine_root_identity") != directory_identity(quarantine_root):
        errors.append("quarantine_root_identity_drift")
    manifest_index = {item["artifact_id"]: item for item in manifest["artifacts"]}
    for entry in plan.get("entries", []):
        item = manifest_index.get(entry.get("artifact_id"))
        if not item:
            errors.append(f"artifact_missing_from_manifest:{entry.get('artifact_id')}")
            continue
        source = artifact_path(root, item)
        if entry.get("eligible"):
            if not source.exists():
                errors.append(f"source_missing:{entry.get('artifact_id')}")
            elif sha256_file(source) != item["digest"]["value"]:
                errors.append(f"artifact_digest_drift:{entry.get('artifact_id')}")
        target = Path(entry["quarantine_path"])
        if not is_under(target, quarantine_root):
            errors.append(f"quarantine_path_outside_root:{entry.get('artifact_id')}")
    return {"ok": not errors, "errors": sorted(set(errors)), "checked_at": utc_now(), "plan_sha256": plan.get("plan_sha256")}


def validate_approval(value: dict[str, Any], plan: dict[str, Any], operation: str) -> list[str]:
    errors = []
    if value.get("schema_version") != APPROVAL_SCHEMA_VERSION:
        errors.append("approval_schema_invalid")
    if value.get("approved") is not True:
        errors.append("approval_not_granted")
    if value.get("operation") != operation:
        errors.append("approval_operation_mismatch")
    if value.get("plan_sha256") != plan.get("plan_sha256"):
        errors.append("approval_plan_hash_mismatch")
    if not value.get("approved_by") or not value.get("approved_at") or not value.get("expires_at"):
        errors.append("approval_identity_or_time_missing")
    try:
        if parse_time(value["expires_at"]) <= parse_time(utc_now()):
            errors.append("approval_expired")
    except (KeyError, TypeError, ValueError):
        errors.append("approval_time_invalid")
    if operation == "purge":
        errors.append("automatic_purge_disabled")
    return sorted(set(errors))


def apply_quarantine(
    plan: dict[str, Any], manifest: dict[str, Any], root: Path, quarantine_root: Path,
    approval: dict[str, Any], receipt_path: Path,
) -> dict[str, Any]:
    verification = verify_plan(plan, manifest, root, quarantine_root)
    errors = list(verification["errors"]) + validate_approval(approval, plan, "quarantine")
    eligible = [item for item in plan.get("entries", []) if item.get("eligible")]
    if not eligible:
        errors.append("no_eligible_artifacts")
    if errors:
        raise LifecycleError("QUARANTINE_BLOCKED", ";".join(sorted(set(errors))))
    changed = []
    try:
        for entry in eligible:
            source = Path(entry["source_path"])
            target = Path(entry["quarantine_path"])
            if volume_identity(source.parent) != volume_identity(quarantine_root):
                raise LifecycleError("CROSS_VOLUME_BLOCKED", str(source))
            if target.exists():
                raise LifecycleError("QUARANTINE_TARGET_EXISTS", str(target))
            target.parent.mkdir(parents=True, exist_ok=False)
            os.replace(source, target)
            if sha256_file(target) != entry["digest"]["value"]:
                raise LifecycleError("QUARANTINE_DIGEST_MISMATCH", str(target))
            changed.append({"artifact_id": entry["artifact_id"], "from": str(source), "to": str(target), "digest": entry["digest"]})
    except Exception:
        for item in reversed(changed):
            source, target = Path(item["from"]), Path(item["to"])
            if target.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                os.replace(target, source)
        raise
    receipt = attach_hash({
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "operation": "quarantine",
        "status": "completed",
        "plan_sha256": plan["plan_sha256"],
        "manifest_sha256": manifest["manifest_sha256"],
        "closure_run_id": manifest["closure_run_id"],
        "completed_at": utc_now(),
        "items": changed,
        "filesystem_mutation_scope": "exact_approved_entries_only",
    }, "receipt_sha256")
    atomic_write_json(receipt_path, receipt)
    return receipt


def restore_from_receipt(receipt: dict[str, Any], plan: dict[str, Any], root: Path, quarantine_root: Path, output: Path) -> dict[str, Any]:
    errors = []
    if receipt.get("operation") != "quarantine" or receipt.get("status") != "completed" or not verify_hash(receipt, "receipt_sha256"):
        errors.append("quarantine_receipt_invalid")
    if receipt.get("plan_sha256") != plan.get("plan_sha256"):
        errors.append("receipt_plan_hash_mismatch")
    restored = []
    if errors:
        raise LifecycleError("RESTORE_BLOCKED", ";".join(errors))
    try:
        for item in receipt.get("items", []):
            source = Path(item["to"])
            target = Path(item["from"])
            if not is_under(source, quarantine_root) or not is_under(target, root):
                raise LifecycleError("RESTORE_PATH_OUTSIDE_SCOPE", item.get("artifact_id", ""))
            assert_no_reparse(source, quarantine_root)
            if target.exists():
                raise LifecycleError("RESTORE_TARGET_EXISTS", str(target))
            if sha256_file(source) != item["digest"]["value"]:
                raise LifecycleError("RESTORE_DIGEST_MISMATCH", str(source))
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(source, target)
            restored.append({"artifact_id": item["artifact_id"], "from": str(source), "to": str(target), "digest": item["digest"]})
    except Exception:
        for item in reversed(restored):
            quarantine_source, restored_target = Path(item["from"]), Path(item["to"])
            if restored_target.exists() and not quarantine_source.exists():
                quarantine_source.parent.mkdir(parents=True, exist_ok=True)
                os.replace(restored_target, quarantine_source)
        raise
    result = attach_hash({
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "operation": "restore",
        "status": "completed",
        "plan_sha256": plan["plan_sha256"],
        "closure_run_id": receipt.get("closure_run_id"),
        "completed_at": utc_now(),
        "items": restored,
        "filesystem_mutation_scope": "exact_quarantined_entries_only",
    }, "receipt_sha256")
    atomic_write_json(output, result)
    return result


def contract_asset_root(tool_root: Path) -> tuple[Path, str]:
    """Resolve contracts from a source checkout or an installed wheel."""
    source_manifest = tool_root / "agent-tool-manifest.v1.json"
    if source_manifest.is_file():
        return tool_root, "source_tree"
    installed = Path(sysconfig.get_path("data")) / "share" / "artifact-lifecycle-core"
    if (installed / "agent-tool-manifest.v1.json").is_file():
        return installed, "installed_data_files"
    return tool_root, "unresolved"


def doctor(
    tool_root: Path,
    target_root: Path | None = None,
    profile_id: str | None = None,
    *,
    estimated_output_bytes: int = 0,
    minimum_free_bytes: int = MIN_FREE_BYTES,
    warning_free_bytes: int = WARN_FREE_BYTES,
    output_headroom_multiplier: float = OUTPUT_HEADROOM_MULTIPLIER,
    minimum_free_ratio: float | None = None,
) -> dict[str, Any]:
    asset_root, asset_root_mode = contract_asset_root(tool_root)
    schema_dir = asset_root / "schemas"
    profiles_path = asset_root / "profiles" / "artifact-lifecycle-profiles.v1.json"
    required = [
        schema_dir / "artifact-lifecycle-manifest.v1.schema.json",
        schema_dir / "artifact-lifecycle-operation-plan.v1.schema.json",
        schema_dir / "artifact-lifecycle-operation-receipt.v1.schema.json",
        schema_dir / "agent-tool-manifest.v1.schema.json",
        profiles_path,
        asset_root / "agent-tool-manifest.v1.json",
        asset_root / "AGENT_DISCOVERY.md",
    ]
    missing = [str(path.relative_to(asset_root)) for path in required if not path.is_file()]
    profile_errors = validate_profiles(read_json(profiles_path)) if profiles_path.is_file() else ["profiles_missing"]
    disk = None
    status = "ready" if not missing and not profile_errors else "blocked"
    reason_codes = [*(f"MISSING:{item}" for item in missing), *profile_errors]
    if target_root is not None and profile_id in LARGE_OUTPUT_PROFILES:
        disk = free_space_status(
            target_root,
            minimum_free_ratio,
            minimum_free_bytes=minimum_free_bytes,
            warning_free_bytes=warning_free_bytes,
            estimated_output_bytes=estimated_output_bytes,
            output_headroom_multiplier=output_headroom_multiplier,
        )
        if disk["status"] == "blocked_low_disk":
            status = "blocked"
            reason_codes.append("blocked_low_disk")
        elif disk["status"] == "low_disk_allowed":
            reason_codes.append("low_disk_allowed")
    return {
        "schema_version": "artifact-lifecycle-doctor.v1",
        "status": status,
        "contract_ready": not missing and not profile_errors,
        "runtime_ready": status == "ready",
        "fresh_e2e_pass": False,
        "real_usage_proof": False,
        "current_online": False,
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "filesystem_mutation_performed": False,
        "asset_root_mode": asset_root_mode,
        "reason_codes": sorted(reason_codes),
        "disk": disk,
        "checked_at": utc_now(),
    }


def emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Fail-closed local artifact lifecycle contracts")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor_p = sub.add_parser("doctor")
    doctor_p.add_argument("--target-root")
    doctor_p.add_argument("--profile", choices=sorted(PROFILE_IDS))
    doctor_p.add_argument("--estimated-output-bytes", type=int, default=0)
    doctor_p.add_argument("--minimum-free-bytes", type=int, default=MIN_FREE_BYTES)
    doctor_p.add_argument("--warning-free-bytes", type=int, default=WARN_FREE_BYTES)
    doctor_p.add_argument("--output-headroom-multiplier", type=float, default=OUTPUT_HEADROOM_MULTIPLIER)
    doctor_p.add_argument("--minimum-free-ratio", type=float)

    scan = sub.add_parser("scan")
    scan.add_argument("--root", required=True)
    scan.add_argument("--profile", required=True, choices=sorted(PROFILE_IDS))
    scan.add_argument("--producer-tool-id", required=True)
    scan.add_argument("--owner-lane", required=True)
    scan.add_argument("--closure-run-id", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--checkpoint", required=True)
    scan.add_argument("--max-files", type=int, default=10000)

    explain = sub.add_parser("explain")
    explain.add_argument("--manifest", required=True)
    explain.add_argument("--artifact-id", required=True)

    plan = sub.add_parser("plan")
    plan.add_argument("operation", choices=["quarantine", "purge"])
    plan.add_argument("--manifest", required=True)
    plan.add_argument("--root", required=True)
    plan.add_argument("--quarantine-root", required=True)
    plan.add_argument("--owner-state", default="unknown")
    plan.add_argument("--process-state", default="unknown")
    plan.add_argument("--dispatch-state", default="unknown")
    plan.add_argument("--output", required=True)

    verify = sub.add_parser("verify-plan")
    verify.add_argument("--plan", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--root", required=True)
    verify.add_argument("--quarantine-root", required=True)

    quarantine = sub.add_parser("apply-quarantine")
    quarantine.add_argument("--plan", required=True)
    quarantine.add_argument("--manifest", required=True)
    quarantine.add_argument("--root", required=True)
    quarantine.add_argument("--quarantine-root", required=True)
    quarantine.add_argument("--approval", required=True)
    quarantine.add_argument("--receipt", required=True)
    quarantine.add_argument("--execute", action="store_true")

    restore = sub.add_parser("restore")
    restore.add_argument("--plan", required=True)
    restore.add_argument("--receipt", required=True)
    restore.add_argument("--root", required=True)
    restore.add_argument("--quarantine-root", required=True)
    restore.add_argument("--output", required=True)
    restore.add_argument("--execute", action="store_true")

    purge = sub.add_parser("apply-purge")
    purge.add_argument("--plan", required=True)
    purge.add_argument("--approval")
    purge.add_argument("--execute", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tool_root = Path(__file__).resolve().parent
    try:
        if args.command == "doctor":
            target = resolve_root(args.target_root) if args.target_root else None
            result = doctor(
                tool_root,
                target,
                args.profile,
                estimated_output_bytes=args.estimated_output_bytes,
                minimum_free_bytes=args.minimum_free_bytes,
                warning_free_bytes=args.warning_free_bytes,
                output_headroom_multiplier=args.output_headroom_multiplier,
                minimum_free_ratio=args.minimum_free_ratio,
            )
            emit(result)
            return 0 if result["status"] == "ready" else 2
        if args.command == "scan":
            root = resolve_root(args.root)
            result = scan_root(root, profile_id=args.profile, producer_tool_id=args.producer_tool_id, owner_lane=args.owner_lane, closure_run_id=args.closure_run_id, max_files=args.max_files, checkpoint=Path(args.checkpoint).resolve())
            atomic_write_json(Path(args.output).resolve(), result)
            emit({"status": "ok", "manifest": str(Path(args.output).resolve()), "artifact_count": len(result["artifacts"]), "manifest_sha256": result["manifest_sha256"]})
            return 0
        if args.command == "explain":
            manifest = load_manifest(Path(args.manifest).resolve())
            item = next((item for item in manifest["artifacts"] if item["artifact_id"] == args.artifact_id), None)
            if item is None:
                raise LifecycleError("ARTIFACT_NOT_FOUND", args.artifact_id)
            blockers = []
            if item["pin"]: blockers.append("artifact_pinned")
            if item["artifact_role"] in PROTECTED_ROLES: blockers.append(f"protected_role:{item['artifact_role']}")
            if item["referenced_by"]: blockers.append("authoritative_reference_present")
            if not _rebuild_complete(item): blockers.append("rebuild_proof_incomplete")
            emit({"status": "ok", "artifact": item, "blocking_gates": blockers, "authorizes_operation": False})
            return 0
        if args.command == "plan":
            root = resolve_root(args.root)
            quarantine_root = resolve_root(args.quarantine_root)
            manifest = load_manifest(Path(args.manifest).resolve())
            result = plan_operation(manifest, root, quarantine_root, args.operation, owner_state=args.owner_state, process_state=args.process_state, dispatch_state=args.dispatch_state)
            atomic_write_json(Path(args.output).resolve(), result)
            emit({"status": "ok", "plan": str(Path(args.output).resolve()), "eligible": sum(bool(item["eligible"]) for item in result["entries"]), "blocked": sum(not bool(item["eligible"]) for item in result["entries"]), "plan_sha256": result["plan_sha256"]})
            return 0
        if args.command == "verify-plan":
            result = verify_plan(read_json(Path(args.plan).resolve()), load_manifest(Path(args.manifest).resolve()), resolve_root(args.root), resolve_root(args.quarantine_root))
            emit(result)
            return 0 if result["ok"] else 2
        if args.command == "apply-quarantine":
            if not args.execute:
                raise LifecycleError("EXECUTE_FLAG_REQUIRED")
            result = apply_quarantine(read_json(Path(args.plan).resolve()), load_manifest(Path(args.manifest).resolve()), resolve_root(args.root), resolve_root(args.quarantine_root), read_json(Path(args.approval).resolve()), Path(args.receipt).resolve())
            emit(result)
            return 0
        if args.command == "restore":
            if not args.execute:
                raise LifecycleError("EXECUTE_FLAG_REQUIRED")
            result = restore_from_receipt(read_json(Path(args.receipt).resolve()), read_json(Path(args.plan).resolve()), resolve_root(args.root), resolve_root(args.quarantine_root), Path(args.output).resolve())
            emit(result)
            return 0
        if args.command == "apply-purge":
            raise LifecycleError(PURGE_ERROR, "automatic and direct purge are unavailable in v1")
    except LifecycleError as exc:
        emit({"status": "blocked", "error_code": exc.code, "detail": exc.detail, "filesystem_mutation_performed": False})
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
