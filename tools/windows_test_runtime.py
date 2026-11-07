from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import importlib.util
import json
import os
import py_compile
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from ctypes import wintypes
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterator, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if (SCRIPT_DIR.parent / "artifact_lifecycle_core.py").is_file():
    WORKSPACE_ROOT = SCRIPT_DIR.parent
else:
    WORKSPACE_ROOT = SCRIPT_DIR.parent if SCRIPT_DIR.name == "scripts" else SCRIPT_DIR
DEFAULT_ROOT = WORKSPACE_ROOT / ".runtime" / "managed-test-runs"
TEST_TMP_ROOT_ENV = "TEST_TMP_ROOT"
RUN_PREFIX = "codex-test-"
ROOT_MARKER = ".codex-managed-test-root.json"
LEASE_SCHEMA = "windows-test-runtime-lease.v2"
RUN_SCHEMA = "windows-test-runtime-run.v2"
RECEIPT_SCHEMA = "windows-test-runtime-command-receipt.v3"
RETENTION_SCHEMA = "windows-test-runtime-retention.v1"
TEST_CACHE_MANIFEST_SCHEMA = "windows-test-runtime-test-cache-manifest.v1"
FAILURE_RETENTION_DAYS = 7
SAFE_CACHE_NAMES = {"__pycache__", ".pytest_cache"}
SUPPORTED_ADAPTERS = {"generic", "pytest", "unittest", "node", "vitest", "jest"}
FAILURE_CATALOG_PATH = SCRIPT_DIR / "contracts" / "windows-failure-catalog.json"
ARTIFACT_CORE_PATH = (
    WORKSPACE_ROOT / "artifact_lifecycle_core.py"
    if (WORKSPACE_ROOT / "artifact_lifecycle_core.py").is_file()
    else WORKSPACE_ROOT / "artifact-lifecycle-core" / "artifact_lifecycle_core.py"
)


class ManagedTestRuntimeError(RuntimeError):
    pass


class TempDirectoryAclError(ManagedTestRuntimeError):
    pass


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + f".{uuid.uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManagedTestRuntimeError(
            f"invalid_json:{path}:{type(exc).__name__}"
        ) from exc
    if not isinstance(value, dict):
        raise ManagedTestRuntimeError(f"json_object_required:{path}")
    return value


def load_artifact_core():
    if not ARTIFACT_CORE_PATH.is_file():
        raise ManagedTestRuntimeError(f"artifact_lifecycle_core_missing:{ARTIFACT_CORE_PATH}")
    spec = importlib.util.spec_from_file_location(
        "artifact_lifecycle_core_for_windows_test_runtime", ARTIFACT_CORE_PATH
    )
    if spec is None or spec.loader is None:
        raise ManagedTestRuntimeError("artifact_lifecycle_core_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def retention_deadline(now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    return (current + timedelta(days=FAILURE_RETENTION_DAYS)).isoformat()


def failure_policy(failure_class: str) -> dict[str, Any]:
    catalog = load_json(FAILURE_CATALOG_PATH)
    for entry in catalog.get("entries", []):
        if entry.get("failure_class") == failure_class:
            return {
                "catalog_schema": catalog.get("schema_version"),
                "failure_class": failure_class,
                "fail_closed_state": entry.get("fail_closed_state"),
                "retryable": entry.get("retryable"),
                "max_retries": entry.get("max_retries"),
                "recovery_checkpoint": entry.get("recovery_checkpoint"),
                "cleanup_boundary": entry.get("cleanup_boundary"),
                "kills_user_processes": entry.get("kills_user_processes"),
            }
    unknown = catalog.get("unknown_failure", {})
    return {
        "catalog_schema": catalog.get("schema_version"),
        "failure_class": failure_class,
        "fail_closed_state": unknown.get("fail_closed_state", "needs_attention"),
        "retryable": False,
        "max_retries": 0,
        "recovery_checkpoint": unknown.get("recovery_checkpoint", "manual_failure_classification"),
        "cleanup_boundary": unknown.get("cleanup_boundary", "none"),
        "kills_user_processes": False,
    }


def path_hash(path: Path) -> str:
    return hashlib.sha256(str(path.resolve()).casefold().encode("utf-8")).hexdigest()


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def process_identity(pid: int) -> dict[str, Any]:
    if pid <= 0:
        return {"pid": pid, "alive": False, "creation_token": None, "query": "invalid"}
    if os.name != "nt":
        proc = Path("/proc") / str(pid)
        try:
            token = str(proc.stat().st_ctime_ns)
            return {"pid": pid, "alive": True, "creation_token": token, "query": "procfs"}
        except (FileNotFoundError, ProcessLookupError):
            return {"pid": pid, "alive": False, "creation_token": None, "query": "procfs"}
        except OSError as exc:
            return {"pid": pid, "alive": None, "creation_token": None, "query": type(exc).__name__}

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        if error in {87, 1168}:
            return {"pid": pid, "alive": False, "creation_token": None, "query": f"winerror_{error}"}
        return {"pid": pid, "alive": None, "creation_token": None, "query": f"winerror_{error}"}
    try:
        creation = wintypes.FILETIME()
        exit_time = wintypes.FILETIME()
        kernel = wintypes.FILETIME()
        user = wintypes.FILETIME()
        get_times = kernel32.GetProcessTimes
        get_times.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
            ctypes.POINTER(wintypes.FILETIME),
        ]
        if not get_times(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
            return {
                "pid": pid,
                "alive": None,
                "creation_token": None,
                "query": f"winerror_{ctypes.get_last_error()}",
            }
        token = str((creation.dwHighDateTime << 32) | creation.dwLowDateTime)
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code.restype = wintypes.BOOL
        exit_code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            return {
                "pid": pid,
                "alive": None,
                "creation_token": token,
                "query": f"winerror_{ctypes.get_last_error()}",
            }
        still_active = 259
        return {
            "pid": pid,
            "alive": exit_code.value == still_active,
            "creation_token": token,
            "exit_code": None if exit_code.value == still_active else exit_code.value,
            "query": "GetProcessTimes+GetExitCodeProcess",
        }
    finally:
        kernel32.CloseHandle(handle)


class WindowsJob:
    def __init__(self) -> None:
        self.handle: int | None = None
        self.assigned = False
        if os.name != "nt":
            return
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_job = kernel32.CreateJobObjectW
        create_job.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        create_job.restype = wintypes.HANDLE
        handle = create_job(None, None)
        if not handle:
            raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_longlong),
                ("PerJobUserTimeLimit", ctypes.c_longlong),
                ("LimitFlags", wintypes.DWORD),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", wintypes.DWORD),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", wintypes.DWORD),
                ("SchedulingClass", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [
                ("ReadOperationCount", ctypes.c_ulonglong),
                ("WriteOperationCount", ctypes.c_ulonglong),
                ("OtherOperationCount", ctypes.c_ulonglong),
                ("ReadTransferCount", ctypes.c_ulonglong),
                ("WriteTransferCount", ctypes.c_ulonglong),
                ("OtherTransferCount", ctypes.c_ulonglong),
            ]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", BasicLimit),
                ("IoInfo", IoCounters),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        info = ExtendedLimit()
        info.BasicLimitInformation.LimitFlags = 0x00002000
        set_information = kernel32.SetInformationJobObject
        set_information.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        set_information.restype = wintypes.BOOL
        ok = set_information(
            handle, 9, ctypes.byref(info), ctypes.sizeof(info)
        )
        if not ok:
            error = ctypes.get_last_error()
            kernel32.CloseHandle(handle)
            raise OSError(error, "SetInformationJobObject failed")
        self.handle = handle

    def assign(self, process: subprocess.Popen[Any]) -> None:
        if os.name != "nt":
            self.assigned = True
            return
        if self.handle is None:
            raise OSError("job handle unavailable")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        assign = kernel32.AssignProcessToJobObject
        assign.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        assign.restype = wintypes.BOOL
        if not assign(self.handle, int(process._handle)):
            raise OSError(ctypes.get_last_error(), "AssignProcessToJobObject failed")
        self.assigned = True

    def terminate(self, code: int = 124) -> None:
        if os.name == "nt" and self.handle is not None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            terminate = kernel32.TerminateJobObject
            terminate.argtypes = [wintypes.HANDLE, wintypes.UINT]
            terminate.restype = wintypes.BOOL
            if not terminate(self.handle, code):
                raise OSError(ctypes.get_last_error(), "TerminateJobObject failed")

    def close(self) -> None:
        if os.name == "nt" and self.handle is not None:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(self.handle)
            self.handle = None


def scan_exclusion_contract(managed_root: Path) -> dict[str, Any]:
    return {
        "schema_version": "windows-test-scan-exclusions.v1",
        "managed_root": str(managed_root.resolve()),
        "managed_root_marker": ROOT_MARKER,
        "managed_run_prefix": RUN_PREFIX,
        "exact_generated_directory_names": sorted(SAFE_CACHE_NAMES),
        "forbidden_fuzzy_patterns": ["tmp*", "test*", "output*", "cache*"],
        "must_never_hide_directory_names": ["src", "tests", "business", "docs", "data"],
        "rule": "exclude the marked managed root subtree and exact generated cache names only",
    }


def _write_root_marker(root: Path) -> None:
    marker = root / ROOT_MARKER
    expected = {
        "schema_version": "windows-test-managed-root.v1",
        "managed_root": str(root.resolve()),
        "managed_root_hash": path_hash(root),
        "run_prefix": RUN_PREFIX,
        "scan_exclusions": scan_exclusion_contract(root),
    }
    if marker.is_file():
        existing = load_json(marker)
        if canonical_sha256(existing) != canonical_sha256(expected):
            raise ManagedTestRuntimeError(f"managed_root_marker_conflict:{root}")
    else:
        atomic_write_json(marker, expected)


def probe_acl(root: Path) -> dict[str, Any]:
    probe = root / f".acl-probe-{os.getpid()}-{uuid.uuid4().hex}"
    operations: list[dict[str, Any]] = []
    try:
        # Root preflight must not create a restrictive directory on Windows.
        # Python's 0700 behavior is verified inside the child compatibility shim.
        probe.mkdir(mode=0o777)
        operations.append({"operation": "mkdir_safe", "passed": True})
        source = probe / "probe.txt"
        source.write_text("ok\n", encoding="utf-8")
        operations.append({"operation": "write", "passed": True})
        if source.read_text(encoding="utf-8").strip() != "ok":
            raise OSError("probe_read_mismatch")
        operations.append({"operation": "read", "passed": True})
        renamed = probe / "renamed.txt"
        source.rename(renamed)
        operations.append({"operation": "rename", "passed": True})
        list(probe.iterdir())
        operations.append({"operation": "list", "passed": True})
        renamed.unlink()
        probe.rmdir()
        operations.append({"operation": "delete", "passed": True})
        return {"status": "passed", "operations": operations, "error": None}
    except (OSError, PermissionError) as exc:
        operations.append({"operation": "failed", "passed": False})
        return {
            "status": "failed",
            "operations": operations,
            "error": f"{type(exc).__name__}: {exc}",
        }
    finally:
        if probe.exists():
            with contextlib.suppress(OSError):
                shutil.rmtree(probe)


def resolve_managed_root(root: Path | str | None = None) -> Path:
    selected = root or os.environ.get(TEST_TMP_ROOT_ENV) or DEFAULT_ROOT
    resolved = Path(selected).resolve()
    if not _inside(resolved, WORKSPACE_ROOT):
        raise ManagedTestRuntimeError(
            f"managed test root must stay inside workspace: {resolved}"
        )
    try:
        resolved.mkdir(parents=True, exist_ok=True)
        _write_root_marker(resolved)
    except (OSError, PermissionError) as exc:
        raise TempDirectoryAclError(
            f"managed test root is not writable: {resolved}: {type(exc).__name__}"
        ) from exc
    acl = probe_acl(resolved)
    if acl["status"] != "passed":
        raise TempDirectoryAclError(
            f"managed test root ACL probe failed: {resolved}: {acl['error']}"
        )
    return resolved


def _run_paths(root: Path, run_id: str) -> tuple[Path, Path, Path]:
    return (
        root / run_id,
        root / "_leases" / f"{run_id}.json",
        root / "_receipts" / f"{run_id}.json",
    )


def create_managed_run(*, purpose: str, profile: str, root: Path | str | None = None) -> dict[str, Any]:
    managed_root = resolve_managed_root(root)
    safe_purpose = purpose.strip()
    safe_profile = profile.strip()
    if not safe_purpose or not safe_profile:
        raise ManagedTestRuntimeError("purpose and profile are required")
    run_id = f"{RUN_PREFIX}{os.getpid()}-{uuid.uuid4().hex}"
    run_path, lease_path, _ = _run_paths(managed_root, run_id)
    token = secrets.token_urlsafe(32)
    identity = process_identity(os.getpid())
    manifest = {
        "schema_version": RUN_SCHEMA,
        "run_id": run_id,
        "purpose": safe_purpose,
        "profile": safe_profile,
        "created_at": utc_now(),
        "creator": identity,
        "managed_root": str(managed_root),
        "managed_root_hash": path_hash(managed_root),
        "run_path": str(run_path),
        "owner_token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
        "status": "active",
        "retention": {
            "schema_version": RETENTION_SCHEMA,
            "failure_retention_days": FAILURE_RETENTION_DAYS,
            "delete_after": None,
            "pin": False,
            "policy": "delete_on_success_retain_failure",
        },
    }
    try:
        run_path.mkdir()
        atomic_write_json(run_path / "run-manifest.json", manifest)
        lease = {
            "schema_version": LEASE_SCHEMA,
            "run_id": run_id,
            "run_path": str(run_path),
            "managed_root": str(managed_root),
            "owner_token": token,
            "owner_token_sha256": manifest["owner_token_sha256"],
            "creator": identity,
            "status": "active",
            "retention": manifest["retention"],
        }
        atomic_write_json(lease_path, lease)
    except (OSError, PermissionError) as exc:
        with contextlib.suppress(OSError):
            shutil.rmtree(run_path)
        raise TempDirectoryAclError(
            f"cannot create managed test run: {run_path}: {type(exc).__name__}"
        ) from exc
    return {
        "root": managed_root,
        "run_id": run_id,
        "run_path": run_path,
        "lease_path": lease_path,
        "owner_token": token,
        "manifest": manifest,
    }


def _validate_owned_run(root: Path, run_path: Path, owner_token: str) -> dict[str, Any]:
    resolved_root = root.resolve()
    resolved_run = run_path.resolve()
    try:
        relative = resolved_run.relative_to(resolved_root)
    except ValueError as exc:
        raise ManagedTestRuntimeError(f"refusing path outside managed root: {resolved_run}") from exc
    if len(relative.parts) != 1 or not relative.name.startswith(RUN_PREFIX):
        raise ManagedTestRuntimeError(f"refusing non-run directory: {resolved_run}")
    manifest = load_json(resolved_run / "run-manifest.json")
    expected_token_hash = hashlib.sha256(owner_token.encode("utf-8")).hexdigest()
    checks = {
        "schema": manifest.get("schema_version") == RUN_SCHEMA,
        "run_id": manifest.get("run_id") == resolved_run.name,
        "root_hash": manifest.get("managed_root_hash") == path_hash(resolved_root),
        "token": secrets.compare_digest(str(manifest.get("owner_token_sha256", "")), expected_token_hash),
    }
    if not all(checks.values()):
        raise ManagedTestRuntimeError(f"owned_run_validation_failed:{resolved_run}:{checks}")
    return manifest


def cleanup_run(root: Path, run_path: Path, owner_token: str, retries: int = 4) -> dict[str, Any]:
    _validate_owned_run(root, run_path, owner_token)
    errors: list[str] = []
    for attempt in range(1, retries + 1):
        try:
            if run_path.exists():
                shutil.rmtree(run_path)
            return {
                "status": "cleaned",
                "attempts": attempt,
                "exists_after_cleanup": run_path.exists(),
                "errors": errors,
                "ownership_verified": True,
            }
        except (OSError, PermissionError) as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            time.sleep(0.05 * attempt)
    return {
        "status": "cleanup_failed",
        "attempts": retries,
        "exists_after_cleanup": run_path.exists(),
        "errors": errors,
        "ownership_verified": True,
    }


def managed_environment(run_path: Path, profile: str) -> dict[str, str]:
    environment = os.environ.copy()
    temp_root = run_path / "temp"
    pycache_root = run_path / "pycache"
    pytest_root = run_path / "pytest-basetemp"
    pytest_cache = run_path / "pytest-cache"
    node_cache = run_path / "node-cache"
    for path in (temp_root, pycache_root, pytest_root.parent, pytest_cache.parent, node_cache):
        path.mkdir(parents=True, exist_ok=True)
    for name in ("TEMP", "TMP", "TMPDIR"):
        environment[name] = str(temp_root)
    environment[TEST_TMP_ROOT_ENV] = str(run_path)
    environment["CODEX_MANAGED_TEST_RUN"] = str(run_path)
    environment["CODEX_TEST_PROFILE"] = profile
    environment["PYTHONPYCACHEPREFIX"] = str(pycache_root)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["npm_config_cache"] = str(node_cache / "npm")
    environment["XDG_CACHE_HOME"] = str(node_cache / "xdg")
    environment["JEST_CACHE_DIRECTORY"] = str(node_cache / "jest")
    environment["VITEST_CACHE_DIR"] = str(node_cache / "vitest")
    existing = environment.get("PYTEST_ADDOPTS", "").strip()
    managed = f"--basetemp={pytest_root.as_posix()} -o cache_dir={pytest_cache.as_posix()}"
    environment["PYTEST_ADDOPTS"] = f"{existing} {managed}".strip()
    sitecustomize = run_path / "sitecustomize.py"
    sitecustomize.write_text(
        "# Loaded only by this managed child process.\n"
        "import os\n"
        "from pathlib import Path\n"
        "if os.name == 'nt':\n"
        "    _root = Path(os.environ['CODEX_MANAGED_TEST_RUN']).resolve()\n"
        "    def _inside(value):\n"
        "        try:\n"
        "            Path(value).resolve().relative_to(_root)\n"
        "            return True\n"
        "        except (OSError, TypeError, ValueError):\n"
        "            return False\n"
        "    _mkdir = os.mkdir\n"
        "    def managed_mkdir(path, mode=0o777, *, dir_fd=None):\n"
        "        if dir_fd is None and mode == 0o700 and _inside(path):\n"
        "            mode = 0o777\n"
        "        if dir_fd is None:\n"
        "            return _mkdir(path, mode)\n"
        "        return _mkdir(path, mode, dir_fd=dir_fd)\n"
        "    os.mkdir = managed_mkdir\n"
        "    _chmod = os.chmod\n"
        "    def managed_chmod(path, mode, *, dir_fd=None, follow_symlinks=True):\n"
        "        try:\n"
        "            if dir_fd is None:\n"
        "                return _chmod(path, mode, follow_symlinks=follow_symlinks)\n"
        "            return _chmod(path, mode, dir_fd=dir_fd, follow_symlinks=follow_symlinks)\n"
        "        except PermissionError:\n"
        "            if dir_fd is None and _inside(path):\n"
        "                return None\n"
        "            raise\n"
        "    os.chmod = managed_chmod\n",
        encoding="utf-8",
    )
    existing_pythonpath = environment.get("PYTHONPATH", "").strip()
    environment["PYTHONPATH"] = (
        str(run_path)
        if not existing_pythonpath
        else str(run_path) + os.pathsep + existing_pythonpath
    )
    return environment


def _write_run_receipt(root: Path, run_id: str, receipt: dict[str, Any]) -> Path:
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    _, _, receipt_path = _run_paths(root, run_id)
    atomic_write_json(receipt_path, receipt)
    return receipt_path


def _child_exit_gate(details: dict[str, Any]) -> dict[str, Any]:
    identity = details.get("child_identity") or {}
    pid = int(identity.get("pid") or 0)
    expected = identity.get("creation_token")
    if pid <= 0 or not expected:
        return {"status": "not_applicable", "child_active": False, "pid": pid or None}
    current = process_identity(pid)
    if current.get("alive") is None:
        return {
            "status": "blocked_identity_unknown",
            "child_active": None,
            "pid": pid,
            "expected_creation_token": expected,
            "current": current,
        }
    active = current.get("alive") is True and current.get("creation_token") == expected
    return {
        "status": "blocked_active_child" if active else "cleared",
        "child_active": active,
        "pid": pid,
        "expected_creation_token": expected,
        "current": current,
    }


def retain_failed_run(
    state: dict[str, Any],
    status: str,
    details: dict[str, Any],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    root = state["root"]
    run_path = state["run_path"]
    lease_path = state["lease_path"]
    _validate_owned_run(root, run_path, state["owner_token"])
    child_gate = _child_exit_gate(details)
    delete_after = retention_deadline(now)
    retained_at = (now or datetime.now(UTC)).isoformat()
    retention = {
        "schema_version": RETENTION_SCHEMA,
        "policy": "delete_on_success_retain_failure",
        "failure_retention_days": FAILURE_RETENTION_DAYS,
        "retained_at": retained_at,
        "delete_after": delete_after,
        "pin": False,
        "reason_status": status,
        "child_exit_gate": child_gate,
    }
    manifest_path = run_path / "run-manifest.json"
    manifest = load_json(manifest_path)
    manifest["status"] = "retained_failure"
    manifest["completed_at"] = retained_at
    manifest["retention"] = retention
    atomic_write_json(manifest_path, manifest)
    lease = load_json(lease_path)
    if not secrets.compare_digest(
        str(lease.get("owner_token_sha256", "")),
        hashlib.sha256(state["owner_token"].encode("utf-8")).hexdigest(),
    ):
        raise ManagedTestRuntimeError(f"retention_lease_token_mismatch:{state['run_id']}")
    lease["status"] = "retained_failure"
    lease["retention"] = retention
    atomic_write_json(lease_path, lease)
    return {
        "status": "retained_failure",
        "exists_after_finish": run_path.exists(),
        "ownership_verified": True,
        "delete_after": delete_after,
        "pin": False,
        "child_exit_gate": child_gate,
    }


def _finish_run(state: dict[str, Any], status: str, details: dict[str, Any]) -> dict[str, Any]:
    root = state["root"]
    run_path = state["run_path"]
    effective_details = dict(details)
    retention: dict[str, Any] | None = None
    if status == "passed":
        cleanup = cleanup_run(root, run_path, state["owner_token"])
        if cleanup["status"] != "cleaned":
            effective_details["failure_class"] = "temp_directory_acl"
            effective_details["signal_code"] = "WINERROR_5_TEMP"
            effective_details["failure_policy"] = failure_policy("temp_directory_acl")
            retention = retain_failed_run(state, "cleanup_failed", effective_details)
    else:
        cleanup = {
            "status": "not_attempted_failure_retained",
            "attempts": 0,
            "exists_after_cleanup": run_path.exists(),
            "errors": [],
            "ownership_verified": True,
        }
        retention = retain_failed_run(state, status, effective_details)
    if retention is not None:
        effective_details["retention"] = retention
        child_gate = retention["child_exit_gate"]
        if child_gate["status"] in {"blocked_active_child", "blocked_identity_unknown"}:
            effective_details["failure_class"] = "active_child_not_cleared"
            effective_details["signal_code"] = "ACTIVE_CHILD_BLOCKED"
    receipt = {
        "schema_version": RECEIPT_SCHEMA,
        "run_id": state["run_id"],
        "purpose": state["manifest"]["purpose"],
        "profile": state["manifest"]["profile"],
        "created_at": state["manifest"]["created_at"],
        "completed_at": utc_now(),
        "status": "cleanup_failed" if status == "passed" and cleanup["status"] != "cleaned" else status,
        "cleanup": cleanup,
        "retention": retention,
        "details": effective_details,
    }
    _write_run_receipt(root, state["run_id"], receipt)
    if status == "passed" and cleanup["status"] == "cleaned":
        with contextlib.suppress(OSError):
            state["lease_path"].unlink()
    return receipt


@contextlib.contextmanager
def managed_test_directory(
    *, purpose: str, profile: str = "generic", root: Path | str | None = None
) -> Iterator[Path]:
    state = create_managed_run(purpose=purpose, profile=profile, root=root)
    error: BaseException | None = None
    try:
        yield state["run_path"]
    except BaseException as exc:
        error = exc
        raise
    finally:
        receipt = _finish_run(
            state,
            "failed" if error else "passed",
            {"body_error_type": type(error).__name__ if error else None},
        )
        if receipt["status"] == "cleanup_failed" and error is None:
            raise ManagedTestRuntimeError(f"managed test cleanup failed:{state['run_id']}")


def terminate_owned_direct_child(
    process: subprocess.Popen[Any], creation_identity: dict[str, Any] | None
) -> dict[str, Any]:
    if process.poll() is not None:
        return {"status": "already_exited", "pid": process.pid, "returncode": process.returncode}
    current = process_identity(process.pid)
    expected_token = (creation_identity or {}).get("creation_token")
    if (
        current.get("alive") is not True
        or not expected_token
        or current.get("creation_token") != expected_token
    ):
        return {
            "status": "identity_mismatch",
            "pid": process.pid,
            "creation_identity": creation_identity,
            "current_identity": current,
        }
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return {"status": "terminate_timeout", "pid": process.pid}
    return {"status": "terminated", "pid": process.pid, "returncode": process.returncode}


def acl_regression_gate(
    run_path: Path,
    environment: dict[str, str],
    *,
    timeout_seconds: float = 10.0,
) -> dict[str, Any]:
    gate_path = run_path / "acl-regression-gate"
    child_receipt = gate_path / "child-receipt.json"
    steps: list[dict[str, Any]] = []
    process: subprocess.Popen[Any] | None = None
    child_identity: dict[str, Any] | None = None
    job: WindowsJob | None = None
    stage = "parent_create"
    try:
        gate_path.mkdir(mode=0o777)
        steps.append({"step": "parent_create", "status": "passed"})
        stage = "child_use"
        child_code = (
            "import json, os, sys, tempfile\n"
            "from pathlib import Path\n"
            "gate = Path(sys.argv[1]).resolve()\n"
            "run = Path(os.environ['TEST_TMP_ROOT']).resolve()\n"
            "temp = Path(tempfile.mkdtemp(prefix='acl-child-', dir=os.environ['TEMP'])).resolve()\n"
            "assert gate.is_relative_to(run) and temp.is_relative_to(run)\n"
            "payload = gate / 'child-data.txt'\n"
            "payload.write_text('child-write-ok\\n', encoding='utf-8')\n"
            "(temp / 'temp-data.txt').write_text('temp-write-ok\\n', encoding='utf-8')\n"
            "Path(sys.argv[2]).write_text(json.dumps({'status':'passed','payload':str(payload),'temp':str(temp)})+'\\n', encoding='utf-8')\n"
        )
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", child_code, str(gate_path), str(child_receipt)],
            cwd=str(run_path),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
            shell=False,
        )
        child_identity = process_identity(process.pid)
        job = WindowsJob()
        job.assign(process)
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            if os.name == "nt":
                job.terminate(124)
            else:
                terminate_owned_direct_child(process, child_identity)
            process.wait(timeout=5)
            return {
                "status": "failed",
                "failure_class": "timeout",
                "signal_code": "DEADLINE_EXCEEDED",
                "failed_stage": stage,
                "steps": steps,
                "failure_policy": failure_policy("timeout"),
            }
        if returncode != 0 or not child_receipt.is_file():
            raise TempDirectoryAclError(f"acl gate child failed with returncode {returncode}")
        steps.append({"step": "child_use", "status": "passed", "child_pid": process.pid})
        stage = "parent_read"
        child_payload = load_json(child_receipt)
        payload_path = Path(str(child_payload.get("payload", ""))).resolve()
        if (
            child_payload.get("status") != "passed"
            or not _inside(payload_path, run_path)
            or payload_path.read_text(encoding="utf-8").strip() != "child-write-ok"
        ):
            raise TempDirectoryAclError("acl gate parent read validation failed")
        steps.append({"step": "parent_read", "status": "passed"})
        stage = "cleanup"
        shutil.rmtree(gate_path)
        if gate_path.exists():
            raise TempDirectoryAclError("acl gate cleanup left directory behind")
        steps.append({"step": "cleanup", "status": "passed"})
        return {
            "status": "passed",
            "failure_class": None,
            "signal_code": None,
            "failed_stage": None,
            "steps": steps,
            "child_identity": child_identity,
        }
    except PermissionError as exc:
        failure_class = "spawn_eperm" if stage == "child_use" and process is None else "temp_directory_acl"
        signal = "SPAWN_EPERM" if failure_class == "spawn_eperm" else "WINERROR_5_TEMP"
        return {
            "status": "failed",
            "failure_class": failure_class,
            "signal_code": signal,
            "failed_stage": stage,
            "error": f"{type(exc).__name__}: {exc}",
            "steps": steps,
            "failure_policy": failure_policy(failure_class),
        }
    except (OSError, ManagedTestRuntimeError, subprocess.SubprocessError) as exc:
        return {
            "status": "failed",
            "failure_class": "temp_directory_acl",
            "signal_code": "WINERROR_5_TEMP",
            "failed_stage": stage,
            "error": f"{type(exc).__name__}: {exc}",
            "steps": steps,
            "failure_policy": failure_policy("temp_directory_acl"),
        }
    finally:
        if job is not None:
            job.close()
        elif process is not None and process.poll() is None:
            terminate_owned_direct_child(process, child_identity)


def _resolve_executable(value: str) -> str:
    candidate = Path(value)
    if candidate.is_file():
        return str(candidate.resolve())
    discovered = shutil.which(value)
    if discovered:
        return discovered
    raise ManagedTestRuntimeError(f"adapter_executable_missing:{value}")


def build_adapter_command(
    adapter: str,
    *,
    cwd: Path,
    arguments: Sequence[str],
    executable: str | None = None,
) -> list[str]:
    if adapter not in SUPPORTED_ADAPTERS - {"generic"}:
        raise ManagedTestRuntimeError(f"unsupported_adapter:{adapter}")
    if adapter in {"pytest", "unittest"}:
        python = _resolve_executable(executable or sys.executable)
        module = "pytest" if adapter == "pytest" else "unittest"
        return [python, "-m", module, *arguments]
    if adapter == "node":
        return [_resolve_executable(executable or "node"), *arguments]
    if executable:
        return [_resolve_executable(executable), *arguments]
    local_name = f"{adapter}.cmd" if os.name == "nt" else adapter
    local_binary = cwd.resolve() / "node_modules" / ".bin" / local_name
    if not local_binary.is_file():
        raise ManagedTestRuntimeError(f"adapter_executable_missing:{adapter}:{local_binary}")
    return [str(local_binary), *arguments]


def run_command(
    command: Sequence[str],
    *,
    purpose: str,
    profile: str,
    timeout_seconds: float,
    cwd: Path | None,
    root: Path | str | None = None,
    adapter: str = "generic",
) -> dict[str, Any]:
    if not command:
        raise ManagedTestRuntimeError("a command is required")
    state = create_managed_run(purpose=purpose, profile=profile, root=root)
    run_path = state["run_path"]
    evidence_dir = state["root"] / "_evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    log_path = evidence_dir / f"{state['run_id']}.log"
    child_evidence = evidence_dir / f"{state['run_id']}.child.json"
    environment = managed_environment(run_path, profile)
    environment["CODEX_CHILD_PID_EVIDENCE"] = str(child_evidence)
    effective_command = list(command)
    if adapter == "jest" and not any(
        item == "--cacheDirectory" or item.startswith("--cacheDirectory=")
        for item in effective_command[1:]
    ):
        effective_command.append(f"--cacheDirectory={run_path / 'node-cache' / 'jest'}")
    manifest_path = run_path / "run-manifest.json"
    manifest = load_json(manifest_path)
    manifest["command_contract"] = {
        "sha256": canonical_sha256(effective_command),
        "executable": Path(effective_command[0]).name,
        "argument_count": max(0, len(effective_command) - 1),
        "cwd": str(cwd.resolve()) if cwd else None,
        "shell": False,
    }
    atomic_write_json(manifest_path, manifest)
    acl_gate = acl_regression_gate(run_path, environment)
    if acl_gate["status"] != "passed":
        failure_class = str(acl_gate["failure_class"])
        gate_status = "timed_out" if failure_class == "timeout" else "blocked"
        return _finish_run(
            state,
            gate_status,
            {
                "adapter": adapter,
                "failure_class": failure_class,
                "signal_code": acl_gate.get("signal_code"),
                "failure_policy": acl_gate.get("failure_policy") or failure_policy(failure_class),
                "acl_regression_gate": acl_gate,
                "command_started": False,
            },
        )
    process: subprocess.Popen[Any] | None = None
    job: WindowsJob | None = None
    status = "blocked"
    returncode: int | None = None
    timed_out = False
    failure_class: str | None = None
    child_identity: dict[str, Any] | None = None
    job_assigned = False
    direct_child_cleanup: dict[str, Any] | None = None
    started_at = utc_now()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        try:
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
            process = subprocess.Popen(
                effective_command,
                cwd=str(cwd) if cwd else None,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                creationflags=creationflags,
                shell=False,
            )
            child_identity = process_identity(process.pid)
            job = WindowsJob()
            job.assign(process)
            job_assigned = True
            try:
                returncode = process.wait(timeout=timeout_seconds)
                status = "passed" if returncode == 0 else "failed"
                failure_class = None if returncode == 0 else "code_assertion_failure"
            except subprocess.TimeoutExpired:
                timed_out = True
                failure_class = "timeout"
                status = "timed_out"
                job.terminate(124)
                returncode = process.wait(timeout=10)
        except PermissionError as exc:
            failure_class = "spawn_eperm"
            log.write(f"PermissionError: {exc}\n")
        except (OSError, subprocess.SubprocessError) as exc:
            failure_class = "job_assignment_failed" if process is not None else "spawn_failure"
            log.write(f"{type(exc).__name__}: {exc}\n")
            if process is not None and process.poll() is None:
                direct_child_cleanup = terminate_owned_direct_child(process, child_identity)
        finally:
            if job is not None:
                job.close()
            elif process is not None and process.poll() is None:
                direct_child_cleanup = terminate_owned_direct_child(process, child_identity)

    details = {
        "started_at": started_at,
        "completed_at": utc_now(),
        "child_pid": process.pid if process is not None else None,
        "child_identity": child_identity,
        "job_object_assigned": job_assigned,
        "job_close_kills_residual_descendants": bool(job_assigned and os.name == "nt"),
        "direct_child_cleanup": direct_child_cleanup,
        "returncode": returncode,
        "timed_out": timed_out,
        "failure_class": failure_class,
        "signal_code": (
            "DEADLINE_EXCEEDED" if failure_class == "timeout"
            else "SPAWN_EPERM" if failure_class == "spawn_eperm"
            else "NONZERO_TEST_EXIT" if failure_class == "code_assertion_failure"
            else None
        ),
        "failure_policy": failure_policy(failure_class) if failure_class else None,
        "adapter": adapter,
        "acl_regression_gate": acl_gate,
        "command_started": process is not None,
        "timeout_seconds": timeout_seconds,
        "executable": Path(effective_command[0]).name,
        "argument_count": max(0, len(effective_command) - 1),
        "cwd": str(cwd.resolve()) if cwd else None,
        "log": str(log_path),
        "child_evidence": str(child_evidence),
        "environment_contract": {
            "temp_root": str(run_path / "temp"),
            "pytest_basetemp": str(run_path / "pytest-basetemp"),
            "pytest_cache": str(run_path / "pytest-cache"),
            "python_pycache_prefix": str(run_path / "pycache"),
            "node_cache": str(run_path / "node-cache"),
        },
    }
    return _finish_run(state, status, details)


def run_adapter(
    adapter: str,
    *,
    purpose: str,
    arguments: Sequence[str],
    timeout_seconds: float,
    cwd: Path,
    root: Path | str | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    command = build_adapter_command(
        adapter,
        cwd=cwd,
        arguments=arguments,
        executable=executable,
    )
    return run_command(
        command,
        purpose=purpose,
        profile=adapter,
        timeout_seconds=timeout_seconds,
        cwd=cwd,
        root=root,
        adapter=adapter,
    )


def recover_run(run_id: str, *, root: Path | str | None = None) -> dict[str, Any]:
    managed_root = resolve_managed_root(root)
    if not run_id.startswith(RUN_PREFIX) or any(char in run_id for char in ("/", "\\", "..")):
        raise ManagedTestRuntimeError(f"invalid_run_id:{run_id}")
    run_path, lease_path, _ = _run_paths(managed_root, run_id)
    lease = load_json(lease_path)
    if lease.get("schema_version") != LEASE_SCHEMA or lease.get("run_id") != run_id:
        raise ManagedTestRuntimeError(f"invalid_recovery_lease:{run_id}")
    creator = lease.get("creator") or {}
    current = process_identity(int(creator.get("pid", -1)))
    same_creator = (
        current.get("alive") is True
        and current.get("creation_token") == creator.get("creation_token")
    )
    if same_creator or current.get("alive") is None:
        status = "owner_busy" if same_creator else "owner_identity_unknown"
        receipt = {
            "schema_version": "windows-test-runtime-recovery-receipt.v2",
            "run_id": run_id,
            "status": status,
            "creator_at_dispatch": creator,
            "creator_now": current,
            "cleanup": None,
            "completed_at": utc_now(),
        }
        _write_run_receipt(managed_root, f"{run_id}.recovery", receipt)
        return receipt
    state = {
        "root": managed_root,
        "run_id": run_id,
        "run_path": run_path,
        "lease_path": lease_path,
        "owner_token": str(lease["owner_token"]),
        "manifest": load_json(run_path / "run-manifest.json"),
    }
    retained = retain_failed_run(
        state,
        "interrupted",
        {"creator_at_dispatch": creator, "creator_now": current},
    )
    receipt = {
        "schema_version": "windows-test-runtime-recovery-receipt.v2",
        "run_id": run_id,
        "status": "interrupted_retained",
        "creator_at_dispatch": creator,
        "creator_now": current,
        "cleanup": None,
        "retention": retained,
        "completed_at": utc_now(),
    }
    _write_run_receipt(managed_root, f"{run_id}.recovery", receipt)
    return receipt


def validate_managed_root_readonly(root: Path | str) -> Path:
    resolved = Path(root).resolve()
    if not _inside(resolved, WORKSPACE_ROOT) or not resolved.is_dir():
        raise ManagedTestRuntimeError(f"managed_test_root_invalid:{resolved}")
    marker = load_json(resolved / ROOT_MARKER)
    checks = {
        "schema": marker.get("schema_version") == "windows-test-managed-root.v1",
        "root": marker.get("managed_root") == str(resolved),
        "hash": marker.get("managed_root_hash") == path_hash(resolved),
        "prefix": marker.get("run_prefix") == RUN_PREFIX,
    }
    if not all(checks.values()):
        raise ManagedTestRuntimeError(f"managed_test_root_marker_invalid:{checks}")
    return resolved


def bounded_tree_stats(path: Path, *, max_nodes: int) -> dict[str, Any]:
    if max_nodes < 1:
        raise ManagedTestRuntimeError("max_nodes_must_be_positive")
    stack = [path]
    nodes = 0
    files = 0
    directories = 0
    total_bytes = 0
    errors: list[str] = []
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    nodes += 1
                    if nodes > max_nodes:
                        errors.append(f"item_node_limit_exceeded:{max_nodes}")
                        return {
                            "nodes": nodes,
                            "files": files,
                            "directories": directories,
                            "bytes": total_bytes,
                            "errors": errors,
                            "complete": False,
                        }
                    try:
                        if entry.is_symlink():
                            errors.append(f"reparse_or_symlink_blocked:{entry.name}")
                        elif entry.is_dir(follow_symlinks=False):
                            directories += 1
                            stack.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            files += 1
                            total_bytes += entry.stat(follow_symlinks=False).st_size
                    except (OSError, PermissionError) as exc:
                        errors.append(f"entry_access_error:{entry.name}:{type(exc).__name__}")
        except (OSError, PermissionError) as exc:
            errors.append(f"directory_access_error:{current.name}:{type(exc).__name__}")
    return {
        "nodes": nodes,
        "files": files,
        "directories": directories,
        "bytes": total_bytes,
        "errors": errors,
        "complete": not errors,
    }


def _bounded_run_directories(root: Path, *, max_items: int) -> list[Path]:
    if not 1 <= max_items <= 1000:
        raise ManagedTestRuntimeError("max_items_out_of_range:1..1000")
    runs: list[Path] = []
    with os.scandir(root) as entries:
        for entry in entries:
            if not entry.name.startswith(RUN_PREFIX):
                continue
            if entry.is_symlink():
                raise ManagedTestRuntimeError(f"test_cache_reparse_blocked:{entry.name}")
            if not entry.is_dir(follow_symlinks=False):
                continue
            runs.append(Path(entry.path))
            if len(runs) > max_items:
                raise ManagedTestRuntimeError(f"test_cache_item_limit_exceeded:{max_items}")
    return sorted(runs, key=lambda item: item.name)


def build_test_cache_manifest(
    root: Path | str,
    *,
    max_items: int = 100,
    max_nodes_per_item: int = 10000,
    now: datetime | None = None,
) -> dict[str, Any]:
    managed_root = validate_managed_root_readonly(root)
    core = load_artifact_core()
    current = now or datetime.now(UTC)
    artifacts: list[dict[str, Any]] = []
    scan_errors: list[str] = []
    for run_path in _bounded_run_directories(managed_root, max_items=max_items):
        run_id = run_path.name
        try:
            manifest = load_json(run_path / "run-manifest.json")
            lease = load_json(managed_root / "_leases" / f"{run_id}.json")
            if manifest.get("run_id") != run_id or lease.get("run_id") != run_id:
                raise ManagedTestRuntimeError("run_identity_mismatch")
            if manifest.get("managed_root_hash") != path_hash(managed_root):
                raise ManagedTestRuntimeError("run_root_hash_mismatch")
            owner_token = str(lease.get("owner_token", ""))
            if not owner_token:
                raise ManagedTestRuntimeError("run_owner_token_missing")
            _validate_owned_run(managed_root, run_path, owner_token)
            retention = manifest.get("retention") or {}
            delete_after = retention.get("delete_after")
            pin = retention.get("pin") is True
            expired = bool(delete_after and parse_utc(str(delete_after)) <= current and not pin)
            lifecycle_state = (
                "expired"
                if expired
                else "failed"
                if manifest.get("status") == "retained_failure"
                else "locked"
            )
            stats = bounded_tree_stats(run_path, max_nodes=max_nodes_per_item)
            scan_errors.extend(f"{run_id}:{error}" for error in stats["errors"])
            receipt_path = managed_root / "_receipts" / f"{run_id}.json"
            receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest() if receipt_path.is_file() else None
            command_contract = manifest.get("command_contract") or {}
            identity = run_path.stat(follow_symlinks=False)
            artifacts.append(
                {
                    "artifact_id": run_id,
                    "closure_run_id": run_id,
                    "producer_tool_id": "windows-test-runtime",
                    "owner_lane": "local-tools",
                    "path": run_id,
                    "artifact_role": "cache_build_test_temp",
                    "digest": {
                        "algorithm": "sha256",
                        "value": canonical_sha256(
                            {
                                "manifest": manifest,
                                "lease_token_sha256": lease.get("owner_token_sha256"),
                                "receipt_sha256": receipt_sha,
                                "tree": stats,
                            }
                        ),
                    },
                    "bytes": stats["bytes"],
                    "lifecycle_state": lifecycle_state,
                    "storage_state": "present",
                    "depends_on": [command_contract.get("sha256")] if command_contract.get("sha256") else [],
                    "referenced_by": [],
                    "sensitivity": "runtime_state",
                    "rebuild_proof": {
                        "status": "verified" if command_contract.get("sha256") else "missing",
                        "command": command_contract.get("executable"),
                        "input_hashes": [command_contract.get("sha256")] if command_contract.get("sha256") else [],
                        "dependency_lock": "windows-test-runtime-contract",
                        "verification_ref": str(receipt_path) if receipt_path.is_file() else None,
                    },
                    "minimum_keep_until": delete_after,
                    "pin": pin,
                    "file_identity": {
                        "device": str(identity.st_dev),
                        "inode": str(identity.st_ino),
                        "hardlink_count": 1,
                        "observed_links": 1,
                    },
                    "test_cache": {
                        "run_status": manifest.get("status"),
                        "retention": retention,
                        "tree": stats,
                        "receipt_ref": str(receipt_path) if receipt_path.is_file() else None,
                    },
                }
            )
        except (OSError, PermissionError, ManagedTestRuntimeError, ValueError) as exc:
            scan_errors.append(f"{run_id}:blocked:{type(exc).__name__}:{exc}")
    payload = {
        "schema_version": core.SCHEMA_VERSION,
        "adapter_schema_version": TEST_CACHE_MANIFEST_SCHEMA,
        "status": "ok",
        "manifest_id": f"test-cache-{canonical_sha256([item['artifact_id'] for item in artifacts])[:16]}",
        "closure_run_id": "test-cache-bounded-scan",
        "producer_tool_id": "windows-test-runtime",
        "owner_lane": "local-tools",
        "root_identity": core.directory_identity(managed_root),
        "profile_id": "test_cache",
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "scan": {
            "root": str(managed_root),
            "root_count": 1,
            "item_limit": max_items,
            "node_limit_per_item": max_nodes_per_item,
            "item_count": len(artifacts),
            "errors": scan_errors,
            "bounded_sort": "run_id_after_bounded_collection",
        },
        "artifacts": artifacts,
    }
    return core.attach_hash(payload, "manifest_sha256")


def explain_test_cache_run(
    root: Path | str,
    run_id: str,
    *,
    max_items: int = 100,
    max_nodes_per_item: int = 10000,
) -> dict[str, Any]:
    manifest = build_test_cache_manifest(
        root, max_items=max_items, max_nodes_per_item=max_nodes_per_item
    )
    for item in manifest["artifacts"]:
        if item["artifact_id"] == run_id:
            return {
                "schema_version": "windows-test-runtime-test-cache-explain.v1",
                "status": "ok",
                "artifact": item,
                "scan_errors": manifest["scan"]["errors"],
                "execution_authorized": False,
            }
    raise ManagedTestRuntimeError(f"test_cache_run_not_found:{run_id}")


def plan_test_cache_quarantine(
    root: Path | str,
    quarantine_root: Path | str,
    *,
    max_items: int = 100,
    max_nodes_per_item: int = 10000,
) -> tuple[dict[str, Any], dict[str, Any]]:
    managed_root = validate_managed_root_readonly(root)
    quarantine = Path(quarantine_root).resolve()
    manifest = build_test_cache_manifest(
        managed_root, max_items=max_items, max_nodes_per_item=max_nodes_per_item
    )
    core = load_artifact_core()
    plan = core.plan_operation(
        manifest,
        managed_root,
        quarantine,
        "quarantine",
        owner_state="idle_confirmed",
        process_state="idle_confirmed",
        dispatch_state="none_active",
    )
    return manifest, plan


def pin_latest_failure(root: Path | str, *, max_items: int = 100) -> dict[str, Any]:
    managed_root = validate_managed_root_readonly(root)
    candidates: list[tuple[datetime, Path, dict[str, Any], dict[str, Any]]] = []
    for run_path in _bounded_run_directories(managed_root, max_items=max_items):
        manifest = load_json(run_path / "run-manifest.json")
        retention = manifest.get("retention") or {}
        if manifest.get("status") != "retained_failure" or retention.get("pin") is True:
            continue
        retained_at = parse_utc(str(retention.get("retained_at")))
        lease_path = managed_root / "_leases" / f"{run_path.name}.json"
        lease = load_json(lease_path)
        candidates.append((retained_at, run_path, manifest, lease))
    if not candidates:
        raise ManagedTestRuntimeError("no_unpinned_retained_failure")
    _, run_path, manifest, lease = max(candidates, key=lambda item: item[0])
    owner_token = str(lease.get("owner_token", ""))
    _validate_owned_run(managed_root, run_path, owner_token)
    receipt_path = managed_root / "_receipts" / f"{run_path.name}.json"
    receipt = load_json(receipt_path)
    child_gate = _child_exit_gate(receipt.get("details") or {})
    if child_gate["status"] in {"blocked_active_child", "blocked_identity_unknown"}:
        raise ManagedTestRuntimeError(f"pin_blocked:{child_gate['status']}")
    manifest["retention"]["pin"] = True
    lease["retention"]["pin"] = True
    atomic_write_json(run_path / "run-manifest.json", manifest)
    atomic_write_json(managed_root / "_leases" / f"{run_path.name}.json", lease)
    pin_receipt = {
        "schema_version": "windows-test-runtime-pin-receipt.v1",
        "run_id": run_path.name,
        "status": "pinned",
        "pinned_at": utc_now(),
        "execution_authorized": False,
    }
    _write_run_receipt(managed_root, f"{run_path.name}.pin", pin_receipt)
    return pin_receipt


def doctor(root: Path | str | None = None) -> dict[str, Any]:
    managed_root = resolve_managed_root(root)
    acl = probe_acl(managed_root)
    state = create_managed_run(
        purpose="windows-test-runtime-doctor", profile="doctor", root=managed_root
    )
    run_path = state["run_path"]
    environment = managed_environment(run_path, "doctor")
    acl_gate = acl_regression_gate(run_path, environment)
    pycache_probe = run_path / "pycache" / "doctor.pyc"
    pycache_status: dict[str, Any]
    try:
        py_compile.compile(__file__, cfile=str(pycache_probe), doraise=True)
        pycache_status = {
            "status": "passed",
            "path_inside_run": _inside(pycache_probe, run_path),
            "exists": pycache_probe.is_file(),
            "error": None,
        }
    except (OSError, PermissionError, py_compile.PyCompileError) as exc:
        pycache_status = {
            "status": "failed",
            "path_inside_run": _inside(pycache_probe, run_path),
            "exists": pycache_probe.is_file(),
            "error": f"{type(exc).__name__}: {exc}",
        }
    status = (
        "passed"
        if acl["status"] == pycache_status["status"] == acl_gate["status"] == "passed"
        else "blocked"
    )
    receipt = _finish_run(
        state,
        status,
        {
            "acl": acl,
            "acl_regression_gate": acl_gate,
            "failure_class": (
                acl_gate.get("failure_class")
                if acl_gate["status"] != "passed"
                else "temp_directory_acl" if acl["status"] != "passed" or pycache_status["status"] != "passed" else None
            ),
            "failure_policy": (
                failure_policy(str(acl_gate.get("failure_class")))
                if acl_gate["status"] != "passed"
                else failure_policy("temp_directory_acl") if acl["status"] != "passed" or pycache_status["status"] != "passed" else None
            ),
            "pycache": pycache_status,
            "environment": {
                name: environment[name]
                for name in (
                    "TEMP", "TMP", "TMPDIR", "TEST_TMP_ROOT", "PYTHONPYCACHEPREFIX",
                    "npm_config_cache", "XDG_CACHE_HOME", "JEST_CACHE_DIRECTORY", "VITEST_CACHE_DIR",
                )
            },
            "scan_exclusions": scan_exclusion_contract(managed_root),
        },
    )
    return receipt


def should_exclude_scan_path(path: Path, *, managed_root: Path) -> tuple[bool, str | None]:
    resolved = path.resolve()
    managed = managed_root.resolve()
    if resolved == managed or _inside(resolved, managed):
        marker = managed / ROOT_MARKER
        if marker.is_file():
            return True, "marked_managed_test_root"
    if path.name in SAFE_CACHE_NAMES:
        return True, "exact_generated_cache_name"
    return False, None


def governance_scan(scan_root: Path, *, managed_root: Path) -> dict[str, Any]:
    scan_root = scan_root.resolve()
    managed_root = managed_root.resolve()
    visited_files: list[str] = []
    excluded_directories: list[dict[str, str]] = []
    errors: list[str] = []
    for current, directories, files in os.walk(scan_root, topdown=True, onerror=lambda exc: errors.append(str(exc))):
        current_path = Path(current)
        retained: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            excluded, reason = should_exclude_scan_path(candidate, managed_root=managed_root)
            if excluded:
                excluded_directories.append(
                    {"path": str(candidate.relative_to(scan_root)), "reason": str(reason)}
                )
            else:
                retained.append(name)
        directories[:] = retained
        for name in sorted(files):
            visited_files.append(str((current_path / name).relative_to(scan_root)))
    return {
        "schema_version": "windows-test-governance-scan-receipt.v1",
        "scan_root": str(scan_root),
        "managed_root": str(managed_root),
        "visited_files": visited_files,
        "excluded_directories": excluded_directories,
        "errors": errors,
        "contract": scan_exclusion_contract(managed_root),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    doctor_parser = subparsers.add_parser("doctor")
    doctor_parser.add_argument("--root")
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--root")
    run_parser.add_argument("--cwd")
    run_parser.add_argument("--purpose", required=True)
    run_parser.add_argument("--profile", default="generic")
    run_parser.add_argument("--timeout-seconds", type=float, default=300.0)
    run_parser.add_argument("test_command", nargs=argparse.REMAINDER)
    adapter_parser = subparsers.add_parser("adapter")
    adapter_parser.add_argument("--root")
    adapter_parser.add_argument("--cwd", required=True)
    adapter_parser.add_argument("--purpose", required=True)
    adapter_parser.add_argument("--adapter", required=True, choices=sorted(SUPPORTED_ADAPTERS - {"generic"}))
    adapter_parser.add_argument("--executable")
    adapter_parser.add_argument("--timeout-seconds", type=float, default=300.0)
    adapter_parser.add_argument("adapter_args", nargs=argparse.REMAINDER)
    recover_parser = subparsers.add_parser("recover")
    recover_parser.add_argument("--root")
    recover_parser.add_argument("--run-id", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--root", required=True)
    scan_parser.add_argument("--managed-root", required=True)
    test_cache_parser = subparsers.add_parser("test-cache")
    test_cache_actions = test_cache_parser.add_subparsers(dest="test_cache_action", required=True)
    test_cache_scan = test_cache_actions.add_parser("scan")
    test_cache_scan.add_argument("--root", required=True)
    test_cache_scan.add_argument("--max-items", type=int, default=100)
    test_cache_scan.add_argument("--max-nodes-per-item", type=int, default=10000)
    test_cache_scan.add_argument("--output")
    test_cache_explain = test_cache_actions.add_parser("explain")
    test_cache_explain.add_argument("--root", required=True)
    test_cache_explain.add_argument("--run-id", required=True)
    test_cache_explain.add_argument("--max-items", type=int, default=100)
    test_cache_explain.add_argument("--max-nodes-per-item", type=int, default=10000)
    test_cache_plan = test_cache_actions.add_parser("plan")
    test_cache_plan.add_argument("--root", required=True)
    test_cache_plan.add_argument("--quarantine-root", required=True)
    test_cache_plan.add_argument("--max-items", type=int, default=100)
    test_cache_plan.add_argument("--max-nodes-per-item", type=int, default=10000)
    test_cache_plan.add_argument("--manifest-output")
    test_cache_plan.add_argument("--plan-output")
    test_cache_pin = test_cache_actions.add_parser("pin-latest-failure")
    test_cache_pin.add_argument("--root", required=True)
    test_cache_pin.add_argument("--max-items", type=int, default=100)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "doctor":
            payload = doctor(args.root)
        elif args.command == "recover":
            payload = recover_run(args.run_id, root=args.root)
        elif args.command == "scan":
            payload = governance_scan(Path(args.root), managed_root=Path(args.managed_root))
        elif args.command == "test-cache":
            if args.test_cache_action == "scan":
                payload = build_test_cache_manifest(
                    args.root,
                    max_items=args.max_items,
                    max_nodes_per_item=args.max_nodes_per_item,
                )
                if args.output:
                    atomic_write_json(Path(args.output).resolve(), payload)
            elif args.test_cache_action == "explain":
                payload = explain_test_cache_run(
                    args.root,
                    args.run_id,
                    max_items=args.max_items,
                    max_nodes_per_item=args.max_nodes_per_item,
                )
            elif args.test_cache_action == "plan":
                manifest, plan = plan_test_cache_quarantine(
                    args.root,
                    args.quarantine_root,
                    max_items=args.max_items,
                    max_nodes_per_item=args.max_nodes_per_item,
                )
                if args.manifest_output:
                    atomic_write_json(Path(args.manifest_output).resolve(), manifest)
                if args.plan_output:
                    atomic_write_json(Path(args.plan_output).resolve(), plan)
                payload = {
                    "schema_version": "windows-test-runtime-test-cache-plan-result.v1",
                    "status": "ok",
                    "manifest": manifest,
                    "plan": plan,
                    "execution_authorized": False,
                }
            else:
                payload = pin_latest_failure(args.root, max_items=args.max_items)
        elif args.command == "adapter":
            adapter_args = list(args.adapter_args)
            if adapter_args and adapter_args[0] == "--":
                adapter_args = adapter_args[1:]
            payload = run_adapter(
                args.adapter,
                purpose=args.purpose,
                arguments=adapter_args,
                timeout_seconds=args.timeout_seconds,
                cwd=Path(args.cwd).resolve(),
                root=args.root,
                executable=args.executable,
            )
        else:
            command = list(args.test_command)
            if command and command[0] == "--":
                command = command[1:]
            payload = run_command(
                command,
                purpose=args.purpose,
                profile=args.profile,
                timeout_seconds=args.timeout_seconds,
                cwd=Path(args.cwd).resolve() if args.cwd else None,
                root=args.root,
            )
    except ManagedTestRuntimeError as exc:
        failure_class = "temp_directory_acl" if isinstance(exc, TempDirectoryAclError) else "unclassified_failure"
        payload = {
            "schema_version": "windows-test-runtime-error.v3",
            "status": "blocked",
            "error": str(exc),
            "failure_class": failure_class,
            "signal_code": "WINERROR_5_TEMP" if failure_class == "temp_directory_acl" else "UNKNOWN",
            "failure_policy": failure_policy(failure_class),
            "execution_authorized": False,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        return 2
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if payload.get("status") in {"passed", "recovered", "ok", "pinned", "interrupted_retained"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
