from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any


DISPATCH_ID = "ARTIFACT-GLOBAL-REGISTRY-AUDIT-20260829-01"
SCHEMA_VERSION = "artifact-global-registry-audit.v1"
ROOT = Path(__file__).resolve().parents[1]
CORE_ROOT = Path(__file__).resolve().parent
DEFAULT_REGISTRY = ROOT / "tool-registry.json"
DEFAULT_INVENTORY = ROOT / "source-reviews" / "SOURCE_INVENTORY.json"
DEFAULT_DECLARATIONS = CORE_ROOT / "registry-lifecycle-declarations.v1.json"
DEFAULT_PROFILES = CORE_ROOT / "profiles" / "artifact-lifecycle-profiles.v1.json"
REUSED_AUDITOR = ROOT / "outputs" / "artifact-retention-audit-20260823" / "artifact_retention_audit.py"
LARGE_PROFILES = {"media", "document_render", "build_dist"}
MIN_FREE_BYTES = 512 * 1024 ** 2
MIN_OUTPUT_HEADROOM_MULTIPLIER = 1.0
NO_MANAGED_ARTIFACT_STATUSES = {
    "not_applicable_protected_state_only",
    "not_applicable_no_managed_artifacts",
}
SOURCE_INVENTORY_REQUIRED_FIELDS = {
    "name",
    "repo_url",
    "local_path",
    "commit",
    "cloned_at",
    "reviewed_at",
    "review_status",
    "integration_status",
    "registry_tool_id",
    "deployment_path",
    "evidence_docs",
    "evidence_link_status",
    "precise_missing_reason",
    "missing_path_status",
    "owner_thread",
    "notes",
    "next_action",
}
VOLATILE_KEYS = {
    "checked_at",
    "generated_at",
    "started_at",
    "completed_at",
    "last_checkpoint_at",
    "duration_seconds",
    "resume_status",
    "candidate_scan_status",
}


def now_iso() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def load_json(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def canonicalize(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: canonicalize(item) for key, item in sorted(value.items()) if key not in VOLATILE_KEYS}
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    return value


def content_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(canonicalize(value)).encode("utf-8")).hexdigest()


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    try:
        temporary.write_text(data, encoding="utf-8", newline="\n")
        if temporary.read_text(encoding="utf-8") != data:
            raise OSError("atomic_write_readback_mismatch")
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def _profiles(path: Path) -> set[str]:
    payload = load_json(path)
    return {str(item["profile_id"]) for item in payload.get("profiles", []) if isinstance(item, dict)}


def validate_declarations(
    registry: dict[str, Any], declarations: dict[str, Any], profiles_path: Path = DEFAULT_PROFILES
) -> list[str]:
    errors: list[str] = []
    tools = registry.get("tools")
    declared = declarations.get("tools")
    if not isinstance(tools, dict):
        return ["registry_tools_object_required"]
    if not isinstance(declared, dict):
        return ["declaration_tools_object_required"]
    missing = sorted(set(tools) - set(declared))
    extra = sorted(set(declared) - set(tools))
    if missing:
        errors.append("missing_tool_declarations:" + ",".join(missing))
    if extra:
        errors.append("unknown_tool_declarations:" + ",".join(extra))
    allowed_profiles = _profiles(profiles_path)
    for tool_id in sorted(set(tools) & set(declared)):
        item = declared[tool_id]
        if not isinstance(item, dict):
            errors.append(f"{tool_id}:declaration_object_required")
            continue
        has_profile = isinstance(item.get("lifecycle_profile"), str)
        no_artifacts = item.get("no_managed_artifacts") is True
        blocked_missing = item.get("blocked_missing_declaration") is True
        if sum((has_profile, no_artifacts, blocked_missing)) != 1:
            errors.append(f"{tool_id}:exactly_one_lifecycle_profile_no_managed_or_blocked_required")
        if has_profile and item["lifecycle_profile"] not in allowed_profiles:
            errors.append(f"{tool_id}:unknown_lifecycle_profile:{item['lifecycle_profile']}")
        if item.get("cleanup_mode") != "plan_only":
            errors.append(f"{tool_id}:cleanup_mode_must_be_plan_only")
        if item.get("automatic_purge") is not False:
            errors.append(f"{tool_id}:automatic_purge_must_be_false")
        if not item.get("owner_lane"):
            errors.append(f"{tool_id}:owner_lane_required")
        if not item.get("protected_roles"):
            errors.append(f"{tool_id}:protected_roles_required")
        if blocked_missing:
            if item.get("adapter_status") != "blocked_missing_declaration":
                errors.append(f"{tool_id}:blocked_declaration_status_required")
            if not item.get("source_projection_errors"):
                errors.append(f"{tool_id}:blocked_declaration_errors_required")
        elif has_profile:
            for field in ("artifact_roots", "authoritative_paths", "doctor", "scan", "plan_gc", "restore"):
                if field not in item:
                    errors.append(f"{tool_id}:{field}_required")
            if item["lifecycle_profile"] in LARGE_PROFILES:
                if item.get("large_output_preflight") is not True:
                    errors.append(f"{tool_id}:large_output_preflight_required")
                minimum_bytes = item.get("minimum_free_bytes")
                warning_bytes = item.get("warning_free_bytes")
                headroom = item.get("output_headroom_multiplier")
                if not isinstance(minimum_bytes, int) or minimum_bytes < MIN_FREE_BYTES:
                    errors.append(f"{tool_id}:minimum_free_bytes_below_512_mib")
                minimum_value = minimum_bytes if isinstance(minimum_bytes, int) else 0
                if not isinstance(warning_bytes, int) or warning_bytes < minimum_value:
                    errors.append(f"{tool_id}:warning_free_bytes_below_minimum")
                if not isinstance(headroom, (int, float)) or headroom < MIN_OUTPUT_HEADROOM_MULTIPLIER:
                    errors.append(f"{tool_id}:output_headroom_multiplier_below_1")
            for root in item.get("artifact_roots", []):
                if root.get("scan_eligible") is True and root.get("status") != "verified_synthetic_fixture":
                    errors.append(f"{tool_id}:scan_eligible_requires_verified_synthetic_fixture")
        elif item.get("adapter_status") not in NO_MANAGED_ARTIFACT_STATUSES:
            errors.append(f"{tool_id}:no_managed_artifacts_requires_not_applicable_status")
    return errors


def declaration_from_registry(tool_id: str, contract: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
    governance = contract.get("artifact_lifecycle_governance")
    has_profile = isinstance(contract.get("lifecycle_profile"), str)
    no_artifacts = contract.get("no_managed_artifacts") is True
    errors: list[str] = []
    if has_profile == no_artifacts:
        errors.append(f"{tool_id}:registry_requires_exactly_one_lifecycle_declaration")
    if not isinstance(governance, dict):
        errors.append(f"{tool_id}:registry_governance_object_required")
    elif governance.get("schema_version") != "registry-artifact-lifecycle.v1":
        errors.append(f"{tool_id}:registry_governance_schema_mismatch")
    if errors:
        return None, errors
    declaration: dict[str, Any] = (
        {"lifecycle_profile": contract["lifecycle_profile"]}
        if has_profile
        else {"no_managed_artifacts": True}
    )
    declaration.update({key: value for key, value in governance.items() if key != "schema_version"})
    validation = validate_declarations(
        {"tools": {tool_id: contract}},
        {"schema_version": "registry-artifact-lifecycle-declarations.v1", "tools": {tool_id: declaration}},
    )
    if validation:
        return None, validation
    return declaration, []


def refresh_declarations(registry_path: Path, declarations_path: Path, output_path: Path) -> dict[str, Any]:
    registry = load_json(registry_path)
    existing = load_json(declarations_path)
    registry_tools = registry.get("tools")
    declared_tools = existing.get("tools")
    if not isinstance(registry_tools, dict) or not isinstance(declared_tools, dict):
        raise ValueError("registry_and_declaration_tools_objects_required")
    extras = sorted(set(declared_tools) - set(registry_tools))
    if extras:
        raise ValueError("unknown_tool_declarations:" + ",".join(extras))

    added: list[str] = []
    updated: list[str] = []
    blocked: list[dict[str, Any]] = []
    refreshed: dict[str, Any] = {}
    for tool_id, contract in registry_tools.items():
        declaration, errors = declaration_from_registry(tool_id, contract)
        if declaration is None:
            governance = contract.get("artifact_lifecycle_governance")
            governance = governance if isinstance(governance, dict) else {}
            declaration = {
                "blocked_missing_declaration": True,
                "owner_lane": governance.get("owner_lane") or "unresolved_owner",
                "cleanup_mode": "plan_only",
                "automatic_purge": False,
                "adapter_status": "blocked_missing_declaration",
                "protected_roles": governance.get("protected_roles") or ["unknown_unclassified"],
                "recovery_entry": "Repair the Registry lifecycle projection and rerun refresh-declarations; no scan or cleanup is allowed.",
                "source_projection_errors": errors,
            }
            blocked.append({"tool_id": tool_id, "declaration": "blocked_missing_declaration", "reasons": errors})
        refreshed[tool_id] = declaration
        if tool_id not in declared_tools:
            added.append(tool_id)
        elif canonical_json(declared_tools[tool_id]) != canonical_json(declaration):
            updated.append(tool_id)

    result = {
        "schema_version": existing.get("schema_version", "registry-artifact-lifecycle-declarations.v1"),
        "tools": refreshed,
    }
    errors = validate_declarations(registry, result)
    if errors:
        raise ValueError("refreshed_declaration_validation_failed:" + ";".join(errors))
    atomic_write_json(output_path, result)
    return {
        "status": "completed_with_blocked_declarations" if blocked else "completed",
        "registry_tool_count": len(registry_tools),
        "declaration_count": len(refreshed),
        "existing_count": len(refreshed) - len(added),
        "added": added,
        "updated": updated,
        "blocked_missing_declaration": blocked,
        "output": str(output_path),
        "output_sha256": sha256_file(output_path),
        "canonical_content_sha256": content_hash(result),
    }


def registry_projection(declaration: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if declaration.get("blocked_missing_declaration") is True:
        raise ValueError("blocked_missing_declaration_has_no_registry_projection")
    direct: dict[str, Any] = {}
    if "lifecycle_profile" in declaration:
        direct["lifecycle_profile"] = declaration["lifecycle_profile"]
    else:
        direct["no_managed_artifacts"] = True
    governance = {
        "schema_version": "registry-artifact-lifecycle.v1",
        **{key: value for key, value in declaration.items() if key not in {"lifecycle_profile", "no_managed_artifacts"}},
    }
    return direct, governance


def apply_registry(
    registry_path: Path,
    declarations_path: Path,
    *,
    expected_sha256: str | None,
    backup_path: Path,
) -> dict[str, Any]:
    before_sha = sha256_file(registry_path)
    if expected_sha256 and before_sha != expected_sha256:
        raise ValueError(f"registry_sha256_drift:{before_sha}")
    registry = load_json(registry_path)
    declarations = load_json(declarations_path)
    errors = validate_declarations(registry, declarations)
    if errors:
        raise ValueError("declaration_validation_failed:" + ";".join(errors))
    blocked = sorted(
        tool_id
        for tool_id, item in declarations.get("tools", {}).items()
        if item.get("blocked_missing_declaration") is True
    )
    if blocked:
        raise ValueError("blocked_declarations_cannot_be_applied:" + ",".join(blocked))
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    if backup_path.exists() and sha256_file(backup_path) != before_sha:
        raise ValueError("backup_path_already_exists_with_different_content")
    if not backup_path.exists():
        shutil.copyfile(registry_path, backup_path)
    for tool_id, contract in registry["tools"].items():
        contract.pop("lifecycle_profile", None)
        contract.pop("no_managed_artifacts", None)
        contract.pop("artifact_lifecycle_governance", None)
        direct, governance = registry_projection(declarations["tools"][tool_id])
        contract.update(direct)
        contract["artifact_lifecycle_governance"] = governance
    core = registry["tools"].get("artifact-lifecycle-core", {})
    if isinstance(core.get("artifact_lifecycle"), dict):
        core["artifact_lifecycle"]["profiles"] = sorted(_profiles(DEFAULT_PROFILES))
    atomic_write_json(registry_path, registry)
    after_sha = sha256_file(registry_path)
    reloaded = load_json(registry_path)
    errors = validate_registry_projection(reloaded, declarations)
    if errors:
        shutil.copyfile(backup_path, registry_path)
        raise ValueError("registry_projection_failed_and_rolled_back:" + ";".join(errors))
    return {
        "ok": True,
        "before_sha256": before_sha,
        "after_sha256": after_sha,
        "backup_path": str(backup_path),
        "tool_count": len(registry["tools"]),
    }


def validate_registry_projection(registry: dict[str, Any], declarations: dict[str, Any]) -> list[str]:
    errors = validate_declarations(registry, declarations)
    tools = registry.get("tools", {})
    for tool_id, expected in declarations.get("tools", {}).items():
        if expected.get("blocked_missing_declaration") is True:
            continue
        actual = tools.get(tool_id, {})
        direct, governance = registry_projection(expected)
        for key, value in direct.items():
            if actual.get(key) != value:
                errors.append(f"{tool_id}:{key}_projection_mismatch")
        if actual.get("artifact_lifecycle_governance") != governance:
            errors.append(f"{tool_id}:artifact_lifecycle_governance_projection_mismatch")
    return errors


def validate_source_inventory_linkage(
    registry: dict[str, Any], inventory: dict[str, Any]
) -> tuple[list[str], dict[str, Any]]:
    """Validate ledger structure and Registry links without probing every source path.

    The PowerShell source-ledger validator deliberately performs filesystem checks for
    every source and evidence path. That is useful for a deep audit, but it can block
    the Local Tools control plane on inaccessible or slow roots. This bounded check
    validates the machine contract and performs path checks only for this core's own
    authoritative linkage.
    """
    errors: list[str] = []
    entries = inventory.get("entries")
    registry_tools = registry.get("tools")
    if inventory.get("schema_version") != 1:
        errors.append("source_inventory_schema_version_must_be_1")
    if not isinstance(entries, list):
        return [*errors, "source_inventory_entries_array_required"], {
            "entry_count": 0,
            "registry_linked_entry_count": 0,
            "artifact_lifecycle_core_linked": False,
        }
    if not isinstance(registry_tools, dict):
        return [*errors, "registry_tools_object_required"], {
            "entry_count": len(entries),
            "registry_linked_entry_count": 0,
            "artifact_lifecycle_core_linked": False,
        }

    linked_count = 0
    core_entries: list[dict[str, Any]] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"source_inventory_entry_{index}:object_required")
            continue
        missing = sorted(SOURCE_INVENTORY_REQUIRED_FIELDS - set(entry))
        if missing:
            errors.append(f"source_inventory_entry_{index}:missing_fields:{','.join(missing)}")
        registry_tool_id = entry.get("registry_tool_id")
        if registry_tool_id:
            linked_count += 1
            if registry_tool_id not in registry_tools:
                errors.append(f"source_inventory_entry_{index}:unknown_registry_tool_id:{registry_tool_id}")
        if registry_tool_id == "artifact-lifecycle-core":
            core_entries.append(entry)

    if len(core_entries) != 1:
        errors.append(f"artifact_lifecycle_core_source_entry_count_must_be_1:{len(core_entries)}")
        core_linked = False
    else:
        core = core_entries[0]
        expected_root = CORE_ROOT.resolve(strict=False)
        source_path = Path(str(core.get("local_path", ""))).resolve(strict=False)
        deployment_path = Path(str(core.get("deployment_path", ""))).resolve(strict=False)
        evidence_docs = core.get("evidence_docs")
        core_linked = True
        if core.get("integration_status") != "integrated_local_tool":
            errors.append("artifact_lifecycle_core:integration_status_must_be_integrated_local_tool")
            core_linked = False
        if core.get("evidence_link_status") != "linked":
            errors.append("artifact_lifecycle_core:evidence_link_status_must_be_linked")
            core_linked = False
        if source_path != expected_root or deployment_path != expected_root:
            errors.append("artifact_lifecycle_core:source_or_deployment_path_mismatch")
            core_linked = False
        if not expected_root.is_dir():
            errors.append("artifact_lifecycle_core:authoritative_root_missing")
            core_linked = False
        if not isinstance(evidence_docs, list) or not evidence_docs:
            errors.append("artifact_lifecycle_core:evidence_docs_required")
            core_linked = False

    return errors, {
        "entry_count": len(entries),
        "registry_linked_entry_count": linked_count,
        "artifact_lifecycle_core_linked": core_linked,
        "validation_scope": "structure_registry_refs_and_core_authority_only",
        "all_entry_filesystem_probe": False,
    }


def resolve_ref(tool_contract: dict[str, Any], path_ref: str) -> Path:
    normalized = path_ref.replace("/", os.sep)
    if normalized == "$tool_root" or normalized.startswith("$tool_root" + os.sep):
        root = Path(str(tool_contract.get("path", "")))
        if root.is_file() or root.suffix:
            root = root.parent
        suffix = normalized[len("$tool_root") :].lstrip("\\/")
        return (root / suffix).resolve(strict=False)
    return Path(normalized).resolve(strict=False)


def is_safe_scan_root(path: Path) -> bool:
    try:
        path.relative_to(ROOT)
    except ValueError:
        return False
    return path != ROOT and not path.is_symlink()


def _load_reused_auditor() -> Any:
    spec = importlib.util.spec_from_file_location("artifact_retention_audit_reused", REUSED_AUDITOR)
    if spec is None or spec.loader is None:
        raise RuntimeError("reused_auditor_import_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def bounded_preflight(path: Path, *, max_nodes: int, max_depth: int) -> dict[str, int]:
    stack = [(path, 0)]
    nodes = 0
    files = 0
    directories = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes:
            raise RuntimeError("root_item_limit_exceeded")
        if current.is_symlink():
            raise RuntimeError("root_reparse_or_symlink_blocked")
        if current.is_dir():
            directories += 1
            if depth >= max_depth:
                raise RuntimeError("root_depth_limit_exceeded")
            with os.scandir(current) as entries:
                for entry in entries:
                    if entry.is_symlink():
                        raise RuntimeError("root_reparse_or_symlink_blocked")
                    stack.append((Path(entry.path), depth + 1))
        else:
            files += 1
    return {"nodes": nodes, "files": files, "directories": directories}


def scan_root_worker(
    root: Path,
    tool_id: str,
    output: Path,
    max_nodes: int,
    max_depth: int,
    dispatch_id: str = DISPATCH_ID,
) -> dict[str, Any]:
    auditor = _load_reused_auditor()
    output.mkdir(parents=True, exist_ok=True)
    checkpoint = output / "root-checkpoint.json"
    database = output / "artifact-inventory-state.sqlite3"
    first_run = not database.exists()
    try:
        preflight = bounded_preflight(root, max_nodes=max_nodes, max_depth=max_depth)
    except PermissionError:
        result = {"status": "blocked_access_denied", "error_class": "AccessDenied", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
        atomic_write_json(checkpoint, {"schema_version": "artifact-global-root-checkpoint.v1", "dispatch_id": dispatch_id, "tool_id": tool_id, "status": result["status"], "checked_at": now_iso()})
        return result
    except OSError as error:
        result = {"status": "blocked_scan_error", "error_class": type(error).__name__, "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
        atomic_write_json(checkpoint, {"schema_version": "artifact-global-root-checkpoint.v1", "dispatch_id": dispatch_id, "tool_id": tool_id, "status": result["status"], "checked_at": now_iso()})
        return result
    connection = auditor.init_database(database)
    root_id = "root-" + hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
    root_row = {"root_id": root_id, "path": str(root), "mode": "self", "root_kind": "registry_verified_synthetic_fixture", "tool_id": tool_id}
    try:
        with connection:
            connection.execute(
                "INSERT OR REPLACE INTO roots(root_id,path,mode,root_kind,tool_id,status,started_at,candidate_count) VALUES (?,?,?,?,?,?,?,?)",
                (root_id, str(root), "self", root_row["root_kind"], tool_id, "scanning", now_iso(), 1),
            )
        scan_result = auditor.scan_candidate(
            connection,
            root_row,
            root,
            [],
            {"hash_manifest_max_bytes": 1024 * 1024},
        )
        error_count = int(connection.execute("SELECT COUNT(*) FROM scan_errors WHERE root_id=?", (root_id,)).fetchone()[0])
        with connection:
            connection.execute(
                "UPDATE roots SET status='completed',completed_at=?,error_count=? WHERE root_id=?",
                (now_iso(), error_count, root_id),
            )
        totals = connection.execute(
            "SELECT COALESCE(SUM(logical_bytes),0),COALESCE(SUM(file_count),0),COALESCE(SUM(dir_count),0) FROM units"
        ).fetchone()
        physical = auditor.physical_by_unit(connection)
        incomplete = sum(int(item.get("incomplete_link_entities", 0)) for item in physical.values())
        lower = 0 if incomplete else sum(int(item.get("lower", 0)) for item in physical.values())
        result = {
            "status": "completed_with_errors" if error_count else "completed",
            "resume_status": "fresh_scan" if first_run else "resumed_from_sqlite_checkpoint",
            "candidate_scan_status": scan_result.get("status", "completed"),
            "logical_bytes": int(totals[0]),
            "file_count": int(totals[1]),
            "directory_count": int(totals[2]),
            "observed_reclaim_lower_bound_bytes": int(lower),
            "incomplete_hardlink_entity_count": incomplete,
            "scan_error_count": error_count,
            "bounded_preflight": preflight,
        }
    finally:
        connection.close()
    atomic_write_json(
        checkpoint,
        {
            "schema_version": "artifact-global-root-checkpoint.v1",
            "dispatch_id": dispatch_id,
            "tool_id": tool_id,
            "status": result["status"],
            "checked_at": now_iso(),
            "observed": {key: result[key] for key in ("logical_bytes", "file_count", "directory_count", "observed_reclaim_lower_bound_bytes", "incomplete_hardlink_entity_count")},
            "boundary": "Read-only metadata checkpoint; no real artifact mutation.",
        },
    )
    return result


def adapter_rule_counts(tool_contract: dict[str, Any], root_decl: dict[str, Any]) -> tuple[int, int, str]:
    ref = root_decl.get("adapter_contract_ref")
    if not ref:
        return 0, 0, "adapter_contract_not_declared"
    path = resolve_ref(tool_contract, str(ref))
    if not path.is_file():
        return 0, 0, "adapter_contract_missing"
    try:
        payload = load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return 0, 0, "adapter_contract_unreadable"
    rules = payload.get("rules")
    if isinstance(rules, list):
        candidates = sum(isinstance(item, dict) and item.get("pin") is False for item in rules)
        protected = sum(isinstance(item, dict) and item.get("pin") is not False for item in rules)
        return int(candidates), int(protected), "rule_counts_from_adapter_contract"
    candidate_paths = payload.get("candidate_paths")
    protected_paths = payload.get("protected_paths")
    if isinstance(candidate_paths, list) and isinstance(protected_paths, dict):
        return len(candidate_paths), len(protected_paths), "rule_counts_from_adapter_contract"
    return 0, 0, "adapter_contract_has_no_static_rule_counts"


def invoke_root_worker(
    tool_id: str,
    root_path: Path,
    output: Path,
    *,
    timeout_seconds: int,
    max_nodes: int,
    max_depth: int,
    dispatch_id: str = DISPATCH_ID,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "_scan-root",
        "--root",
        str(root_path),
        "--tool-id",
        tool_id,
        "--output",
        str(output),
        "--max-nodes",
        str(max_nodes),
        "--max-depth",
        str(max_depth),
        "--dispatch-id",
        dispatch_id,
    ]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return {"status": "blocked_timeout", "error_class": "RootTimeout", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
    except PermissionError:
        return {"status": "blocked_access_denied", "error_class": "AccessDenied", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
    if completed.returncode != 0:
        return {"status": "blocked_worker_error", "error_class": "WorkerNonZeroExit", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
    try:
        return json.loads(completed.stdout.strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError):
        return {"status": "blocked_worker_invalid_json", "error_class": "WorkerInvalidJson", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}


def audit_registry(
    registry_path: Path,
    inventory_path: Path,
    declarations_path: Path,
    output: Path,
    *,
    timeout_seconds: int,
    max_nodes: int,
    max_depth: int,
    dispatch_id: str = DISPATCH_ID,
) -> dict[str, Any]:
    registry = load_json(registry_path)
    declarations = load_json(declarations_path)
    errors = validate_registry_projection(registry, declarations)
    if errors:
        raise ValueError("registry_lifecycle_projection_invalid:" + ";".join(errors))
    tools_report: list[dict[str, Any]] = []
    for tool_id in sorted(registry["tools"]):
        tool_contract = registry["tools"][tool_id]
        declaration = declarations["tools"][tool_id]
        declaration_kind = (
            "blocked_missing_declaration"
            if declaration.get("blocked_missing_declaration")
            else ("no_managed_artifacts" if declaration.get("no_managed_artifacts") else "lifecycle_profile")
        )
        item: dict[str, Any] = {
            "tool_id": tool_id,
            "producer_tool_id": tool_id,
            "owner_lane": declaration["owner_lane"],
            "declaration": declaration_kind,
            "lifecycle_profile": declaration.get("lifecycle_profile"),
            "adapter_status": declaration["adapter_status"],
            "cleanup_mode": declaration["cleanup_mode"],
            "automatic_purge": False,
            "protected_roles": declaration["protected_roles"],
            "recovery_entry": declaration["recovery_entry"],
            "roots": [],
            "logical_bytes": 0,
            "file_count": 0,
            "directory_count": 0,
            "candidate_count": 0,
            "protected_count": 0,
            "estimated_releasable_lower_bound_bytes": 0,
            "blockers": [],
        }
        if declaration.get("blocked_missing_declaration"):
            item["status"] = "blocked_missing_declaration"
            item["blockers"] = list(declaration.get("source_projection_errors", []))
            tools_report.append(item)
            continue
        if declaration.get("no_managed_artifacts"):
            item["status"] = "not_applicable_no_managed_artifacts"
            item["blockers"] = ["protected_state_only", "no_cleanup_scope"]
            tools_report.append(item)
            continue
        roots = declaration.get("artifact_roots", [])
        eligible = [root for root in roots if root.get("scan_eligible") is True]
        if not eligible:
            item["status"] = "blocked_pending_or_owner_scoped_adapter"
            item["blockers"] = [declaration["adapter_status"], "no_verified_synthetic_audit_root"]
            tools_report.append(item)
            continue
        root_results = []
        for index, root_decl in enumerate(eligible, start=1):
            root_path = resolve_ref(tool_contract, root_decl["path_ref"])
            candidate_count, protected_count, count_basis = adapter_rule_counts(tool_contract, root_decl)
            root_item: dict[str, Any] = {
                "path_ref": root_decl["path_ref"],
                "status": "pending",
                "candidate_count": candidate_count,
                "protected_count": protected_count,
                "classification_basis": count_basis,
                "checkpoint_ref": f"roots/{tool_id}-{index}/root-checkpoint.json",
            }
            if not is_safe_scan_root(root_path):
                scan = {"status": "blocked_outside_safe_workspace_or_reparse", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
            elif not root_path.exists():
                scan = {"status": "blocked_root_missing", "logical_bytes": 0, "file_count": 0, "directory_count": 0, "observed_reclaim_lower_bound_bytes": 0, "incomplete_hardlink_entity_count": 0}
            else:
                scan = invoke_root_worker(
                    tool_id,
                    root_path,
                    output / "roots" / f"{tool_id}-{index}",
                    timeout_seconds=timeout_seconds,
                    max_nodes=max_nodes,
                    max_depth=max_depth,
                    dispatch_id=dispatch_id,
                )
            root_item.update(scan)
            root_item["estimated_releasable_lower_bound_bytes"] = 0
            root_item["release_lower_bound_reason"] = "synthetic_fixture_only_or_real_mutation_not_authorized"
            root_results.append(root_item)
            item["logical_bytes"] += int(scan.get("logical_bytes", 0))
            item["file_count"] += int(scan.get("file_count", 0))
            item["directory_count"] += int(scan.get("directory_count", 0))
            item["candidate_count"] += candidate_count
            item["protected_count"] += protected_count
        item["roots"] = root_results
        failed = [root for root in root_results if not str(root.get("status", "")).startswith("completed")]
        item["status"] = "read_only_fixture_audit_complete" if not failed else "partial_with_isolated_root_failures"
        item["blockers"] = ["real_mutation_not_authorized", "synthetic_fixture_only"]
        item["blockers"].extend(sorted({str(root["status"]) for root in failed}))
        tools_report.append(item)
    summary = {
        "registry_tool_count": len(tools_report),
        "declaration_coverage_count": len(tools_report),
        "lifecycle_profile_count": sum(item["declaration"] == "lifecycle_profile" for item in tools_report),
        "no_managed_artifacts_count": sum(item["declaration"] == "no_managed_artifacts" for item in tools_report),
        "blocked_missing_declaration_count": sum(item["declaration"] == "blocked_missing_declaration" for item in tools_report),
        "verified_owner_adapter_count": sum(item["adapter_status"] == "verified_owner_adapter" for item in tools_report),
        "pending_owner_adapter_count": sum(item["adapter_status"] == "pending_owner_adapter" for item in tools_report),
        "audited_root_count": sum(len(item["roots"]) for item in tools_report),
        "isolated_root_failure_count": sum(item["status"] == "partial_with_isolated_root_failures" for item in tools_report),
        "logical_bytes": sum(int(item["logical_bytes"]) for item in tools_report),
        "file_count": sum(int(item["file_count"]) for item in tools_report),
        "directory_count": sum(int(item["directory_count"]) for item in tools_report),
        "candidate_count": sum(int(item["candidate_count"]) for item in tools_report),
        "protected_count": sum(int(item["protected_count"]) for item in tools_report),
        "estimated_releasable_lower_bound_bytes": 0,
        "real_mutation_count": 0,
    }
    canonical = {
        "schema_version": SCHEMA_VERSION,
        "dispatch_id": dispatch_id,
        "authority": {
            "registry_sha256": sha256_file(registry_path),
            "source_inventory_sha256": sha256_file(inventory_path),
            "declarations_sha256": sha256_file(declarations_path),
            "reused_auditor_sha256": sha256_file(REUSED_AUDITOR),
        },
        "summary": summary,
        "tools": tools_report,
        "boundary": {
            "mode": "read_only_incremental",
            "automatic_purge": False,
            "real_quarantine_restore_purge": 0,
            "content_read": "metadata_and_small_manifest_hashes_only",
            "activepieces_optional": True,
        },
    }
    report = {**canonical, "checked_at": now_iso(), "canonical_content_sha256": content_hash(canonical)}
    atomic_write_json(output / "artifact-global-registry-audit.v1.json", report)
    render_markdown(output / "artifact-global-registry-audit.zh-CN.md", report)
    return report


def render_markdown(path: Path, report: dict[str, Any]) -> None:
    summary = report["summary"]
    pending = [item["tool_id"] for item in report["tools"] if item["adapter_status"] == "pending_owner_adapter"]
    lines = [
        "# 全局 Registry 产物生命周期只读审计",
        "",
        f"- dispatch_id: `{report['dispatch_id']}`",
        f"- checked_at: `{report['checked_at']}`",
        f"- canonical_content_sha256: `{report['canonical_content_sha256']}`",
        f"- Registry 覆盖: {summary['declaration_coverage_count']}/{summary['registry_tool_count']}",
        f"- 已验证 Owner adapter: {summary['verified_owner_adapter_count']}",
        f"- 待 Owner adapter: {summary['pending_owner_adapter_count']}",
        f"- no_managed_artifacts: {summary['no_managed_artifacts_count']}",
        f"- blocked_missing_declaration: {summary['blocked_missing_declaration_count']}",
        f"- 已审计合成根: {summary['audited_root_count']}",
        f"- 逻辑字节: {summary['logical_bytes']}",
        f"- 物理可释放保守下界: {summary['estimated_releasable_lower_bound_bytes']}（合成/只读审计，不外推真实释放量）",
        f"- 真实文件变动: {summary['real_mutation_count']}",
        "",
        "## 待 Owner 适配",
        "",
        *[f"- `{tool_id}`" for tool_id in pending],
        "",
        "## 边界",
        "",
        "- 数据库、客户资料、知识库、账号状态、原始素材、最终交付、凭据、运行状态、checkpoint 和不可变回执均永久保护。",
        "- Access Denied、超时、缺根和损坏输出按根隔离，不会中断其他工具的回执。",
        "- 所有 cleanup_mode 均为 plan_only；automatic purge 永久关闭。",
        "- 执行工具/模型：Codex (GPT-5.6 Sol)。",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Registry lifecycle declarations and bounded read-only artifact audit.")
    sub = parser.add_subparsers(dest="command", required=True)
    refresh = sub.add_parser("refresh-declarations")
    refresh.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    refresh.add_argument("--declarations", type=Path, default=DEFAULT_DECLARATIONS)
    refresh.add_argument("--output", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    validate.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    validate.add_argument("--declarations", type=Path, default=DEFAULT_DECLARATIONS)
    apply = sub.add_parser("apply-registry")
    apply.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    apply.add_argument("--declarations", type=Path, default=DEFAULT_DECLARATIONS)
    apply.add_argument("--expected-sha256")
    apply.add_argument("--backup", type=Path, required=True)
    audit = sub.add_parser("audit")
    audit.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    audit.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    audit.add_argument("--declarations", type=Path, default=DEFAULT_DECLARATIONS)
    audit.add_argument("--output", type=Path, required=True)
    audit.add_argument("--root-timeout-seconds", type=int, default=15)
    audit.add_argument("--max-nodes-per-root", type=int, default=5000)
    audit.add_argument("--max-depth", type=int, default=12)
    audit.add_argument("--dispatch-id", default=DISPATCH_ID)
    worker = sub.add_parser("_scan-root")
    worker.add_argument("--root", type=Path, required=True)
    worker.add_argument("--tool-id", required=True)
    worker.add_argument("--output", type=Path, required=True)
    worker.add_argument("--max-nodes", type=int, required=True)
    worker.add_argument("--max-depth", type=int, required=True)
    worker.add_argument("--dispatch-id", default=DISPATCH_ID)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "refresh-declarations":
        result = refresh_declarations(args.registry, args.declarations, args.output)
        print(json.dumps(result, ensure_ascii=False))
        return 0 if result["status"].startswith("completed") else 2
    if args.command == "validate":
        registry = load_json(args.registry)
        inventory = load_json(args.inventory)
        declarations = load_json(args.declarations)
        errors = validate_declarations(registry, declarations)
        if not errors and any("artifact_lifecycle_governance" in item for item in registry.get("tools", {}).values()):
            errors.extend(validate_registry_projection(registry, declarations))
        inventory_errors, source_linkage = validate_source_inventory_linkage(registry, inventory)
        errors.extend(inventory_errors)
        print(
            json.dumps(
                {
                    "ok": not errors,
                    "tool_count": len(registry.get("tools", {})),
                    "source_linkage": source_linkage,
                    "errors": errors,
                },
                ensure_ascii=False,
            )
        )
        return 0 if not errors else 2
    if args.command == "apply-registry":
        result = apply_registry(args.registry, args.declarations, expected_sha256=args.expected_sha256, backup_path=args.backup)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    if args.command == "audit":
        report = audit_registry(
            args.registry,
            args.inventory,
            args.declarations,
            args.output,
            timeout_seconds=args.root_timeout_seconds,
            max_nodes=args.max_nodes_per_root,
            max_depth=args.max_depth,
            dispatch_id=args.dispatch_id,
        )
        print(json.dumps({"ok": True, "canonical_content_sha256": report["canonical_content_sha256"], **report["summary"], "output": str(args.output)}, ensure_ascii=False))
        return 0
    if args.command == "_scan-root":
        result = scan_root_worker(
            args.root.resolve(strict=False),
            args.tool_id,
            args.output.resolve(strict=False),
            args.max_nodes,
            args.max_depth,
            dispatch_id=args.dispatch_id,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
