"""Configuration-driven, synthetic-only project adapter for artifact-lifecycle-core.

Project repositories own a small rules file and fixture root.  This module owns
the bounded scan, immutable plan, drift check, quarantine, and restore mechanics
by delegating every lifecycle operation to ``artifact_lifecycle_core``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

import artifact_lifecycle_core as core


SCHEMA_VERSION = "project-artifact-lifecycle-adapter.v1"
DEFAULT_REBUILD_PROOF = {
    "status": "unknown",
    "command": None,
    "input_hashes": [],
    "dependency_lock": None,
    "verification_ref": None,
}


class AdapterError(RuntimeError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _safe_relative(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise AdapterError("ADAPTER_PATH_INVALID", value)
    return path.as_posix()


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def load_config(path: str | Path) -> tuple[Path, dict[str, Any]]:
    config_path = Path(path).resolve()
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError("ADAPTER_CONFIG_INVALID", str(config_path)) from exc
    required = {"schema_version", "profile_id", "producer_tool_id", "owner_lane", "allowed_roots", "default", "rules"}
    if not isinstance(config, dict) or required - set(config):
        raise AdapterError("ADAPTER_CONFIG_FIELDS_MISSING")
    if config["schema_version"] != SCHEMA_VERSION or config["profile_id"] not in core.PROFILE_IDS:
        raise AdapterError("ADAPTER_CONFIG_CONTRACT_MISMATCH")
    if not isinstance(config["allowed_roots"], list) or not config["allowed_roots"]:
        raise AdapterError("ADAPTER_ALLOWED_ROOTS_INVALID")
    roots = [_safe_relative(str(item)) for item in config["allowed_roots"]]
    if len(roots) != len(set(roots)):
        raise AdapterError("ADAPTER_ALLOWED_ROOTS_DUPLICATE")
    if not isinstance(config["rules"], list):
        raise AdapterError("ADAPTER_RULES_INVALID")
    paths = []
    for rule in config["rules"]:
        if not isinstance(rule, dict) or "path" not in rule or "artifact_role" not in rule:
            raise AdapterError("ADAPTER_RULE_INVALID")
        paths.append(_safe_relative(str(rule["path"])))
    if len(paths) != len(set(paths)):
        raise AdapterError("ADAPTER_RULE_PATH_DUPLICATE")
    return config_path, config


def _repo_root(config_path: Path, config: dict[str, Any]) -> Path:
    parent_count = int(config.get("repository_root_parents", 1))
    if parent_count < 1:
        raise AdapterError("ADAPTER_REPOSITORY_ROOT_INVALID")
    return config_path.parents[parent_count]


def resolve_allowed_root(config_path: Path, config: dict[str, Any], root: str | Path) -> Path:
    repo_root = _repo_root(config_path, config)
    target = Path(root).resolve()
    allowed = [(repo_root / item).resolve() for item in config["allowed_roots"]]
    if target not in allowed:
        raise AdapterError("ADAPTER_ROOT_NOT_CONFIGURED", str(target))
    if not target.is_dir():
        raise AdapterError("ADAPTER_ROOT_MISSING", str(target))
    try:
        core.assert_no_reparse(target, target)
    except core.LifecycleError as exc:
        raise AdapterError(exc.code, exc.detail) from exc
    return target


def _rule_index(config: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {_safe_relative(str(rule["path"])): rule for rule in config["rules"]}


def _apply_rule(item: dict[str, Any], rule: dict[str, Any]) -> None:
    item["artifact_role"] = rule["artifact_role"]
    item["lifecycle_state"] = rule.get("lifecycle_state", "candidate")
    item["depends_on"] = list(rule.get("depends_on", []))
    item["referenced_by"] = list(rule.get("referenced_by", []))
    item["sensitivity"] = rule.get("sensitivity", "unknown")
    item["rebuild_proof"] = dict(rule.get("rebuild_proof", DEFAULT_REBUILD_PROOF))
    item["minimum_keep_until"] = rule.get("minimum_keep_until")
    item["pin"] = bool(rule.get("pin", item["artifact_role"] in core.PROTECTED_ROLES))


def build_manifest(config_path: str | Path, root: str | Path, closure_run_id: str, checkpoint: str | Path, max_files: int = 128) -> dict[str, Any]:
    config_file, config = load_config(config_path)
    scan_root = resolve_allowed_root(config_file, config, root)
    manifest = core.scan_root(
        scan_root,
        profile_id=config["profile_id"],
        producer_tool_id=config["producer_tool_id"],
        owner_lane=config["owner_lane"],
        closure_run_id=closure_run_id,
        max_files=max_files,
        checkpoint=Path(checkpoint).resolve(),
    )
    rules = _rule_index(config)
    default = dict(config["default"])
    for item in manifest["artifacts"]:
        _apply_rule(item, rules.get(item["path"], default))
    manifest["adapter"] = {
        "schema_version": SCHEMA_VERSION,
        "config_sha256": core.sha256_file(config_file),
        "configured_root": scan_root.relative_to(_repo_root(config_file, config)).as_posix(),
        "synthetic_only": bool(config.get("synthetic_only", True)),
        "real_mutation_count": 0,
    }
    manifest.pop("manifest_sha256", None)
    manifest = core.attach_hash(manifest, "manifest_sha256")
    errors = core.validate_manifest(manifest)
    if errors:
        raise AdapterError("ADAPTER_MANIFEST_INVALID", ";".join(errors))
    return manifest


def doctor(config_path: str | Path, root: str | Path) -> dict[str, Any]:
    config_file, config = load_config(config_path)
    scan_root = resolve_allowed_root(config_file, config, root)
    result = core.doctor(Path(__file__).resolve().parent, scan_root, config["profile_id"])
    disk_preflight = config.get("disk_preflight")
    if disk_preflight is not None:
        if not isinstance(disk_preflight, dict):
            raise AdapterError("ADAPTER_DISK_PREFLIGHT_INVALID")
        try:
            minimum_free_bytes = int(disk_preflight["minimum_free_bytes"])
            warning_free_bytes = int(disk_preflight["warning_free_bytes"])
            estimated_output_bytes = int(disk_preflight.get("estimated_output_bytes", 0))
            output_headroom_multiplier = float(disk_preflight["output_headroom_multiplier"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AdapterError("ADAPTER_DISK_PREFLIGHT_INVALID") from exc
        if min(minimum_free_bytes, warning_free_bytes, estimated_output_bytes) < 0 or output_headroom_multiplier < 1:
            raise AdapterError("ADAPTER_DISK_PREFLIGHT_INVALID")
        disk = core.free_space_status(
            scan_root,
            minimum_free_bytes=minimum_free_bytes,
            warning_free_bytes=warning_free_bytes,
            estimated_output_bytes=estimated_output_bytes,
            output_headroom_multiplier=output_headroom_multiplier,
        )
        result["disk"] = disk
        result["disk_preflight"] = "blocked_low_disk" if disk["status"] == "blocked_low_disk" else disk["status"]
        if disk["status"] == "blocked_low_disk":
            result["status"] = "blocked"
            result["runtime_ready"] = False
            result["reason_codes"] = sorted(set(result["reason_codes"] + ["blocked_low_disk"]))
        elif disk["status"] == "low_disk_allowed":
            result["reason_codes"] = sorted(set(result["reason_codes"] + ["low_disk_allowed"]))
    result["adapter_schema_version"] = SCHEMA_VERSION
    result["synthetic_only"] = bool(config.get("synthetic_only", True))
    result["execution_authority"] = "none_metadata_only"
    result["real_mutation_count"] = 0
    if config.get("retired_disabled"):
        result.update({
            "status": "retired_disabled",
            "runtime_ready": False,
            "current_online": False,
            "actionability": "disabled_no_execution_authority",
            "reason_codes": sorted(set(result["reason_codes"] + ["retired_disabled"])),
        })
    elif isinstance(result.get("disk"), dict) and result["disk"].get("status") == "blocked_low_disk":
        result["large_operation_preflight"] = "blocked_low_disk"
        result["read_only_doctor_ready"] = bool(result["contract_ready"])
    elif isinstance(result.get("disk"), dict) and result["disk"].get("status") == "low_disk_allowed":
        result["large_operation_preflight"] = "low_disk_allowed"
    return result


def _require_synthetic(config: dict[str, Any]) -> None:
    if not config.get("synthetic_only", True):
        raise AdapterError("SYNTHETIC_ONLY_CONTRACT_REQUIRED")


def _require_synthetic_markers(config: dict[str, Any], root: Path) -> None:
    markers = config.get("synthetic_markers", [])
    if not isinstance(markers, list):
        raise AdapterError("ADAPTER_SYNTHETIC_MARKERS_INVALID")
    for marker in markers:
        marker_path = root / _safe_relative(str(marker))
        if not marker_path.is_file():
            raise AdapterError("SYNTHETIC_FIXTURE_MARKER_MISSING", str(marker_path))


def _approval(plan: dict[str, Any]) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    return {
        "schema_version": core.APPROVAL_SCHEMA_VERSION,
        "operation": "quarantine",
        "plan_sha256": plan["plan_sha256"],
        "approved": True,
        "approved_by": "synthetic-fixture-only",
        "approved_at": now.isoformat(),
        "expires_at": (now + dt.timedelta(minutes=5)).isoformat(),
    }


def _load_plan_args(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any], Path, Path]:
    config_file, config = load_config(args.config)
    _require_synthetic(config)
    if config.get("retired_disabled"):
        raise AdapterError("RETIRED_DISABLED")
    root = resolve_allowed_root(config_file, config, args.root)
    _require_synthetic_markers(config, root)
    quarantine_root = Path(args.quarantine_root).resolve()
    if not quarantine_root.is_dir():
        raise AdapterError("ADAPTER_QUARANTINE_ROOT_MISSING", str(quarantine_root))
    manifest = core.load_manifest(Path(args.manifest).resolve())
    return config, manifest, root, quarantine_root


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thin, synthetic-only artifact lifecycle adapter")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "scan"):
        child = sub.add_parser(name)
        child.add_argument("--config", required=True)
        child.add_argument("--root", required=True)
    scan = sub.choices["scan"]
    scan.add_argument("--closure-run-id", required=True)
    scan.add_argument("--checkpoint", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--max-files", type=int, default=128)
    explain = sub.add_parser("explain")
    explain.add_argument("--manifest", required=True)
    explain.add_argument("--artifact-id", required=True)
    for name in ("plan", "verify-plan", "synthetic-quarantine", "synthetic-restore"):
        child = sub.add_parser(name)
        child.add_argument("--config", required=True)
        child.add_argument("--root", required=True)
        child.add_argument("--manifest", required=True)
        child.add_argument("--quarantine-root", required=True)
        child.add_argument("--plan", required=name != "plan")
    plan = sub.choices["plan"]
    plan.add_argument("--output", required=True)
    plan.add_argument("--owner-state", default="unknown")
    plan.add_argument("--process-state", default="unknown")
    plan.add_argument("--dispatch-state", default="unknown")
    quarantine = sub.choices["synthetic-quarantine"]
    quarantine.add_argument("--receipt", required=True)
    restore = sub.choices["synthetic-restore"]
    restore.add_argument("--receipt", required=True)
    restore.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            result = doctor(args.config, args.root)
            _emit(result)
            return 0 if result["status"] in {"ready", "retired_disabled"} else 2
        if args.command == "scan":
            manifest = build_manifest(args.config, args.root, args.closure_run_id, args.checkpoint, args.max_files)
            core.atomic_write_json(Path(args.output).resolve(), manifest)
            _emit({"status": "ok", "artifact_count": len(manifest["artifacts"]), "manifest_sha256": manifest["manifest_sha256"], "real_mutation_count": 0})
            return 0
        if args.command == "explain":
            manifest = core.load_manifest(Path(args.manifest).resolve())
            item = next((row for row in manifest["artifacts"] if row["artifact_id"] == args.artifact_id), None)
            if item is None:
                raise AdapterError("ARTIFACT_NOT_FOUND", args.artifact_id)
            _emit({"status": "ok", "artifact": item, "authorizes_operation": False, "real_mutation_count": 0})
            return 0
        config, manifest, root, quarantine_root = _load_plan_args(args)
        if args.command == "plan":
            plan = core.plan_operation(manifest, root, quarantine_root, "quarantine", owner_state=args.owner_state, process_state=args.process_state, dispatch_state=args.dispatch_state)
            core.atomic_write_json(Path(args.output).resolve(), plan)
            _emit({"status": "ok", "plan_sha256": plan["plan_sha256"], "authorizes_operation": False, "real_mutation_count": 0})
            return 0
        plan = core.read_json(Path(args.plan).resolve())
        if args.command == "verify-plan":
            result = core.verify_plan(plan, manifest, root, quarantine_root)
            result["authorizes_operation"] = False
            result["real_mutation_count"] = 0
            _emit(result)
            return 0 if result["ok"] else 2
        if args.command == "synthetic-quarantine":
            receipt = core.apply_quarantine(plan, manifest, root, quarantine_root, _approval(plan), Path(args.receipt).resolve())
            receipt["synthetic_fixture_only"] = True
            _emit(receipt)
            return 0
        receipt = core.restore_from_receipt(core.read_json(Path(args.receipt).resolve()), plan, root, quarantine_root, Path(args.output).resolve())
        receipt["synthetic_fixture_only"] = True
        _emit(receipt)
        return 0
    except (AdapterError, core.LifecycleError) as exc:
        _emit({"status": "blocked", "error_code": getattr(exc, "code", "ADAPTER_ERROR"), "detail": str(exc), "filesystem_mutation_performed": False, "real_mutation_count": 0})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
