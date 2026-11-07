from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import artifact_lifecycle_core as core


ADAPTER_SCHEMA = "research-evidence-lifecycle-adapter.v1"
LARGE_OPERATIONS = {"fetch", "embedding", "index", "render"}
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


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _safe_relative(value: str) -> str:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise AdapterError("ADAPTER_PATH_INVALID", value)
    return path.as_posix()


def load_config(path: str | Path) -> tuple[Path, dict[str, Any]]:
    config_path = Path(path).resolve()
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdapterError("ADAPTER_CONFIG_INVALID", str(config_path)) from exc
    required = {"schema_version", "profile_id", "producer_tool_id", "owner_lane", "allowed_roots", "default", "rules"}
    if not isinstance(config, dict) or required - set(config):
        raise AdapterError("ADAPTER_CONFIG_FIELDS_MISSING")
    if config["schema_version"] != ADAPTER_SCHEMA or config["profile_id"] != "research_evidence":
        raise AdapterError("ADAPTER_CONFIG_CONTRACT_MISMATCH")
    if not isinstance(config["allowed_roots"], list) or not config["allowed_roots"]:
        raise AdapterError("ADAPTER_ALLOWED_ROOTS_INVALID")
    roots = [_safe_relative(str(item)) for item in config["allowed_roots"]]
    if len(set(roots)) != len(roots):
        raise AdapterError("ADAPTER_ALLOWED_ROOTS_DUPLICATE")
    if not isinstance(config["rules"], list):
        raise AdapterError("ADAPTER_RULES_INVALID")
    paths = []
    for rule in config["rules"]:
        if not isinstance(rule, dict) or "path" not in rule or "artifact_role" not in rule:
            raise AdapterError("ADAPTER_RULE_INVALID")
        paths.append(_safe_relative(str(rule["path"])))
    if len(set(paths)) != len(paths):
        raise AdapterError("ADAPTER_RULE_PATH_DUPLICATE")
    return config_path, config


def resolve_allowed_root(config_path: Path, config: dict[str, Any], root: str | Path) -> Path:
    repo_root = config_path.parents[1]
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


def build_manifest(config_path: str | Path, root: str | Path, closure_run_id: str, checkpoint: str | Path, max_files: int = 256) -> dict[str, Any]:
    config_file, config = load_config(config_path)
    scan_root = resolve_allowed_root(config_file, config, root)
    manifest = core.scan_root(
        scan_root,
        profile_id="research_evidence",
        producer_tool_id=config["producer_tool_id"],
        owner_lane=config["owner_lane"],
        closure_run_id=closure_run_id,
        max_files=max_files,
        checkpoint=Path(checkpoint).resolve(),
    )
    default = dict(config["default"])
    rules = _rule_index(config)
    for item in manifest["artifacts"]:
        rule = rules.get(item["path"], default)
        _apply_rule(item, rule)
    manifest["adapter"] = {
        "schema_version": ADAPTER_SCHEMA,
        "config_sha256": core.sha256_file(config_file),
        "configured_root": scan_root.relative_to(config_file.parents[1]).as_posix(),
        "unknown_paths_fail_closed": True,
        "real_mutation_count": 0,
    }
    manifest.pop("manifest_sha256", None)
    manifest = core.attach_hash(manifest, "manifest_sha256")
    errors = core.validate_manifest(manifest)
    if errors:
        raise AdapterError("ADAPTER_MANIFEST_INVALID", ";".join(errors))
    return manifest


def preflight(
    config_path: str | Path,
    root: str | Path,
    operation: str,
    estimated_output_bytes: int = 0,
) -> dict[str, Any]:
    config_file, config = load_config(config_path)
    scan_root = resolve_allowed_root(config_file, config, root)
    disk = core.free_space_status(scan_root, estimated_output_bytes=estimated_output_bytes)
    blocked = operation in LARGE_OPERATIONS and disk["status"] == "blocked_low_disk"
    return {
        "schema_version": "research-evidence-lifecycle-preflight.v1",
        "status": "blocked" if blocked else "ready",
        "operation": operation,
        "disk": disk,
        "minimum_free_bytes": core.MIN_FREE_BYTES,
        "warning_free_bytes": core.WARN_FREE_BYTES,
        "estimated_output_bytes": estimated_output_bytes,
        "output_headroom_multiplier": core.OUTPUT_HEADROOM_MULTIPLIER,
        "reason_codes": ["blocked_low_disk"] if blocked else [],
        "filesystem_mutation_performed": False,
        "real_mutation_count": 0,
    }


def explain(manifest: dict[str, Any], artifact_id: str, root: str | Path, quarantine_root: str | Path) -> dict[str, Any]:
    plan = core.plan_operation(
        manifest,
        Path(root).resolve(),
        Path(quarantine_root).resolve(),
        "quarantine",
        owner_state="unknown",
        process_state="unknown",
        dispatch_state="unknown",
    )
    entry = next((item for item in plan["entries"] if item["artifact_id"] == artifact_id), None)
    if entry is None:
        raise AdapterError("ARTIFACT_NOT_FOUND", artifact_id)
    return {"status": "ok", "entry": entry, "authorizes_operation": False, "real_mutation_count": 0}


def _emit(value: dict[str, Any]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Thin research_evidence adapter for artifact-lifecycle-core")
    sub = parser.add_subparsers(dest="command", required=True)
    doctor = sub.add_parser("doctor")
    doctor.add_argument("--config", required=True)
    doctor.add_argument("--root", required=True)
    check = sub.add_parser("preflight")
    check.add_argument("--config", required=True)
    check.add_argument("--root", required=True)
    check.add_argument("--operation", choices=["scan", *sorted(LARGE_OPERATIONS)], required=True)
    check.add_argument("--estimated-output-bytes", type=int, default=0)
    scan = sub.add_parser("scan")
    scan.add_argument("--config", required=True)
    scan.add_argument("--root", required=True)
    scan.add_argument("--closure-run-id", required=True)
    scan.add_argument("--checkpoint", required=True)
    scan.add_argument("--output", required=True)
    scan.add_argument("--max-files", type=int, default=256)
    explain_parser = sub.add_parser("explain")
    explain_parser.add_argument("--config", required=True)
    explain_parser.add_argument("--root", required=True)
    explain_parser.add_argument("--manifest", required=True)
    explain_parser.add_argument("--artifact-id", required=True)
    explain_parser.add_argument("--quarantine-root", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--config", required=True)
    plan.add_argument("--root", required=True)
    plan.add_argument("--manifest", required=True)
    plan.add_argument("--quarantine-root", required=True)
    plan.add_argument("--output", required=True)
    plan.add_argument("--owner-state", default="unknown")
    plan.add_argument("--process-state", default="unknown")
    plan.add_argument("--dispatch-state", default="unknown")
    verify = sub.add_parser("verify-plan")
    verify.add_argument("--config", required=True)
    verify.add_argument("--root", required=True)
    verify.add_argument("--manifest", required=True)
    verify.add_argument("--plan", required=True)
    verify.add_argument("--quarantine-root", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            config_file, config = load_config(args.config)
            root = resolve_allowed_root(config_file, config, args.root)
            result = core.doctor(Path(__file__).resolve().parent, root, "research_evidence")
            result["adapter_schema_version"] = ADAPTER_SCHEMA
            result["real_mutation_count"] = 0
            _emit(result)
            return 0 if result["status"] == "ready" else 2
        if args.command == "preflight":
            result = preflight(args.config, args.root, args.operation, args.estimated_output_bytes)
            _emit(result)
            return 0 if result["status"] == "ready" else 2
        if args.command == "explain":
            config_file, config = load_config(args.config)
            root = resolve_allowed_root(config_file, config, args.root)
            result = explain(
                core.load_manifest(Path(args.manifest).resolve()),
                args.artifact_id,
                root,
                Path(args.quarantine_root).resolve(),
            )
            _emit(result)
            return 0
        if args.command == "plan":
            config_file, config = load_config(args.config)
            root = resolve_allowed_root(config_file, config, args.root)
            plan_value = core.plan_operation(
                core.load_manifest(Path(args.manifest).resolve()),
                root,
                Path(args.quarantine_root).resolve(),
                "quarantine",
                owner_state=args.owner_state,
                process_state=args.process_state,
                dispatch_state=args.dispatch_state,
            )
            core.atomic_write_json(Path(args.output).resolve(), plan_value)
            _emit(
                {
                    "status": "ok",
                    "plan_sha256": plan_value["plan_sha256"],
                    "eligible_count": sum(item["eligible"] for item in plan_value["entries"]),
                    "authorizes_operation": False,
                    "real_mutation_count": 0,
                }
            )
            return 0
        if args.command == "verify-plan":
            config_file, config = load_config(args.config)
            root = resolve_allowed_root(config_file, config, args.root)
            result = core.verify_plan(
                core.read_json(Path(args.plan).resolve()),
                core.load_manifest(Path(args.manifest).resolve()),
                root,
                Path(args.quarantine_root).resolve(),
            )
            result["real_mutation_count"] = 0
            _emit(result)
            return 0 if result["ok"] else 2
        manifest = build_manifest(args.config, args.root, args.closure_run_id, args.checkpoint, args.max_files)
        core.atomic_write_json(Path(args.output).resolve(), manifest)
        _emit({"status": "ok", "manifest_sha256": manifest["manifest_sha256"], "artifact_count": len(manifest["artifacts"]), "real_mutation_count": 0})
        return 0
    except (AdapterError, core.LifecycleError) as exc:
        _emit({"status": "blocked", "error_code": getattr(exc, "code", "ADAPTER_ERROR"), "detail": str(exc), "filesystem_mutation_performed": False, "real_mutation_count": 0})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
