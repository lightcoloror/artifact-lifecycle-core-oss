from __future__ import annotations

import argparse
import errno
import json
import re
import shutil
from pathlib import Path

import artifact_lifecycle_core as core
import synthetic_roundtrip_pilot as pilot


DEMO_DISPATCH_ID = "ARTIFACT-LIFECYCLE-SYNTHETIC-DEMO"
RUN_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")


def _emit(value: dict[str, object]) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def _read_existing(receipt_path: Path) -> dict[str, object] | None:
    if not receipt_path.is_file():
        return None
    value = core.read_json(receipt_path)
    if value.get("schema_version") != "artifact-lifecycle-portable-demo-receipt.v1":
        return None
    if not core.verify_hash(value, "receipt_sha256"):
        return None
    if value.get("status") != "completed" or value.get("purge_enabled") is not False:
        return None
    return value


def run_demo(workspace: Path, run_id: str) -> tuple[int, dict[str, object]]:
    try:
        return _run_demo(workspace, run_id)
    except OSError as error:
        code = "DEMO_FILESYSTEM_ERROR"
        if isinstance(error, PermissionError) or error.errno in (errno.EACCES, errno.EROFS):
            code = "PATH_ACCESS_DENIED"
        elif error.errno == errno.ENAMETOOLONG or getattr(error, "winerror", None) == 206:
            code = "PATH_TOO_LONG"
        return 2, {
            "status": "blocked", "error_code": code,
            "error_class": type(error).__name__, "failure_point": "filesystem_preflight",
            "recovery_entry": "Use a short writable local workspace; preserve existing evidence and do not change ACLs.",
            "purge_enabled": False,
        }
    except (core.LifecycleError, ValueError) as error:
        return 2, {
            "status": "blocked", "error_code": "DEMO_RECEIPT_INVALID",
            "error_class": type(error).__name__, "failure_point": "receipt_readback",
            "recovery_entry": "Preserve the damaged receipt and use a new --run-id.",
            "purge_enabled": False,
        }


def _run_demo(workspace: Path, run_id: str) -> tuple[int, dict[str, object]]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        return 2, {
            "status": "blocked",
            "error_code": "DEMO_RUN_ID_INVALID",
            "recovery_entry": "Use 1-80 ASCII letters, digits, dot, underscore, or dash.",
        }
    if shutil.which("git") is None:
        return 2, {
            "status": "blocked", "error_code": "GIT_UNAVAILABLE",
            "failure_point": "dependency_preflight",
            "recovery_entry": "Provide Git explicitly on the command PATH for the synthetic plan gate; doctor requires no Git.",
            "purge_enabled": False,
        }
    workspace.mkdir(parents=True, exist_ok=True)
    try:
        core.assert_no_reparse(workspace, workspace)
    except core.LifecycleError as error:
        return 2, {
            "status": "blocked",
            "error_code": error.code,
            "detail": error.detail,
            "recovery_entry": "Choose a normal local directory that is not a link or junction.",
        }

    run_root = workspace / run_id
    receipt_path = run_root / "demo-receipt.json"
    existing = _read_existing(receipt_path)
    if existing is not None:
        return 0, {
            "status": "completed_idempotent_replay",
            "run_id": run_id,
            "receipt": str(receipt_path),
            "receipt_sha256": existing["receipt_sha256"],
            "filesystem_mutation_scope": "none_existing_receipt_verified",
        }
    if run_root.exists():
        return 2, {
            "status": "blocked",
            "error_code": "DEMO_PARTIAL_RUN_PRESENT",
            "run_id": run_id,
            "failure_point": "preflight",
            "recovery_entry": "Preserve the partial evidence and retry with a new --run-id.",
        }

    run_root.mkdir()
    runtime_root = run_root / f"{DEMO_DISPATCH_ID}-runtime"
    output_root = run_root / f"{DEMO_DISPATCH_ID}-output"
    previous_dispatch = pilot.DISPATCH_ID
    try:
        pilot.DISPATCH_ID = DEMO_DISPATCH_ID
        result = pilot.run_pilot(runtime_root, output_root)
        receipt = core.attach_hash(
            {
                "schema_version": "artifact-lifecycle-portable-demo-receipt.v1",
                "status": "completed",
                "run_id": run_id,
                "pilot_receipt": str(output_root / f"{DEMO_DISPATCH_ID}.roundtrip-receipt.json"),
                "pilot_receipt_sha256": result["receipt_sha256"],
                "double_run_hash": result["double_run_hash"],
                "roundtrip_restored": result["roundtrip_restored"],
                "negative_tests": result["negative_tests"],
                "real_history_or_business_file_mutation_count": 0,
                "purge_enabled": False,
                "recovery_entry": f"local-artifacts-demo --workspace <workspace> --run-id {run_id}",
            },
            "receipt_sha256",
        )
        core.atomic_write_json(receipt_path, receipt)
        return 0, receipt
    except Exception as error:
        return 2, {
            "status": "failed",
            "error_code": "SYNTHETIC_DEMO_FAILED",
            "error_class": type(error).__name__,
            "detail": str(error),
            "failure_point": "synthetic_roundtrip",
            "run_id": run_id,
            "recovery_entry": "Preserve this run directory and retry with a new --run-id.",
            "real_history_or_business_file_mutation_count": 0,
            "purge_enabled": False,
        }
    finally:
        pilot.DISPATCH_ID = previous_dispatch


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline, synthetic-only artifact lifecycle roundtrip."
    )
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--run-id", default="portable-demo-01")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    code, result = run_demo(args.workspace.resolve(strict=False), args.run_id)
    _emit(result)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
