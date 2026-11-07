from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path
from typing import Any

import artifact_lifecycle_core as core
import run_tests


ROOT = Path(__file__).resolve().parent
SCHEMA_VERSION = "artifact-lifecycle-release-readiness-receipt.v1"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        temporary.write_text(data, encoding="utf-8", newline="\n")
        if temporary.read_text(encoding="utf-8") != data:
            raise OSError("atomic_write_readback_mismatch")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_stage(
    stage: str,
    command: list[str],
    cwd: Path,
    *,
    expected: set[int] = {0},
    timeout: int = 300,
) -> dict[str, Any]:
    environment = os.environ.copy()
    inherited_temp = os.environ.get("TEMP") or os.environ.get("TMP")
    temp_root = Path(inherited_temp) if inherited_temp else cwd / ".command-temp"
    temp_root.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "PIP_NO_INDEX": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "TEMP": str(temp_root),
            "TMP": str(temp_root),
            "TMPDIR": str(temp_root),
        }
    )
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False,
        check=False,
    )
    result = {
        "stage": stage,
        "returncode": completed.returncode,
        "expected_returncodes": sorted(expected),
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
        "checked_at": now_iso(),
    }
    if completed.returncode not in expected:
        raise RuntimeError(f"stage_failed:{stage}:{completed.returncode}:{completed.stderr[-500:]}")
    return result


def source_content_sha256() -> tuple[str, int]:
    files, _, _, errors = run_tests.delivery_file_list()
    if errors:
        raise RuntimeError("delivery_enumeration_failed:" + ";".join(errors))
    digest = hashlib.sha256()
    for relative in files:
        digest.update(relative.replace("\\", "/").encode("utf-8"))
        digest.update(b"\0")
        digest.update((ROOT / relative).read_bytes())
        digest.update(b"\0")
    return digest.hexdigest(), len(files)


def scan_source_delivery() -> dict[str, Any]:
    files, _, excluded_files, errors = run_tests.delivery_file_list()
    forbidden = [
        b"d:" + b"\\used-by-codex",
        b"d:/" + b"used-by-codex",
        b"c:" + b"\\users\\lightcolor",
        b"c:/users/" + b"lightcolor",
    ]
    path_hits: list[str] = []
    large: list[dict[str, Any]] = []
    for relative in files:
        path = ROOT / relative
        data = path.read_bytes()
        if any(marker in data.lower() for marker in forbidden):
            path_hits.append(relative)
        if len(data) > 2 * 1024 * 1024:
            large.append({"path": relative, "bytes": len(data)})
    return {
        "status": "passed" if not errors and not path_hits and not large else "blocked",
        "file_count": len(files),
        "excluded_task_receipts": sorted(excluded_files),
        "personal_or_workspace_path_hits": sorted(path_hits),
        "files_over_2_mib": large,
        "enumeration_errors": errors,
    }


def scan_wheel(wheel: Path) -> dict[str, Any]:
    required_suffixes = {
        "share/artifact-lifecycle-core/AGENT_DISCOVERY.md",
        "share/artifact-lifecycle-core/agent-tool-manifest.v1.json",
        "share/artifact-lifecycle-core/LICENSE",
        "share/artifact-lifecycle-core/README.zh-CN.md",
        "share/artifact-lifecycle-core/profiles/artifact-lifecycle-profiles.v1.json",
        "share/artifact-lifecycle-core/schemas/artifact-lifecycle-manifest.v1.schema.json",
    }
    forbidden = [
        b"d:" + b"\\used-by-codex",
        b"d:/" + b"used-by-codex",
        b"c:" + b"\\users\\lightcolor",
        b"c:/users/" + b"lightcolor",
    ]
    names: set[str] = set()
    leaks: list[str] = []
    large: list[dict[str, Any]] = []
    with zipfile.ZipFile(wheel) as archive:
        for info in archive.infolist():
            normalized = info.filename.replace("\\", "/")
            names.add(normalized)
            if info.file_size > 2 * 1024 * 1024:
                large.append({"path": normalized, "bytes": info.file_size})
            if info.is_dir():
                continue
            data = archive.read(info).lower()
            if any(marker in data for marker in forbidden):
                leaks.append(normalized)
    missing = sorted(
        suffix for suffix in required_suffixes if not any(name.endswith(suffix) for name in names)
    )
    return {
        "status": "passed" if not missing and not leaks and not large else "blocked",
        "required_assets_missing": missing,
        "personal_or_workspace_path_hits": sorted(leaks),
        "files_over_2_mib": large,
        "archive_file_count": len(names),
    }


def script_path(venv: Path, name: str) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / f"{name}.exe"
    return venv / "bin" / name


def python_path(venv: Path) -> Path:
    if os.name == "nt":
        return venv / "Scripts" / "python.exe"
    return venv / "bin" / "python"


def execute(workspace: Path) -> dict[str, Any]:
    if workspace.exists() and any(workspace.iterdir()):
        raise RuntimeError("release_workspace_must_be_empty")
    workspace.mkdir(parents=True, exist_ok=True)
    core.assert_no_reparse(workspace, workspace)
    wheelhouse = workspace / "wheelhouse"
    wheelhouse.mkdir()
    venv = workspace / "venv"
    stages: list[dict[str, Any]] = []
    stages.append(
        run_stage(
            "build_wheel_offline",
            [sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheelhouse)],
            workspace,
        )
    )
    wheels = sorted(wheelhouse.glob("artifact_lifecycle_core-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"exactly_one_wheel_required:{len(wheels)}")
    wheel = wheels[0]
    archive_scan = scan_wheel(wheel)
    if archive_scan["status"] != "passed":
        raise RuntimeError("wheel_archive_scan_failed")
    source_scan = scan_source_delivery()
    if source_scan["status"] != "passed":
        raise RuntimeError("source_delivery_scan_failed")
    stages.append(
        run_stage(
            "create_clean_venv",
            [sys.executable, "-m", "venv", "--without-pip", str(venv)],
            workspace,
        )
    )
    venv_python = python_path(venv)
    stages.append(
        run_stage(
            "install_wheel_offline",
            [
                sys.executable,
                "-m",
                "pip",
                "--python",
                str(venv_python),
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
            ],
            workspace,
        )
    )
    doctor_stage = run_stage("installed_doctor", [str(script_path(venv, "local-artifacts")), "doctor"], workspace)
    doctor = json.loads(doctor_stage["stdout_tail"])
    if doctor.get("status") != "ready" or doctor.get("asset_root_mode") != "installed_data_files":
        raise RuntimeError("installed_doctor_contract_failed")
    stages.append(doctor_stage)
    demo_workspace = workspace / "demo"
    demo_command = [str(script_path(venv, "local-artifacts-demo")), "--workspace", str(demo_workspace), "--run-id", "install-demo-01"]
    first_demo_stage = run_stage("installed_synthetic_demo", demo_command, workspace)
    first_demo = json.loads(first_demo_stage["stdout_tail"])
    if first_demo.get("status") != "completed" or first_demo.get("purge_enabled") is not False:
        raise RuntimeError("installed_demo_contract_failed")
    stages.append(first_demo_stage)
    second_demo_stage = run_stage("installed_demo_idempotent_replay", demo_command, workspace)
    second_demo = json.loads(second_demo_stage["stdout_tail"])
    if second_demo.get("status") != "completed_idempotent_replay":
        raise RuntimeError("installed_demo_idempotence_failed")
    if second_demo.get("receipt_sha256") != first_demo.get("receipt_sha256"):
        raise RuntimeError("installed_demo_receipt_hash_drift")
    stages.append(second_demo_stage)
    purge_stage = run_stage(
        "installed_purge_rejected",
        [str(script_path(venv, "local-artifacts")), "apply-purge", "--plan", "synthetic-not-used.json", "--execute"],
        workspace,
        expected={2},
    )
    purge = json.loads(purge_stage["stdout_tail"])
    if purge.get("error_code") != "PURGE_DISABLED_BY_POLICY":
        raise RuntimeError("purge_policy_not_enforced")
    stages.append(purge_stage)
    source_sha, source_file_count = source_content_sha256()
    return core.attach_hash(
        {
            "schema_version": SCHEMA_VERSION,
            "status": "passed",
            "source_content_sha256": source_sha,
            "source_file_count": source_file_count,
            "wheel": wheel.name,
            "wheel_sha256": sha256_file(wheel),
            "archive_scan": archive_scan,
            "source_scan": source_scan,
            "installed_doctor": {
                "status": doctor["status"],
                "asset_root_mode": doctor["asset_root_mode"],
                "current_online": doctor["current_online"],
                "real_usage_proof": doctor["real_usage_proof"],
            },
            "synthetic_demo": {
                "status": first_demo["status"],
                "receipt_sha256": first_demo["receipt_sha256"],
                "idempotent_replay": second_demo["status"],
                "real_history_or_business_file_mutation_count": first_demo["real_history_or_business_file_mutation_count"],
                "purge_enabled": first_demo["purge_enabled"],
            },
            "stages": stages,
            "network_dependency": "none_pip_no_index",
            "publication_performed": False,
            "real_artifact_mutation_count": 0,
            "checked_at": now_iso(),
        },
        "receipt_sha256",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline clean-install release-readiness verification.")
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = execute(args.workspace.resolve(strict=False))
        code = 0
    except Exception as error:
        result = core.attach_hash(
            {
                "schema_version": SCHEMA_VERSION,
                "status": "blocked",
                "failure_point": "release_readiness",
                "error_class": type(error).__name__,
                "detail": str(error),
                "recovery_entry": "Use a new empty --workspace after correcting the reported stage.",
                "publication_performed": False,
                "real_artifact_mutation_count": 0,
                "checked_at": now_iso(),
            },
            "receipt_sha256",
        )
        code = 2
    atomic_write(args.receipt.resolve(strict=False), result)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
