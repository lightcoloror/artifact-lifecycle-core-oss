from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest import mock

import artifact_lifecycle_core as core
import global_registry_audit as global_audit


DISPATCH_ID = "ARTIFACT-SYNTHETIC-ROUNDTRIP-PILOT-20260829-01"
CLI = Path(__file__).resolve().parent / "artifact_lifecycle_core.py"


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def write_receipt(path: Path, value: dict[str, Any]) -> dict[str, Any]:
    payload = core.attach_hash(value, "receipt_sha256")
    core.atomic_write_json(path, payload)
    return payload


def run_cli(
    stage: str,
    args: list[str],
    receipt_dir: Path,
    *,
    expected_returncodes: set[int] = {0},
) -> tuple[int, dict[str, Any]]:
    command = [sys.executable, str(CLI), *args]
    display_command = ["python", "artifact-lifecycle-core/artifact_lifecycle_core.py", *args]
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    try:
        output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        output = {"status": "invalid_json", "stdout_summary": completed.stdout[-1000:]}
    receipt = write_receipt(
        receipt_dir / f"{stage}.receipt.json",
        {
            "schema_version": "artifact-synthetic-pilot-stage-receipt.v1",
            "dispatch_id": DISPATCH_ID,
            "stage": stage,
            "command": display_command,
            "returncode": completed.returncode,
            "expected_returncodes": sorted(expected_returncodes),
            "result": output,
            "stderr_summary": completed.stderr[-1000:],
            "checked_at": now_iso(),
        },
    )
    if completed.returncode not in expected_returncodes:
        raise RuntimeError(f"unexpected_returncode:{stage}:{completed.returncode}")
    return completed.returncode, receipt


def sanitize_existing_receipts(root: Path) -> dict[str, Any]:
    resolved = root.resolve(strict=True)
    if "artifact-synthetic-roundtrip-pilot-2026-08-29" not in str(resolved).lower():
        raise RuntimeError("sanitize_root_must_be_dispatch_scoped")
    changed = 0
    checked = 0
    interpreter = str(Path(sys.executable).resolve(strict=False))
    for path in sorted(resolved.rglob("*.json")):
        checked += 1
        value = core.read_json(path)
        command = value.get("command")
        if isinstance(command, list) and command and command[0] == interpreter:
            command[0] = "python"
            if len(command) > 1 and command[1] == str(CLI):
                command[1] = "artifact-lifecycle-core/artifact_lifecycle_core.py"
            if "receipt_sha256" in value:
                value = core.attach_hash(value, "receipt_sha256")
            core.atomic_write_json(path, value)
            changed += 1
    remaining = []
    personal_markers: set[str] = set()
    for raw_home in (os.environ.get("USERPROFILE"), os.environ.get("HOME"), str(Path.home())):
        if not raw_home:
            continue
        normalized_home = str(Path(raw_home).resolve(strict=False)).lower()
        personal_markers.add(normalized_home)
        personal_markers.add(normalized_home.replace("\\", "\\\\"))
        if Path(normalized_home).name:
            personal_markers.add(Path(normalized_home).name.lower())
    for path in sorted(resolved.rglob("*.json")):
        text = path.read_text(encoding="utf-8").lower()
        if any(marker in text for marker in personal_markers):
            remaining.append(str(path))
    return {
        "status": "ok" if not remaining else "blocked_personal_path_remaining",
        "checked_json_count": checked,
        "changed_receipt_count": changed,
        "remaining_personal_path_files": remaining,
    }


def eligible_manifest(path: Path, evidence_ref: str) -> dict[str, Any]:
    manifest = core.read_json(path)
    for item in manifest["artifacts"]:
        item["lifecycle_state"] = "failed"
        item["sensitivity"] = "synthetic_non_sensitive"
        item["rebuild_proof"] = {
            "status": "verified",
            "command": "recreate the dispatch-owned synthetic fixture from this pilot",
            "input_hashes": [item["digest"]["value"]],
            "dependency_lock": "python-stdlib-only",
            "verification_ref": evidence_ref,
        }
    manifest = core.attach_hash(
        {key: value for key, value in manifest.items() if key != "manifest_sha256"},
        "manifest_sha256",
    )
    if errors := core.validate_manifest(manifest):
        raise RuntimeError("eligible_manifest_invalid:" + ";".join(errors))
    core.atomic_write_json(path, manifest)
    return manifest


def approval(plan: dict[str, Any], *, expired: bool = False) -> dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    expires = now - dt.timedelta(hours=1) if expired else now + dt.timedelta(hours=1)
    return {
        "schema_version": core.APPROVAL_SCHEMA_VERSION,
        "operation": "quarantine",
        "plan_sha256": plan["plan_sha256"],
        "approved": True,
        "approved_by": f"user_dispatch:{DISPATCH_ID}:synthetic_root_only",
        "approved_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": expires.isoformat().replace("+00:00", "Z"),
        "scope": "dispatch_owned_synthetic_root_only",
    }


def write_fixture(root: Path) -> dict[str, dict[str, Any]]:
    files = {
        "cache-alpha.txt": b"synthetic cache alpha\n",
        "nested/cache-beta.json": b'{"kind":"synthetic-cache","value":2}\n',
    }
    result: dict[str, dict[str, Any]] = {}
    for relative, content in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        result[relative] = {
            "sha256": core.sha256_file(target),
            "bytes": len(content),
        }
    return result


def assert_fixture(root: Path, expected: dict[str, dict[str, Any]]) -> None:
    for relative, evidence in expected.items():
        target = root / relative
        if not target.is_file():
            raise RuntimeError(f"fixture_missing:{relative}")
        if core.sha256_file(target) != evidence["sha256"]:
            raise RuntimeError(f"fixture_digest_mismatch:{relative}")
        if target.stat().st_size != evidence["bytes"]:
            raise RuntimeError(f"fixture_size_mismatch:{relative}")


def prepare_fresh_directory(path: Path) -> None:
    if path.exists():
        raise RuntimeError(f"pilot_path_must_not_preexist:{path}")
    path.mkdir(parents=True)


def run_pilot(runtime_root: Path, output_root: Path) -> dict[str, Any]:
    if DISPATCH_ID.lower() not in str(runtime_root).lower():
        raise RuntimeError("runtime_root_must_be_dispatch_scoped")
    prepare_fresh_directory(runtime_root)
    prepare_fresh_directory(output_root)
    receipt_dir = output_root / "roundtrip-receipts"
    receipt_dir.mkdir()
    source = runtime_root / "positive" / "source"
    quarantine = runtime_root / "positive" / "quarantine"
    control = runtime_root / "positive" / "control"
    source.mkdir(parents=True)
    quarantine.mkdir(parents=True)
    control.mkdir(parents=True)
    fixture = write_fixture(source)
    closure_run_id = "closure-artifact-synthetic-roundtrip-20260829-01"

    run_cli("01-doctor", ["doctor", "--target-root", str(source), "--profile", "test_cache"], receipt_dir)

    manifest_raw_1 = control / "manifest-raw-1.json"
    manifest_raw_2 = control / "manifest-raw-2.json"
    checkpoint = control / "checkpoint.sqlite3"
    scan_args = [
        "scan", "--root", str(source), "--profile", "test_cache",
        "--producer-tool-id", "artifact-lifecycle-core", "--owner-lane", "local-tools",
        "--closure-run-id", closure_run_id, "--checkpoint", str(checkpoint), "--max-files", "20",
    ]
    run_cli("02-scan-first", [*scan_args, "--output", str(manifest_raw_1)], receipt_dir)
    run_cli("03-scan-second", [*scan_args, "--output", str(manifest_raw_2)], receipt_dir)
    raw_first = core.read_json(manifest_raw_1)
    raw_second = core.read_json(manifest_raw_2)
    if raw_first["manifest_sha256"] != raw_second["manifest_sha256"]:
        raise RuntimeError("double_scan_hash_mismatch")

    manifest_path = control / "manifest-eligible.json"
    shutil.copyfile(manifest_raw_1, manifest_path)
    manifest = eligible_manifest(manifest_path, "roundtrip-receipts/02-scan-first.receipt.json")
    classification_receipt = write_receipt(
        receipt_dir / "04-synthetic-classification.receipt.json",
        {
            "schema_version": "artifact-synthetic-classification-receipt.v1",
            "dispatch_id": DISPATCH_ID,
            "stage": "synthetic-classification",
            "manifest_sha256": manifest["manifest_sha256"],
            "lifecycle_state": "failed",
            "scope": "dispatch_owned_synthetic_test_cache_only",
            "authorizes_operation": False,
            "checked_at": now_iso(),
        },
    )
    artifact_id = manifest["artifacts"][0]["artifact_id"]
    run_cli("05-explain", ["explain", "--manifest", str(manifest_path), "--artifact-id", artifact_id], receipt_dir)

    plan_path = control / "quarantine-plan.json"
    plan_args = [
        "plan", "quarantine", "--manifest", str(manifest_path), "--root", str(source),
        "--quarantine-root", str(quarantine), "--owner-state", "idle_confirmed",
        "--process-state", "idle_confirmed", "--dispatch-state", "none_active", "--output", str(plan_path),
    ]
    run_cli("06-plan-quarantine", plan_args, receipt_dir)
    plan = core.read_json(plan_path)
    if not all(item["eligible"] for item in plan["entries"]):
        raise RuntimeError("synthetic_plan_not_fully_eligible")
    run_cli(
        "07-verify-plan",
        ["verify-plan", "--plan", str(plan_path), "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(quarantine)],
        receipt_dir,
    )

    approval_path = control / "synthetic-approval.json"
    core.atomic_write_json(approval_path, approval(plan))
    quarantine_receipt = control / "quarantine-receipt.json"
    run_cli(
        "08-apply-quarantine",
        ["apply-quarantine", "--plan", str(plan_path), "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(quarantine), "--approval", str(approval_path), "--receipt", str(quarantine_receipt), "--execute"],
        receipt_dir,
    )
    if any((source / relative).exists() for relative in fixture):
        raise RuntimeError("source_still_present_after_quarantine")
    quarantine_value = core.read_json(quarantine_receipt)
    for item in quarantine_value["items"]:
        if not Path(item["to"]).is_file() or core.sha256_file(Path(item["to"])) != item["digest"]["value"]:
            raise RuntimeError("quarantine_content_validation_failed")

    restore_receipt = control / "restore-receipt.json"
    run_cli(
        "09-restore",
        ["restore", "--plan", str(plan_path), "--receipt", str(quarantine_receipt), "--root", str(source), "--quarantine-root", str(quarantine), "--output", str(restore_receipt), "--execute"],
        receipt_dir,
    )
    assert_fixture(source, fixture)

    post_manifest_1 = control / "manifest-post-restore-1.json"
    post_manifest_2 = control / "manifest-post-restore-2.json"
    run_cli("10-post-restore-scan-first", [*scan_args, "--output", str(post_manifest_1)], receipt_dir)
    run_cli("11-post-restore-scan-second", [*scan_args, "--output", str(post_manifest_2)], receipt_dir)
    post_first = core.read_json(post_manifest_1)
    post_second = core.read_json(post_manifest_2)
    if post_first["manifest_sha256"] != post_second["manifest_sha256"]:
        raise RuntimeError("post_restore_double_scan_hash_mismatch")
    if post_first["manifest_sha256"] != raw_first["manifest_sha256"]:
        raise RuntimeError("restored_manifest_hash_mismatch")

    drift_target = source / "cache-alpha.txt"
    original = drift_target.read_bytes()
    drift_target.write_bytes(original + b"drift\n")
    try:
        run_cli(
            "negative-file-drift",
            ["verify-plan", "--plan", str(plan_path), "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(quarantine)],
            receipt_dir,
            expected_returncodes={2},
        )
    finally:
        drift_target.write_bytes(original)
    assert_fixture(source, fixture)

    expired_approval_path = control / "expired-approval.json"
    core.atomic_write_json(expired_approval_path, approval(plan, expired=True))
    run_cli(
        "negative-expired-approval",
        ["apply-quarantine", "--plan", str(plan_path), "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(quarantine), "--approval", str(expired_approval_path), "--receipt", str(control / "must-not-exist-expired.json"), "--execute"],
        receipt_dir,
        expected_returncodes={2},
    )
    assert_fixture(source, fixture)

    bad_plan = dict(plan)
    bad_plan["plan_sha256"] = "0" * 64
    bad_plan_path = control / "bad-hash-plan.json"
    core.atomic_write_json(bad_plan_path, bad_plan)
    run_cli(
        "negative-plan-hash",
        ["verify-plan", "--plan", str(bad_plan_path), "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(quarantine)],
        receipt_dir,
        expected_returncodes={2},
    )

    escaped_manifest = json.loads(json.dumps(manifest))
    escaped_manifest["artifacts"][0]["path"] = "../outside.txt"
    escaped_manifest = core.attach_hash(
        {key: value for key, value in escaped_manifest.items() if key != "manifest_sha256"},
        "manifest_sha256",
    )
    escaped_manifest_path = control / "escaped-manifest.json"
    core.atomic_write_json(escaped_manifest_path, escaped_manifest)
    run_cli(
        "negative-path-escape",
        ["plan", "quarantine", "--manifest", str(escaped_manifest_path), "--root", str(source), "--quarantine-root", str(quarantine), "--owner-state", "idle_confirmed", "--process-state", "idle_confirmed", "--dispatch-state", "none_active", "--output", str(control / "must-not-exist-escape-plan.json")],
        receipt_dir,
        expected_returncodes={2},
    )

    cross_volume_root = Path(os.environ.get("SystemRoot", "C:/Windows")) / "Temp"
    if cross_volume_root.is_dir() and core.volume_identity(source) != core.volume_identity(cross_volume_root):
        run_cli(
            "negative-cross-volume",
            ["plan", "quarantine", "--manifest", str(manifest_path), "--root", str(source), "--quarantine-root", str(cross_volume_root), "--owner-state", "idle_confirmed", "--process-state", "idle_confirmed", "--dispatch-state", "none_active", "--output", str(control / "must-not-exist-cross-volume-plan.json")],
            receipt_dir,
            expected_returncodes={2},
        )
        cross_volume_status = "blocked_as_expected"
    else:
        cross_volume_status = "skipped_no_distinct_existing_volume"

    link_root = runtime_root / "negative-link" / "source"
    link_quarantine = runtime_root / "negative-link" / "quarantine"
    link_root.mkdir(parents=True)
    link_quarantine.mkdir(parents=True)
    (link_root / "regular.txt").write_text("regular synthetic cache\n", encoding="utf-8")
    link = link_root / "linked.txt"
    try:
        link.symlink_to(link_root / "regular.txt")
        run_cli(
            "negative-reparse-scan",
            ["scan", "--root", str(link_root), "--profile", "test_cache", "--producer-tool-id", "artifact-lifecycle-core", "--owner-lane", "local-tools", "--closure-run-id", closure_run_id + "-link", "--output", str(control / "link-manifest.json"), "--checkpoint", str(control / "link-checkpoint.sqlite3"), "--max-files", "20"],
            receipt_dir,
        )
        reparse_status = "scan_recorded_reparse_error"
    except OSError as error:
        reparse_status = f"skipped_host_denied_link_creation:{type(error).__name__}"
        write_receipt(
            receipt_dir / "negative-reparse-scan.receipt.json",
            {
                "schema_version": "artifact-synthetic-pilot-stage-receipt.v1",
                "dispatch_id": DISPATCH_ID,
                "stage": "negative-reparse-scan",
                "status": "skipped_host_denied_link_creation",
                "error_class": type(error).__name__,
                "checked_at": now_iso(),
            },
        )

    directory_root = runtime_root / "negative-directory-drift" / "source"
    directory_quarantine = runtime_root / "negative-directory-drift" / "quarantine"
    directory_control = runtime_root / "negative-directory-drift" / "control"
    directory_root.mkdir(parents=True)
    directory_quarantine.mkdir(parents=True)
    directory_control.mkdir(parents=True)
    (directory_root / "cache.txt").write_text("directory drift cache\n", encoding="utf-8")
    directory_manifest_path = directory_control / "manifest.json"
    run_cli(
        "negative-directory-drift-scan",
        ["scan", "--root", str(directory_root), "--profile", "test_cache", "--producer-tool-id", "artifact-lifecycle-core", "--owner-lane", "local-tools", "--closure-run-id", closure_run_id + "-directory", "--output", str(directory_manifest_path), "--checkpoint", str(directory_control / "checkpoint.sqlite3"), "--max-files", "20"],
        receipt_dir,
    )
    directory_manifest = eligible_manifest(directory_manifest_path, "roundtrip-receipts/negative-directory-drift-scan.receipt.json")
    directory_plan_path = directory_control / "plan.json"
    run_cli(
        "negative-directory-drift-plan",
        ["plan", "quarantine", "--manifest", str(directory_manifest_path), "--root", str(directory_root), "--quarantine-root", str(directory_quarantine), "--owner-state", "idle_confirmed", "--process-state", "idle_confirmed", "--dispatch-state", "none_active", "--output", str(directory_plan_path)],
        receipt_dir,
    )
    directory_old = directory_root.with_name("source-before-drift")
    os.replace(directory_root, directory_old)
    directory_root.mkdir()
    (directory_root / "cache.txt").write_text("directory drift cache\n", encoding="utf-8")
    run_cli(
        "negative-directory-drift-verify",
        ["verify-plan", "--plan", str(directory_plan_path), "--manifest", str(directory_manifest_path), "--root", str(directory_root), "--quarantine-root", str(directory_quarantine)],
        receipt_dir,
        expected_returncodes={2},
    )

    run_cli(
        "negative-purge-disabled",
        ["apply-purge", "--plan", str(plan_path), "--execute"],
        receipt_dir,
        expected_returncodes={2},
    )

    with mock.patch.object(global_audit.subprocess, "run", side_effect=PermissionError("synthetic denied")):
        denied = global_audit.invoke_root_worker(
            "artifact-lifecycle-core",
            source,
            runtime_root / "negative-access-denied",
            timeout_seconds=1,
            max_nodes=20,
            max_depth=4,
        )
    access_denied_receipt = write_receipt(
        receipt_dir / "negative-access-denied.receipt.json",
        {
            "schema_version": "artifact-synthetic-pilot-stage-receipt.v1",
            "dispatch_id": DISPATCH_ID,
            "stage": "negative-access-denied",
            "injection": "PermissionError at isolated root worker boundary; no ACL changed",
            "result": denied,
            "global_run_continued": True,
            "checked_at": now_iso(),
        },
    )
    run_cli("12-post-negative-doctor", ["doctor", "--target-root", str(source), "--profile", "test_cache"], receipt_dir)

    total_bytes = sum(item["bytes"] for item in manifest["artifacts"])
    release_lower = sum(
        item["bytes"]
        for item in manifest["artifacts"]
        if not item["referenced_by"]
        and item["file_identity"]["hardlink_count"] == item["file_identity"]["observed_links"]
    )
    earliest = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=24)).replace(microsecond=0)
    candidate_plan = {
        "schema_version": "artifact-lifecycle-real-candidate-plan-only.v1",
        "dispatch_id": DISPATCH_ID,
        "status": "plan_only_observation_required",
        "authorizes_operation": False,
        "cleanup_mode": "plan_only",
        "automatic_purge": False,
        "owner": "local-tools",
        "root": str(source),
        "source_kind": "dispatch_created_synthetic_test_cache",
        "evidence_refs": [
            str(manifest_path),
            str(quarantine_receipt),
            str(restore_receipt),
        ],
        "logical_bytes": total_bytes,
        "physical_release_lower_bound_bytes": release_lower,
        "candidate_count": len(manifest["artifacts"]),
        "blockers": [
            "minimum_24h_observation_not_elapsed",
            "fresh_plan_and_approval_required",
            "real_quarantine_not_authorized_by_this_candidate_list",
        ],
        "recovery_entry": f"python {CLI} restore --plan <fresh-plan> --receipt <quarantine-receipt> --root {source} --quarantine-root {quarantine} --output <restore-receipt> --execute",
        "earliest_observation_at": earliest.isoformat().replace("+00:00", "Z"),
        "entries": [
            {
                "artifact_id": item["artifact_id"],
                "path": str(source / item["path"]),
                "digest": item["digest"],
                "bytes": item["bytes"],
                "owner": item["owner_lane"],
                "referenced_by": item["referenced_by"],
                "hardlink_coverage_complete": item["file_identity"]["hardlink_count"] == item["file_identity"]["observed_links"],
            }
            for item in manifest["artifacts"]
        ],
    }
    candidate_path = output_root / "real-candidate-plan-only.v1.json"
    core.atomic_write_json(candidate_path, candidate_plan)

    summary = write_receipt(
        output_root / f"{DISPATCH_ID}.roundtrip-receipt.json",
        {
            "schema_version": "artifact-synthetic-roundtrip-receipt.v1",
            "dispatch_id": DISPATCH_ID,
            "goal_status": "completed",
            "synthetic_root": str(runtime_root),
            "closure_run_id": closure_run_id,
            "fixture": fixture,
            "manifest_sha256": manifest["manifest_sha256"],
            "plan_sha256": plan["plan_sha256"],
            "quarantine_receipt_sha256": core.read_json(quarantine_receipt)["receipt_sha256"],
            "restore_receipt_sha256": core.read_json(restore_receipt)["receipt_sha256"],
            "double_run_hash": raw_first["manifest_sha256"],
            "roundtrip_restored": True,
            "original_paths_restored": True,
            "content_hashes_restored": True,
            "bytes_restored": True,
            "classification_receipt_sha256": classification_receipt["receipt_sha256"],
            "negative_tests": {
                "file_drift": "blocked",
                "directory_identity_drift": "blocked",
                "expired_approval": "blocked",
                "plan_hash_mismatch": "blocked",
                "path_escape": "blocked",
                "cross_volume": cross_volume_status,
                "reparse_or_symlink": reparse_status,
                "access_denied": access_denied_receipt["result"]["status"],
                "purge": "blocked_by_policy",
            },
            "candidate_plan_ref": str(candidate_path),
            "real_history_or_business_file_mutation_count": 0,
            "synthetic_quarantine_move_count": len(manifest["artifacts"]),
            "synthetic_restore_move_count": len(manifest["artifacts"]),
            "purge_enabled": False,
            "completed_at": now_iso(),
        },
    )
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the dispatch-scoped synthetic quarantine/restore pilot.")
    parser.add_argument("--runtime-root", type=Path)
    parser.add_argument("--output-root", type=Path)
    parser.add_argument("--sanitize-output-root", type=Path)
    parser.add_argument("--sanitize-only", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        sanitized = None
        if args.sanitize_output_root:
            sanitized = sanitize_existing_receipts(args.sanitize_output_root)
            if sanitized["status"] != "ok":
                print(json.dumps(sanitized, ensure_ascii=False, indent=2))
                return 2
        if args.sanitize_only:
            print(json.dumps(sanitized or {"status": "nothing_to_sanitize"}, ensure_ascii=False, indent=2))
            return 0
        if not args.runtime_root or not args.output_root:
            raise RuntimeError("runtime_root_and_output_root_required")
        result = run_pilot(args.runtime_root.resolve(strict=False), args.output_root.resolve(strict=False))
    except Exception as error:
        print(json.dumps({"status": "failed", "error_class": type(error).__name__, "detail": str(error)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps({"status": "completed", "receipt_sha256": result["receipt_sha256"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
