from __future__ import annotations

import datetime as dt
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import artifact_lifecycle_core as core


def managed_test_root() -> Path:
    value = os.environ.get("TEST_TMP_ROOT")
    managed = os.environ.get("CODEX_MANAGED_TEST_RUN")
    if not value or not managed:
        raise RuntimeError("managed_test_runtime_required")
    root = Path(value).resolve()
    if root != Path(managed).resolve():
        raise RuntimeError("managed_test_root_mismatch")
    if not (root / "run-manifest.json").is_file():
        raise RuntimeError("managed_test_run_manifest_missing")
    return root


class CoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = managed_test_root() / f"case-{uuid.uuid4().hex}"
        self.base.mkdir(mode=0o777)
        self.root = self.base / "workspace"
        self.quarantine = self.base / "quarantine"
        self.root.mkdir()
        self.quarantine.mkdir()
        (self.root / "cache.txt").write_text("synthetic cache artifact\n", encoding="utf-8")

    def tearDown(self) -> None:
        if self.base.exists():
            shutil.rmtree(self.base)

    def test_unmanaged_runtime_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(RuntimeError, "managed_test_runtime_required"):
                managed_test_root()

    def scan(self) -> dict:
        return core.scan_root(
            self.root,
            profile_id="test_cache",
            producer_tool_id="synthetic-tool",
            owner_lane="local-tools",
            closure_run_id="closure-synthetic-001",
            max_files=20,
            checkpoint=self.base / "checkpoint.sqlite3",
        )

    def eligible_manifest(self) -> dict:
        manifest = self.scan()
        item = manifest["artifacts"][0]
        item["lifecycle_state"] = "failed"
        manifest = core.attach_hash({key: value for key, value in manifest.items() if key != "manifest_sha256"}, "manifest_sha256")
        self.assertEqual([], core.validate_manifest(manifest))
        return manifest

    def plan(self, manifest: dict) -> dict:
        return core.plan_operation(
            manifest,
            self.root,
            self.quarantine,
            "quarantine",
            owner_state="idle_confirmed",
            process_state="idle_confirmed",
            dispatch_state="none_active",
        )

    def approval(self, plan: dict) -> dict:
        now = dt.datetime.now(dt.timezone.utc)
        return {
            "schema_version": core.APPROVAL_SCHEMA_VERSION,
            "operation": "quarantine",
            "plan_sha256": plan["plan_sha256"],
            "approved": True,
            "approved_by": "synthetic-test-reviewer",
            "approved_at": now.isoformat(),
            "expires_at": (now + dt.timedelta(hours=1)).isoformat(),
        }

    def test_doctor_and_profiles(self) -> None:
        result = core.doctor(ROOT)
        self.assertEqual("ready", result["status"])
        self.assertTrue(result["contract_ready"])
        self.assertFalse(result["real_usage_proof"])
        self.assertFalse(result["current_online"])
        self.assertFalse(result["automatic_purge"])

        profiles = core.read_json(ROOT / "profiles" / "artifact-lifecycle-profiles.v1.json")
        test_cache = next(
            item for item in profiles["profiles"] if item["profile_id"] == "test_cache"
        )
        self.assertEqual("scripts/windows_test_runtime.py test-cache", test_cache["owner_adapter"])
        self.assertTrue(test_cache["explicit_root_required"])
        self.assertFalse(test_cache["bounded_scan"]["recursive_workspace_scan"])
        self.assertEqual(7, test_cache["retention"]["failure_days"])
        self.assertEqual("blocked", test_cache["retention"]["active_child"])
        self.assertFalse(test_cache["automatic_purge"])

    def test_large_profile_low_disk_blocks(self) -> None:
        usage = shutil._ntuple_diskusage(total=1000, used=900, free=100)
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            result = core.doctor(ROOT, self.root, "media")
        self.assertEqual("blocked", result["status"])
        self.assertIn("blocked_low_disk", result["reason_codes"])

    def test_low_percentage_with_two_gib_free_is_warning_not_block(self) -> None:
        total = 1024 * core.GIB
        usage = shutil._ntuple_diskusage(total=total, used=total - (2 * core.GIB), free=2 * core.GIB)
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            result = core.doctor(ROOT, self.root, "media")
        self.assertEqual("ready", result["status"])
        self.assertTrue(result["runtime_ready"])
        self.assertEqual("low_disk_allowed", result["disk"]["status"])
        self.assertIn("low_disk_allowed", result["reason_codes"])
        self.assertEqual(512 * core.MIB, result["disk"]["minimum_free_bytes"])

    def test_estimated_output_and_headroom_can_still_block(self) -> None:
        total = 1024 * core.GIB
        usage = shutil._ntuple_diskusage(total=total, used=total - (2 * core.GIB), free=2 * core.GIB)
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            result = core.doctor(ROOT, self.root, "media", estimated_output_bytes=2 * core.GIB)
        self.assertEqual("blocked", result["status"])
        self.assertEqual("blocked_low_disk", result["disk"]["status"])
        self.assertEqual(3 * core.GIB, result["disk"]["required_free_bytes"])

    def test_scan_is_deterministic_and_checkpoint_valid(self) -> None:
        first = self.scan()
        second = self.scan()
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        self.assertEqual([], core.validate_manifest(first))
        connection = sqlite3.connect(self.base / "checkpoint.sqlite3")
        try:
            self.assertEqual("ok", connection.execute("PRAGMA integrity_check").fetchone()[0])
        finally:
            connection.close()

    def test_plan_is_deterministic(self) -> None:
        manifest = self.eligible_manifest()
        first = self.plan(manifest)
        second = self.plan(manifest)
        self.assertEqual(first["plan_sha256"], second["plan_sha256"])
        self.assertEqual([], core.validate_plan(first))
        self.assertTrue(first["entries"][0]["eligible"])

    def test_unknown_owner_process_dispatch_fail_closed(self) -> None:
        manifest = self.eligible_manifest()
        plan = core.plan_operation(
            manifest, self.root, self.quarantine, "quarantine",
            owner_state="unknown", process_state="unknown", dispatch_state="unknown",
        )
        blockers = plan["entries"][0]["blocking_gates"]
        self.assertIn("owner_not_idle_confirmed", blockers)
        self.assertIn("active_process_not_cleared", blockers)
        self.assertIn("dispatch_not_cleared", blockers)
        self.assertFalse(plan["entries"][0]["eligible"])

    def test_reference_and_pin_fail_closed(self) -> None:
        manifest = self.eligible_manifest()
        manifest["artifacts"][0]["pin"] = True
        manifest["artifacts"][0]["referenced_by"] = ["synthetic-authoritative-ref"]
        manifest = core.attach_hash({key: value for key, value in manifest.items() if key != "manifest_sha256"}, "manifest_sha256")
        blockers = self.plan(manifest)["entries"][0]["blocking_gates"]
        self.assertIn("artifact_pinned", blockers)
        self.assertIn("authoritative_reference_present", blockers)

    def test_plan_drift_is_detected(self) -> None:
        manifest = self.eligible_manifest()
        plan = self.plan(manifest)
        (self.root / "cache.txt").write_text("changed after plan", encoding="utf-8")
        result = core.verify_plan(plan, manifest, self.root, self.quarantine)
        self.assertFalse(result["ok"])
        self.assertIn(f"artifact_digest_drift:{manifest['artifacts'][0]['artifact_id']}", result["errors"])

    def test_quarantine_restore_round_trip(self) -> None:
        manifest = self.eligible_manifest()
        plan = self.plan(manifest)
        receipt_path = self.base / "quarantine-receipt.json"
        receipt = core.apply_quarantine(plan, manifest, self.root, self.quarantine, self.approval(plan), receipt_path)
        self.assertFalse((self.root / "cache.txt").exists())
        self.assertTrue(Path(receipt["items"][0]["to"]).exists())
        restore_path = self.base / "restore-receipt.json"
        restored = core.restore_from_receipt(receipt, plan, self.root, self.quarantine, restore_path)
        self.assertTrue((self.root / "cache.txt").exists())
        self.assertTrue(core.verify_hash(restored, "receipt_sha256"))

    def test_expired_approval_blocks_without_mutation(self) -> None:
        manifest = self.eligible_manifest()
        plan = self.plan(manifest)
        approval = self.approval(plan)
        approval["expires_at"] = "2000-01-01T00:00:00Z"
        with self.assertRaises(core.LifecycleError) as caught:
            core.apply_quarantine(plan, manifest, self.root, self.quarantine, approval, self.base / "receipt.json")
        self.assertEqual("QUARANTINE_BLOCKED", caught.exception.code)
        self.assertTrue((self.root / "cache.txt").exists())

    def test_purge_is_permanently_disabled(self) -> None:
        rc = core.main(["apply-purge", "--plan", str(self.base / "does-not-matter.json"), "--execute"])
        self.assertEqual(2, rc)
        self.assertTrue((self.root / "cache.txt").exists())

    def test_self_media_v2_compatibility_view(self) -> None:
        source = core.read_json(ROOT / "fixtures" / "synthetic" / "self-media-v2.json")
        converted = core.convert_self_media_v2(source)
        self.assertEqual(core.SCHEMA_VERSION, converted["schema_version"])
        self.assertEqual("media", converted["profile_id"])
        self.assertEqual([], core.validate_manifest(converted))
        self.assertEqual(core.SELF_MEDIA_V2, converted["compatibility_source"])

    def test_agent_manifest_is_metadata_only(self) -> None:
        manifest = core.read_json(ROOT / "agent-tool-manifest.v1.json")
        self.assertEqual("artifact-lifecycle-core", manifest["id"])
        self.assertTrue(manifest["notTrustedAsInstruction"])
        self.assertEqual("none_metadata_only", manifest["executionAuthority"])
        self.assertFalse(manifest["health"]["proves_current_online"])

    @unittest.skipUnless(hasattr(os, "link"), "hard links unavailable")
    def test_incomplete_hardlink_coverage_blocks(self) -> None:
        outside = self.base / "other-link.txt"
        os.link(self.root / "cache.txt", outside)
        manifest = self.eligible_manifest()
        plan = self.plan(manifest)
        self.assertIn("hardlink_coverage_incomplete", plan["entries"][0]["blocking_gates"])

    def test_symlink_scan_records_fail_closed_error(self) -> None:
        target = self.base / "outside.txt"
        target.write_text("outside", encoding="utf-8")
        link = self.root / "linked.txt"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("symlink creation not permitted")
        manifest = self.scan()
        self.assertTrue(manifest["scan"]["errors"])
        manifest["artifacts"][0]["lifecycle_state"] = "failed"
        manifest = core.attach_hash({key: value for key, value in manifest.items() if key != "manifest_sha256"}, "manifest_sha256")
        self.assertIn("scan_errors_present", self.plan(manifest)["entries"][0]["blocking_gates"])

    def test_dirty_git_blocks(self) -> None:
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        manifest = self.eligible_manifest()
        plan = self.plan(manifest)
        self.assertIn("git_dirty", plan["entries"][0]["blocking_gates"])

    def test_path_escape_rejected(self) -> None:
        manifest = self.eligible_manifest()
        manifest["artifacts"][0]["path"] = "../outside.txt"
        manifest = core.attach_hash({key: value for key, value in manifest.items() if key != "manifest_sha256"}, "manifest_sha256")
        with self.assertRaises(core.LifecycleError) as caught:
            self.plan(manifest)
        self.assertEqual("PATH_OUTSIDE_ROOT", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
