from __future__ import annotations

import datetime as dt
import json
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

import artifact_lifecycle_core as core
import project_artifact_adapter as adapter

from test_artifact_lifecycle_core import managed_test_root


class ProjectArtifactAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = managed_test_root() / f"project-adapter-{uuid.uuid4().hex}"
        self.repo = self.base / "repo"
        self.root = self.repo / "fixtures" / "artifacts"
        self.quarantine = self.base / "quarantine"
        self.root.mkdir(parents=True)
        self.quarantine.mkdir()
        self.config = self.repo / "artifact-lifecycle" / "adapter.v1.json"
        self.config.parent.mkdir()
        self._write("build/candidate.bin", "candidate")
        self._write("runtime/route.json", "protected")
        self.config.write_text(json.dumps({
            "schema_version": adapter.SCHEMA_VERSION,
            "profile_id": "build_dist",
            "producer_tool_id": "synthetic-project",
            "owner_lane": "local-tools",
            "repository_root_parents": 1,
            "synthetic_only": True,
            "allowed_roots": ["fixtures/artifacts"],
            "default": {"artifact_role": "unknown", "referenced_by": ["unknown"], "pin": True},
            "rules": [
                {"path": "build/candidate.bin", "artifact_role": "duplicate_or_obsolete", "lifecycle_state": "failed", "referenced_by": [], "pin": False, "rebuild_proof": {"status": "verified", "command": "synthetic-rebuild", "input_hashes": ["fixture"], "dependency_lock": "fixture", "verification_ref": "runtime/route.json"}},
                {"path": "runtime/route.json", "artifact_role": "runtime_state", "lifecycle_state": "verified", "referenced_by": ["receipt"], "pin": True}
            ]
        }), encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)

    def _write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_scan_plan_drift_and_synthetic_round_trip(self) -> None:
        manifest = adapter.build_manifest(self.config, self.root, "closure-project-adapter", self.base / "checkpoint.sqlite3")
        repeat = adapter.build_manifest(self.config, self.root, "closure-project-adapter", self.base / "checkpoint.sqlite3")
        self.assertEqual(manifest["manifest_sha256"], repeat["manifest_sha256"])
        self.assertEqual([], core.validate_manifest(manifest))
        plan = core.plan_operation(manifest, self.root, self.quarantine, "quarantine", owner_state="idle_confirmed", process_state="idle_confirmed", dispatch_state="none_active")
        candidate_id = next(item["artifact_id"] for item in manifest["artifacts"] if item["path"] == "build/candidate.bin")
        protected_id = next(item["artifact_id"] for item in manifest["artifacts"] if item["path"] == "runtime/route.json")
        candidate = next(item for item in plan["entries"] if item["artifact_id"] == candidate_id)
        protected = next(item for item in plan["entries"] if item["artifact_id"] == protected_id)
        self.assertTrue(candidate["eligible"])
        self.assertFalse(protected["eligible"])
        self.assertTrue(core.verify_plan(plan, manifest, self.root, self.quarantine)["ok"])
        (self.root / "build" / "candidate.bin").write_text("drift", encoding="utf-8")
        self.assertFalse(core.verify_plan(plan, manifest, self.root, self.quarantine)["ok"])
        manifest = adapter.build_manifest(self.config, self.root, "closure-project-adapter", self.base / "checkpoint.sqlite3")
        plan = core.plan_operation(manifest, self.root, self.quarantine, "quarantine", owner_state="idle_confirmed", process_state="idle_confirmed", dispatch_state="none_active")
        now = dt.datetime.now(dt.timezone.utc)
        approval = {"schema_version": core.APPROVAL_SCHEMA_VERSION, "operation": "quarantine", "plan_sha256": plan["plan_sha256"], "approved": True, "approved_by": "synthetic-test", "approved_at": now.isoformat(), "expires_at": (now + dt.timedelta(minutes=5)).isoformat()}
        receipt = core.apply_quarantine(plan, manifest, self.root, self.quarantine, approval, self.base / "quarantine-receipt.json")
        self.assertFalse((self.root / "build" / "candidate.bin").exists())
        core.restore_from_receipt(receipt, plan, self.root, self.quarantine, self.base / "restore-receipt.json")
        self.assertTrue((self.root / "build" / "candidate.bin").exists())

    def test_retired_status_and_unconfigured_root_fail_closed(self) -> None:
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter.build_manifest(self.config, self.base, "closure-project-adapter", self.base / "blocked.sqlite3")
        self.assertEqual("ADAPTER_ROOT_NOT_CONFIGURED", caught.exception.code)
        payload = json.loads(self.config.read_text(encoding="utf-8"))
        payload["retired_disabled"] = True
        self.config.write_text(json.dumps(payload), encoding="utf-8")
        report = adapter.doctor(self.config, self.root)
        self.assertEqual("retired_disabled", report["status"])
        self.assertFalse(report["runtime_ready"])
        self.assertFalse(report["current_online"])

        class Args:
            config = self.config
            root = self.root
            quarantine_root = self.quarantine
            manifest = self.base / "manifest.json"

        with self.assertRaises(adapter.AdapterError) as plan_blocked:
            adapter._load_plan_args(Args())
        self.assertEqual("RETIRED_DISABLED", plan_blocked.exception.code)

    def test_non_large_profile_doctor_accepts_null_disk_status(self) -> None:
        payload = json.loads(self.config.read_text(encoding="utf-8"))
        payload["profile_id"] = "research_evidence"
        self.config.write_text(json.dumps(payload), encoding="utf-8")
        report = adapter.doctor(self.config, self.root)
        self.assertEqual("ready", report["status"])
        self.assertIsNone(report["disk"])
        self.assertTrue(report["runtime_ready"])

    def test_optional_disk_preflight_applies_to_test_cache(self) -> None:
        payload = json.loads(self.config.read_text(encoding="utf-8"))
        payload["profile_id"] = "test_cache"
        payload["disk_preflight"] = {
            "minimum_free_bytes": 512,
            "warning_free_bytes": 1024,
            "estimated_output_bytes": 512,
            "output_headroom_multiplier": 1.25,
        }
        self.config.write_text(json.dumps(payload), encoding="utf-8")
        usage = shutil._ntuple_diskusage(total=4096, used=3700, free=396)
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            report = adapter.doctor(self.config, self.root)
        self.assertEqual("blocked", report["status"])
        self.assertEqual("blocked_low_disk", report["disk_preflight"])
        self.assertIn("blocked_low_disk", report["reason_codes"])
