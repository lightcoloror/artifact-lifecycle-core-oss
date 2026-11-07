from __future__ import annotations

import datetime as dt
import json
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

import artifact_lifecycle_core as core
import research_evidence_adapter as adapter

from test_artifact_lifecycle_core import managed_test_root


class ResearchEvidenceAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.base = managed_test_root() / f"adapter-{uuid.uuid4().hex}"
        self.repo = self.base / "repo"
        self.root = self.repo / "fixtures" / "research-evidence"
        self.quarantine = self.base / "quarantine"
        self.root.mkdir(parents=True)
        self.quarantine.mkdir()
        self.config_path = self.repo / "artifact-lifecycle" / "research-evidence.v1.json"
        self.config_path.parent.mkdir()
        self._write("evidence-bundle.json", "bundle")
        self._write("receipt.json", "receipt")
        self._write("cache/failed-retrieval.tmp", "cache")
        self._write("unknown.bin", "unknown")
        self.config_path.write_text(json.dumps({
            "schema_version": adapter.ADAPTER_SCHEMA,
            "profile_id": "research_evidence",
            "producer_tool_id": "synthetic-research",
            "owner_lane": "research-evidence",
            "allowed_roots": ["fixtures/research-evidence"],
            "default": {"artifact_role": "evidence_receipt_manifest", "lifecycle_state": "candidate", "referenced_by": ["unknown_reference"], "pin": True},
            "rules": [
                {"path": "evidence-bundle.json", "artifact_role": "authoritative_input", "lifecycle_state": "verified", "referenced_by": ["receipt.json"], "pin": True},
                {"path": "receipt.json", "artifact_role": "evidence_receipt_manifest", "lifecycle_state": "verified", "referenced_by": ["closure"], "pin": True},
                {"path": "cache/failed-retrieval.tmp", "artifact_role": "duplicate_or_obsolete", "lifecycle_state": "failed", "referenced_by": [], "pin": False, "rebuild_proof": {"status": "verified", "command": "rebuild --synthetic", "input_hashes": ["fixture"], "dependency_lock": "fixture-lock", "verification_ref": "receipt.json"}}
            ]
        }, indent=2), encoding="utf-8")

    def tearDown(self) -> None:
        if self.base.exists():
            shutil.rmtree(self.base)

    def _write(self, relative: str, value: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def _scan(self) -> dict:
        return adapter.build_manifest(self.config_path, self.root, "closure-adapter-001", self.base / "checkpoint.sqlite3")

    def test_roles_are_protected_or_explicit_candidates_and_scan_is_stable(self) -> None:
        first = self._scan()
        second = self._scan()
        self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
        self.assertEqual([], core.validate_manifest(first))
        roles = {item["path"]: item for item in first["artifacts"]}
        self.assertTrue(roles["evidence-bundle.json"]["pin"])
        self.assertEqual("authoritative_input", roles["evidence-bundle.json"]["artifact_role"])
        self.assertFalse(roles["cache/failed-retrieval.tmp"]["pin"])
        self.assertEqual("duplicate_or_obsolete", roles["cache/failed-retrieval.tmp"]["artifact_role"])
        self.assertEqual(["unknown_reference"], roles["unknown.bin"]["referenced_by"])

    def test_plan_drift_and_synthetic_quarantine_restore(self) -> None:
        manifest = self._scan()
        plan = core.plan_operation(manifest, self.root, self.quarantine, "quarantine", owner_state="idle_confirmed", process_state="idle_confirmed", dispatch_state="none_active")
        candidate = next(item for item in plan["entries"] if item["artifact_id"] == next(row["artifact_id"] for row in manifest["artifacts"] if row["path"] == "cache/failed-retrieval.tmp"))
        protected = next(item for item in plan["entries"] if item["artifact_id"] == next(row["artifact_id"] for row in manifest["artifacts"] if row["path"] == "evidence-bundle.json"))
        self.assertTrue(candidate["eligible"])
        self.assertIn("artifact_pinned", protected["blocking_gates"])
        self.assertTrue(core.verify_plan(plan, manifest, self.root, self.quarantine)["ok"])
        (self.root / "cache" / "failed-retrieval.tmp").write_text("drift", encoding="utf-8")
        self.assertFalse(core.verify_plan(plan, manifest, self.root, self.quarantine)["ok"])
        manifest = self._scan()
        plan = core.plan_operation(manifest, self.root, self.quarantine, "quarantine", owner_state="idle_confirmed", process_state="idle_confirmed", dispatch_state="none_active")
        now = dt.datetime.now(dt.timezone.utc)
        approval = {"schema_version": core.APPROVAL_SCHEMA_VERSION, "operation": "quarantine", "plan_sha256": plan["plan_sha256"], "approved": True, "approved_by": "synthetic-test", "approved_at": now.isoformat(), "expires_at": (now + dt.timedelta(minutes=5)).isoformat()}
        receipt = core.apply_quarantine(plan, manifest, self.root, self.quarantine, approval, self.base / "quarantine-receipt.json")
        self.assertFalse((self.root / "cache" / "failed-retrieval.tmp").exists())
        core.restore_from_receipt(receipt, plan, self.root, self.quarantine, self.base / "restore-receipt.json")
        self.assertTrue((self.root / "cache" / "failed-retrieval.tmp").exists())

    def test_unconfigured_root_and_low_disk_large_operation_fail_closed(self) -> None:
        with self.assertRaises(adapter.AdapterError) as caught:
            adapter.build_manifest(self.config_path, self.base, "closure-adapter-001", self.base / "other.sqlite3")
        self.assertEqual("ADAPTER_ROOT_NOT_CONFIGURED", caught.exception.code)
        usage = shutil._ntuple_diskusage(total=1000, used=900, free=100)
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            result = adapter.preflight(self.config_path, self.root, "embedding")
        self.assertEqual("blocked", result["status"])
        self.assertIn("blocked_low_disk", result["reason_codes"])

    def test_two_gib_is_warning_only_until_declared_output_exceeds_headroom(self) -> None:
        two_gib = 2 * core.GIB
        usage = shutil._ntuple_diskusage(
            total=1024 * core.GIB,
            used=(1024 * core.GIB) - two_gib,
            free=two_gib,
        )
        with mock.patch.object(core.shutil, "disk_usage", return_value=usage):
            allowed = adapter.preflight(self.config_path, self.root, "embedding")
            blocked = adapter.preflight(
                self.config_path,
                self.root,
                "embedding",
                estimated_output_bytes=2 * core.GIB,
            )
        self.assertEqual("ready", allowed["status"])
        self.assertEqual("low_disk_allowed", allowed["disk"]["status"])
        self.assertTrue(allowed["disk"]["warning_only"])
        self.assertNotIn("minimum_free_ratio", allowed)
        self.assertEqual("blocked", blocked["status"])
        self.assertEqual("blocked_low_disk", blocked["disk"]["status"])

    def test_cli_plan_and_verify_keep_plan_and_manifest_contracts_distinct(self) -> None:
        manifest = self._scan()
        manifest_path = self.base / "manifest.json"
        plan_path = self.base / "plan.json"
        core.atomic_write_json(manifest_path, manifest)
        self.assertEqual(0, adapter.main([
            "plan",
            "--config", str(self.config_path),
            "--root", str(self.root),
            "--manifest", str(manifest_path),
            "--quarantine-root", str(self.quarantine),
            "--output", str(plan_path),
            "--owner-state", "idle_confirmed",
            "--process-state", "idle_confirmed",
            "--dispatch-state", "none_active",
        ]))
        self.assertEqual(0, adapter.main([
            "verify-plan",
            "--config", str(self.config_path),
            "--root", str(self.root),
            "--manifest", str(manifest_path),
            "--plan", str(plan_path),
            "--quarantine-root", str(self.quarantine),
        ]))
