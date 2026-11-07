from __future__ import annotations

import json
import errno
import os
import shutil
import unittest
import uuid
from pathlib import Path
from unittest import mock

import artifact_lifecycle_core as core
import artifact_lifecycle_demo as demo
import release_readiness
import run_tests


ROOT = Path(__file__).resolve().parents[1]


class ReleaseReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        managed = os.environ.get("TEST_TMP_ROOT")
        managed_run = os.environ.get("CODEX_MANAGED_TEST_RUN")
        if not managed or not managed_run:
            self.fail("managed_windows_test_runtime_required")
        managed_root = Path(managed).resolve()
        if managed_root != Path(managed_run).resolve():
            self.fail("managed_windows_test_root_mismatch")
        self.root = managed_root / f"release-readiness-{uuid.uuid4().hex}"
        self.root.mkdir()

    def tearDown(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)

    def test_installed_asset_fallback_is_self_contained(self) -> None:
        data_root = self.root / "environment-data"
        asset_root = data_root / "share" / "artifact-lifecycle-core"
        shutil.copytree(ROOT / "schemas", asset_root / "schemas")
        shutil.copytree(ROOT / "profiles", asset_root / "profiles")
        for name in ("agent-tool-manifest.v1.json", "AGENT_DISCOVERY.md"):
            shutil.copy2(ROOT / name, asset_root / name)
        module_root = self.root / "site-packages"
        module_root.mkdir()
        with mock.patch.object(core.sysconfig, "get_path", return_value=str(data_root)):
            result = core.doctor(module_root)
        self.assertEqual("ready", result["status"])
        self.assertEqual("installed_data_files", result["asset_root_mode"])
        self.assertFalse(result["current_online"])
        self.assertFalse(result["real_usage_proof"])

    def test_synthetic_demo_roundtrip_and_idempotent_receipt(self) -> None:
        workspace = self.root / "unicode-验收" / ("long-segment-" + "x" * 80)
        first_code, first = demo.run_demo(workspace, "demo-01")
        self.assertEqual(0, first_code, first)
        self.assertEqual("completed", first["status"])
        self.assertTrue(first["roundtrip_restored"])
        self.assertFalse(first["purge_enabled"])
        self.assertEqual(0, first["real_history_or_business_file_mutation_count"])

        second_code, second = demo.run_demo(workspace, "demo-01")
        self.assertEqual(0, second_code, second)
        self.assertEqual("completed_idempotent_replay", second["status"])
        self.assertEqual(first["receipt_sha256"], second["receipt_sha256"])

    def test_partial_or_invalid_demo_fails_closed_with_recovery(self) -> None:
        workspace = self.root / "partial"
        (workspace / "demo-02").mkdir(parents=True)
        code, result = demo.run_demo(workspace, "demo-02")
        self.assertEqual(2, code)
        self.assertEqual("DEMO_PARTIAL_RUN_PRESENT", result["error_code"])
        self.assertIn("recovery_entry", result)

        code, result = demo.run_demo(workspace, "../escape")
        self.assertEqual(2, code)
        self.assertEqual("DEMO_RUN_ID_INVALID", result["error_code"])

    def test_access_denied_is_structured_with_recovery(self) -> None:
        workspace = self.root / "access-denied"
        workspace.mkdir()
        error = core.LifecycleError("PATH_ACCESS_DENIED", "synthetic")
        with mock.patch.object(core, "assert_no_reparse", side_effect=error):
            code, result = demo.run_demo(workspace, "demo-03")
        self.assertEqual(2, code)
        self.assertEqual("PATH_ACCESS_DENIED", result["error_code"])
        self.assertIn("recovery_entry", result)

    def test_manifest_portability_is_metadata_only(self) -> None:
        manifest = json.loads((ROOT / "agent-tool-manifest.v1.json").read_text(encoding="utf-8"))
        self.assertEqual("none_metadata_only", manifest["executionAuthority"])
        self.assertTrue(manifest["notTrustedAsInstruction"])
        self.assertIn("public_release_not_claimed", manifest["portability"]["gaps"])
        self.assertEqual("Apache-2.0", manifest["license"]["spdx"])

    def test_filesystem_preflight_errors_are_structured(self) -> None:
        for error, expected in (
            (PermissionError(errno.EACCES, "synthetic"), "PATH_ACCESS_DENIED"),
            (OSError(errno.EROFS, "synthetic"), "PATH_ACCESS_DENIED"),
            (OSError(errno.ENAMETOOLONG, "synthetic"), "PATH_TOO_LONG"),
        ):
            with self.subTest(expected=expected), mock.patch.object(Path, "mkdir", side_effect=error):
                code, result = demo.run_demo(self.root / "unwritable", "demo-01")
            self.assertEqual(2, code)
            self.assertEqual(expected, result["error_code"])
            self.assertIn("recovery_entry", result)

    def test_corrupt_existing_receipt_is_not_success(self) -> None:
        run = self.root / "demo-01"
        run.mkdir()
        (run / "demo-receipt.json").write_text("{broken", encoding="utf-8")
        code, result = demo.run_demo(self.root, "demo-01")
        self.assertEqual(2, code)
        self.assertEqual("DEMO_RECEIPT_INVALID", result["error_code"])

    def test_no_git_allows_doctor_but_blocks_demo_before_mutation(self) -> None:
        workspace = self.root / "no-git"
        with mock.patch.object(demo.shutil, "which", return_value=None):
            self.assertEqual("ready", core.doctor(ROOT)["status"])
            code, result = demo.run_demo(workspace, "demo-01")
        self.assertEqual(2, code)
        self.assertEqual("GIT_UNAVAILABLE", result["error_code"])
        self.assertFalse(workspace.exists())

    def test_delivery_excludes_all_managed_runtime_variants(self) -> None:
        source = self.root / "source"
        source.mkdir()
        (source / "README.md").write_text("synthetic", encoding="utf-8")
        for name in (".test-runtime-pass3", ".test-runtime-new"):
            runtime = source / name
            runtime.mkdir()
            (runtime / "private-log.txt").write_text("not for distribution", encoding="utf-8")
        with mock.patch.object(run_tests, "ROOT", source):
            files, excluded, _, errors = run_tests.delivery_file_list()
        self.assertEqual(["README.md"], files)
        self.assertEqual(2, len(excluded))
        self.assertEqual([], errors)

    def test_bundled_runtime_precedes_workspace_sibling(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual((ROOT / "tools/windows_test_runtime.py").resolve(),
                             run_tests.find_windows_test_runtime(None))

    def test_bundled_runtime_includes_its_failure_catalog(self) -> None:
        runtime = run_tests.load_runtime(ROOT / "tools/windows_test_runtime.py")
        catalog_path = ROOT / "tools/contracts/windows-failure-catalog.json"
        self.assertEqual(catalog_path, runtime.FAILURE_CATALOG_PATH)
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        entry = next(row for row in catalog["entries"]
                     if row["failure_class"] == "code_assertion_failure")
        self.assertFalse(entry["retryable"])
        self.assertFalse(entry["network_access_allowed"])
        self.assertEqual("code_assertion_failure",
                         runtime.failure_policy("code_assertion_failure")["failure_class"])
        files, _, _, errors = run_tests.delivery_file_list()
        self.assertEqual([], errors)
        self.assertIn("tools/contracts/windows-failure-catalog.json",
                      [name.replace("\\", "/") for name in files])

    def test_portable_delivery_excludes_workspace_governance_records(self) -> None:
        files, _, excluded_files, errors = run_tests.delivery_file_list()
        self.assertEqual([], errors)
        self.assertNotIn("CHANGE-RATIONALE.md", files)
        self.assertNotIn("registry-lifecycle-declarations.v1.json", files)
        for name in ("CHANGE-RATIONALE.md", "registry-lifecycle-declarations.v1.json"):
            if (ROOT / name).is_file():
                self.assertIn(name, excluded_files)
            else:
                self.assertNotIn(name, excluded_files)
        self.assertIn("RELEASE-NOTES.md", files)

        scan = release_readiness.scan_source_delivery()
        self.assertEqual("passed", scan["status"], scan)
        self.assertEqual([], scan["personal_or_workspace_path_hits"])


if __name__ == "__main__":
    unittest.main()
