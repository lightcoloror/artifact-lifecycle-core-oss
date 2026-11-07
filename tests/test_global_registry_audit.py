from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("global_registry_audit", ROOT / "global_registry_audit.py")
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


class GlobalRegistryAuditTests(unittest.TestCase):
    def test_current_registry_has_full_declaration_coverage(self) -> None:
        if not MODULE.DEFAULT_DECLARATIONS.is_file():
            self.skipTest("workspace_registry_projection_not_in_portable_delivery")
        declarations = MODULE.load_json(MODULE.DEFAULT_DECLARATIONS)
        expected_count = len(declarations["tools"])
        self.assertGreater(expected_count, 0)
        portable_registry = {"tools": {tool_id: {} for tool_id in declarations["tools"]}}
        self.assertEqual([], MODULE.validate_declarations(portable_registry, declarations))
        if MODULE.DEFAULT_REGISTRY.is_file():
            registry = MODULE.load_json(MODULE.DEFAULT_REGISTRY)
            self.assertEqual(len(registry["tools"]), expected_count)
            self.assertEqual([], MODULE.validate_declarations(registry, declarations))
            self.assertEqual([], MODULE.validate_registry_projection(registry, declarations))

    def test_refresh_declarations_reuses_registry_projection(self) -> None:
        registry = {
            "tools": {
                "metadata-only": {
                    "no_managed_artifacts": True,
                    "artifact_lifecycle_governance": {
                        "schema_version": "registry-artifact-lifecycle.v1",
                        "owner_lane": "fixture",
                        "cleanup_mode": "plan_only",
                        "automatic_purge": False,
                        "adapter_status": "not_applicable_no_managed_artifacts",
                        "protected_roles": ["contract", "receipt"],
                        "recovery_entry": "rerun fixture doctor",
                    },
                }
            }
        }
        declarations = {"schema_version": "registry-artifact-lifecycle-declarations.v1", "tools": {}}
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMP_ROOT")) as temporary:
            root = Path(temporary)
            registry_path = root / "registry.json"
            declarations_path = root / "declarations.json"
            output_path = root / "refreshed.json"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            declarations_path.write_text(json.dumps(declarations), encoding="utf-8")
            result = MODULE.refresh_declarations(registry_path, declarations_path, output_path)
            refreshed = MODULE.load_json(output_path)
        self.assertEqual("completed", result["status"])
        self.assertEqual(["metadata-only"], result["added"])
        self.assertEqual([], result["updated"])
        self.assertTrue(refreshed["tools"]["metadata-only"]["no_managed_artifacts"])
        self.assertEqual([], MODULE.validate_registry_projection(registry, refreshed))

    def test_refresh_marks_invalid_registry_projection_blocked(self) -> None:
        registry = {
            "tools": {
                "invalid-root": {
                    "lifecycle_profile": "document_render",
                    "artifact_lifecycle_governance": {
                        "schema_version": "registry-artifact-lifecycle.v1",
                        "owner_lane": "fixture",
                        "cleanup_mode": "plan_only",
                        "automatic_purge": False,
                        "adapter_status": "verified_owner_adapter_synthetic_fixture_only",
                        "artifact_roots": [{"path_ref": "$tool_root/fixture", "status": "wrong", "scan_eligible": True}],
                        "authoritative_paths": [],
                        "protected_roles": ["final_output"],
                        "doctor": "fixture",
                        "scan": "fixture",
                        "plan_gc": "fixture",
                        "restore": "fixture",
                        "recovery_entry": "repair fixture declaration",
                        "large_output_preflight": True,
                        "minimum_free_bytes": 536870912,
                        "warning_free_bytes": 5368709120,
                        "output_headroom_multiplier": 1.25,
                    },
                }
            }
        }
        declarations = {"schema_version": "registry-artifact-lifecycle-declarations.v1", "tools": {}}
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMP_ROOT")) as temporary:
            root = Path(temporary)
            registry_path = root / "registry.json"
            declarations_path = root / "declarations.json"
            output_path = root / "refreshed.json"
            registry_path.write_text(json.dumps(registry), encoding="utf-8")
            declarations_path.write_text(json.dumps(declarations), encoding="utf-8")
            result = MODULE.refresh_declarations(registry_path, declarations_path, output_path)
            refreshed = MODULE.load_json(output_path)
        blocked = refreshed["tools"]["invalid-root"]
        self.assertEqual("completed_with_blocked_declarations", result["status"])
        self.assertTrue(blocked["blocked_missing_declaration"])
        self.assertIn("scan_eligible_requires_verified_synthetic_fixture", blocked["source_projection_errors"][0])
        self.assertEqual([], MODULE.validate_declarations(registry, refreshed))
        self.assertEqual([], MODULE.validate_registry_projection(registry, refreshed))

    def test_declaration_schema_covers_current_projection_vocabulary(self) -> None:
        schema = MODULE.load_json(MODULE.CORE_ROOT / "schemas" / "registry-artifact-lifecycle-declaration.v1.schema.json")
        declaration_properties = schema["properties"]["tools"]["additionalProperties"]["properties"]
        adapter_statuses = set(declaration_properties["adapter_status"]["enum"])
        path_statuses = set(schema["$defs"]["pathDeclaration"]["properties"]["status"]["enum"])
        self.assertIn("blocked_missing_declaration", declaration_properties)
        self.assertIn("source_projection_errors", declaration_properties)
        if MODULE.DEFAULT_DECLARATIONS.is_file():
            declarations = MODULE.load_json(MODULE.DEFAULT_DECLARATIONS)
            current_adapter_statuses = {item["adapter_status"] for item in declarations["tools"].values()}
            current_path_statuses = {
                path["status"]
                for item in declarations["tools"].values()
                for field in ("artifact_roots", "authoritative_paths")
                for path in item.get(field, [])
            }
            self.assertEqual(set(), current_adapter_statuses - adapter_statuses)
            self.assertEqual(set(), current_path_statuses - path_statuses)

    def test_missing_declaration_fails_closed(self) -> None:
        registry = {"tools": {"alpha": {}, "beta": {}}}
        declarations = {
            "tools": {
                "alpha": {
                    "no_managed_artifacts": True,
                    "owner_lane": "fixture",
                    "cleanup_mode": "plan_only",
                    "automatic_purge": False,
                    "adapter_status": "not_applicable_protected_state_only",
                    "protected_roles": ["fixture"],
                    "recovery_entry": "fixture",
                }
            }
        }
        errors = MODULE.validate_declarations(registry, declarations)
        self.assertTrue(any("missing_tool_declarations:beta" in error for error in errors))

    def test_large_profile_requires_low_disk_gate(self) -> None:
        registry = {"tools": {"media-tool": {}}}
        declarations = {
            "tools": {
                "media-tool": {
                    "lifecycle_profile": "media",
                    "owner_lane": "fixture",
                    "cleanup_mode": "plan_only",
                    "automatic_purge": False,
                    "adapter_status": "pending_owner_adapter",
                    "artifact_roots": [],
                    "authoritative_paths": [],
                    "protected_roles": ["original_media"],
                    "doctor": "pending_owner_adapter",
                    "scan": "pending_owner_adapter",
                    "plan_gc": "pending_owner_adapter",
                    "restore": "pending_owner_adapter",
                    "recovery_entry": "fixture",
                }
            }
        }
        errors = MODULE.validate_declarations(registry, declarations)
        self.assertIn("media-tool:large_output_preflight_required", errors)
        self.assertIn("media-tool:minimum_free_bytes_below_512_mib", errors)
        self.assertIn("media-tool:warning_free_bytes_below_minimum", errors)
        self.assertIn("media-tool:output_headroom_multiplier_below_1", errors)

    def test_canonical_hash_ignores_timestamps(self) -> None:
        first = {"checked_at": "one", "payload": {"generated_at": "one", "value": 1}}
        second = {"checked_at": "two", "payload": {"generated_at": "two", "value": 1}}
        self.assertEqual(MODULE.content_hash(first), MODULE.content_hash(second))

    def test_access_denied_is_isolated(self) -> None:
        with mock.patch.object(MODULE.subprocess, "run", side_effect=PermissionError("denied")):
            result = MODULE.invoke_root_worker("fixture", ROOT, ROOT / ".runtime", timeout_seconds=1, max_nodes=1, max_depth=1)
        self.assertEqual("blocked_access_denied", result["status"])

    def test_timeout_is_isolated(self) -> None:
        with mock.patch.object(MODULE.subprocess, "run", side_effect=subprocess.TimeoutExpired(["fixture"], 1)):
            result = MODULE.invoke_root_worker("fixture", ROOT, ROOT / ".runtime", timeout_seconds=1, max_nodes=1, max_depth=1)
        self.assertEqual("blocked_timeout", result["status"])

    def test_bounded_preflight_rejects_item_overflow(self) -> None:
        managed = os.environ.get("TEST_TMP_ROOT")
        if not managed:
            self.skipTest("TEST_TMP_ROOT_required_for_windows_acl_safe_temp")
        with tempfile.TemporaryDirectory(dir=managed) as raw:
            root = Path(raw)
            (root / "one.txt").write_text("one", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "root_item_limit_exceeded"):
                MODULE.bounded_preflight(root, max_nodes=1, max_depth=4)

    def test_projection_round_trip(self) -> None:
        declaration = {
            "no_managed_artifacts": True,
            "owner_lane": "fixture",
            "cleanup_mode": "plan_only",
            "automatic_purge": False,
            "adapter_status": "not_applicable_protected_state_only",
            "protected_roles": ["fixture"],
            "recovery_entry": "fixture",
        }
        direct, governance = MODULE.registry_projection(declaration)
        self.assertEqual({"no_managed_artifacts": True}, direct)
        self.assertEqual("registry-artifact-lifecycle.v1", governance["schema_version"])

    def test_source_inventory_linkage_is_bounded_and_exact(self) -> None:
        registry = {"tools": {"artifact-lifecycle-core": {}}}
        entry = {field: None for field in MODULE.SOURCE_INVENTORY_REQUIRED_FIELDS}
        entry.update(
            {
                "name": "Artifact Lifecycle Core",
                "local_path": str(MODULE.CORE_ROOT),
                "integration_status": "integrated_local_tool",
                "registry_tool_id": "artifact-lifecycle-core",
                "deployment_path": str(MODULE.CORE_ROOT),
                "evidence_docs": [str(MODULE.CORE_ROOT / "AGENT_DISCOVERY.md")],
                "evidence_link_status": "linked",
            }
        )
        errors, summary = MODULE.validate_source_inventory_linkage(
            registry, {"schema_version": 1, "entries": [entry]}
        )
        self.assertEqual([], errors)
        self.assertTrue(summary["artifact_lifecycle_core_linked"])
        self.assertFalse(summary["all_entry_filesystem_probe"])

    def test_source_inventory_unknown_registry_link_fails_closed(self) -> None:
        entry = {field: None for field in MODULE.SOURCE_INVENTORY_REQUIRED_FIELDS}
        entry["registry_tool_id"] = "missing-tool"
        errors, _ = MODULE.validate_source_inventory_linkage(
            {"tools": {}}, {"schema_version": 1, "entries": [entry]}
        )
        self.assertTrue(any("unknown_registry_tool_id:missing-tool" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
