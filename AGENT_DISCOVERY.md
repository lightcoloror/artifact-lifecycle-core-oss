# Artifact Lifecycle Core Agent Discovery

## Purpose

`artifact-lifecycle-core` is the first-party generic contract and CLI for local artifact manifests, bounded scans, immutable quarantine/purge plans, plan drift verification, recoverable quarantine, and restore. It is independent from `work-lifecycle-core`; project-specific lifecycle states remain owned by their project adapters.

## Stable entry

Installed, cross-platform entry:

```text
local-artifacts doctor
local-artifacts scan --help
local-artifacts explain --help
local-artifacts plan --help
local-artifacts verify-plan --help
local-artifacts apply-quarantine --help
local-artifacts restore --help
local-artifacts apply-purge --help
local-artifacts-demo --workspace <dedicated-root> --run-id demo-01
```

Source-tree equivalent:

```powershell
python artifact_lifecycle_core.py doctor
python artifact_lifecycle_core.py scan --help
python artifact_lifecycle_core.py explain --help
python artifact_lifecycle_core.py plan --help
python artifact_lifecycle_core.py verify-plan --help
python artifact_lifecycle_core.py apply-quarantine --help
python artifact_lifecycle_core.py restore --help
python artifact_lifecycle_core.py apply-purge --help
python artifact_lifecycle_demo.py --workspace <dedicated-root> --run-id demo-01
```

Workspace integration only; these commands require the shared Registry and
Source Inventory and are not portable core health checks:

```powershell
python global_registry_audit.py validate
python global_registry_audit.py refresh-declarations --output registry-lifecycle-declarations.v1.json
python global_registry_audit.py audit --output <audit-output-root> --dispatch-id <dispatch-id>
```

## Global Registry lifecycle truth

`registry-lifecycle-declarations.v1.json` is the reviewed projection source for
the Registry lifecycle fields. Every Registry tool declares exactly one of
`lifecycle_profile`, `no_managed_artifacts`, or
`blocked_missing_declaration`. Managed tools also declare bounded roots,
authoritative paths, plan-only commands, protected roles, and a recovery entry.
A tool without a verified owner adapter remains `pending_owner_adapter`;
metadata never makes it executable.

`global_registry_audit.py` reuses the existing 2026-08-23 SQLite checkpoint and
NTFS hardlink accounting implementation. It launches each explicitly verified
synthetic root in an isolated child process with a per-root timeout, node/depth
limits, and an independent checkpoint. Access Denied, timeout, missing roots,
and malformed worker output are recorded per root and do not stop other tools.
The generated report never authorizes quarantine, restore, purge, service
startup, customer/knowledge access, or external writes.

Authority links:

- Registry: `../tool-registry.json#artifact-lifecycle-core`
- Source Inventory: `../source-reviews/SOURCE_INVENTORY.json#artifact-lifecycle-core`
- Declaration schema: `schemas/registry-artifact-lifecycle-declaration.v1.schema.json`
- Declaration projection: `registry-lifecycle-declarations.v1.json`

Each current tool has exactly one declaration state: `lifecycle_profile`,
`no_managed_artifacts`, or `blocked_missing_declaration`. The blocked state
retains owner and protected-role evidence but grants no scan, projection, apply,
quarantine, or purge capability.

Those authority links describe the current Local Tools workspace. A clean clone
or installed wheel does not infer Registry truth from absent sibling files.

## Profiles

The seven contract profiles are `media`, `document_render`, `research_evidence`, `source_review`, `build_dist`, `test_cache`, and `sync_logs`. Profiles are declarations over the shared core, not duplicated cleanup engines.

### Project thin adapters

`project_artifact_adapter.py` is the configuration-driven adapter for a
repository-owned synthetic fixture root. It delegates lifecycle work to this
core and provides `doctor`, `scan`, `explain`, `plan`, `verify-plan`,
`synthetic-quarantine`, and `synthetic-restore`. It rejects roots not named in
the repository configuration. Production roots and real mutation require a
separate reviewed scope.

### test_cache owner adapter

`test_cache` delegates ownership, lease validation, bounded enumeration, retention,
and cleanup to the existing workspace runtime. The generic core consumes only its
manifest or creates a plan; it never recursively deletes a test directory.

```powershell
python ..\scripts\windows_test_runtime.py test-cache scan --root <managed-root> --max-items 100 --max-nodes-per-item 10000
python ..\scripts\windows_test_runtime.py test-cache explain --root <managed-root> --run-id <run-id>
python ..\scripts\windows_test_runtime.py test-cache plan --root <managed-root> --quarantine-root <same-volume-quarantine>
python ..\scripts\windows_test_runtime.py test-cache pin-latest-failure --root <managed-root>
```

Every root must carry the managed-root marker. Every run must carry a matching
lease and owner token. Successful runs are removed only after child-exit
verification; failures are retained for seven days and the latest failure may be
pinned. Missing ownership evidence, active/unknown children, ACL errors, item
limits, and node limits fail closed. Historical ACL-denied directories are not
adopted or cleaned by this adapter.

## Safety contract

- Default and only v1 cleanup mode is `plan_only`; plans never grant execution authority.
- Large-output preflight reserves 512 MiB plus `estimated_output_bytes * 1.25`.
- Below 5 GiB free is `low_disk_allowed`: warn and continue when the declared output still fits.
- `blocked_low_disk` is returned only when the hard reserve plus estimated-output headroom does not fit. Percentage-only blocking is deprecated.
- Quarantine requires an exact plan, current hashes, same-volume source and quarantine roots, and an unexpired human approval binding.
- `apply-purge` always returns `PURGE_DISABLED_BY_POLICY` in v1.
- Path escape, symlink/junction/reparse points, cross-volume targets, dirty Git, active/unknown owner/process/dispatch state, authoritative references, stale plans, incomplete rebuild proof, incomplete hardlink coverage, and access errors fail closed.
- Doctor and synthetic tests do not authorize real customer or business artifact mutation.
- `test_cache` plans are metadata-only. Apply and historical-directory cleanup remain outside this phase.

## Compatibility

`self-media-artifact-lifecycle-manifest.v2` is accepted through an in-memory media compatibility view. Existing manifests are not rewritten or migrated.

## Readiness truth

- `contract_ready`: schema, profiles, discovery, and CLI exist.
- `runtime_ready`: the current local doctor passes.
- `fresh_e2e_pass`: false in doctor output; the synthetic demo produces a
  separate, run-scoped receipt and does not change doctor truth.
- `real_usage_proof`: false for phase 1.
- `current_online`: false; no service exists.

## Recovery

Verify the immutable plan before execution. A failed quarantine rolls back already moved entries. Restore verifies the quarantine receipt and every digest before moving an item back. Never use non-atomic copy/delete as a fallback.

## Tests and delivery enumeration

```powershell
python run_tests.py
python run_tests.py --enumerate
```

`run_tests.py` uses the reviewed repository-local Windows test runtime by default
and accepts an explicit runtime path. Direct
`python -m unittest` execution is intentionally rejected because it lacks the
managed `TEST_TMP_ROOT`, basetemp, cache, cleanup receipt, and retention contract.
The enumeration command skips only exact generated or legacy runtime directory
names; any other access error remains fail-closed.

## Distribution boundary

The public source edition and wheel carry Apache-2.0. Build and install
evidence applies to the tested environment. The manifest is metadata only
and grants no execution authority.
