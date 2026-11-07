# Artifact Lifecycle Core

This repository-local module is the generic first-party artifact lifecycle core for Local Tools. It combines the existing bounded audit/checkpoint design with the existing self-media immutable-plan and recoverable-quarantine design. It does not replace project state machines or run a service.

## Quick start

```powershell
python artifact_lifecycle_core.py doctor
python artifact_lifecycle_core.py doctor --target-root <root> --profile media --estimated-output-bytes <bytes>
python global_registry_audit.py validate
python global_registry_audit.py refresh-declarations --output registry-lifecycle-declarations.v1.json
python global_registry_audit.py audit --output <audit-output-root>
python run_tests.py
python run_tests.py --enumerate
python run_tests.py --clean-copy
```

The test entry prefers the reviewed repository-local
`tools/windows_test_runtime.py` and can also accept an explicit `--runtime`.
Tests refuse to run outside a uniquely leased managed run, and temp, basetemp,
cache, and cleanup receipts are owned by that runtime rather than this repository.
The `test_cache` profile consumes that runtime's bounded manifest: successful
runs are removed after verified child exit, failed runs remain readable for seven
days, and only the latest failed run may be pinned. The generic core may explain
or plan from the manifest but does not recursively remove test directories.

`scan` is bounded and writes only its declared manifest and SQLite checkpoint. `plan` and `verify-plan` are read-only with respect to artifacts. `apply-quarantine` and `restore` require exact contracts; use them only within separately approved scope. `apply-purge` is permanently disabled in v1.

Disk preflight uses an absolute reserve plus estimated-output headroom instead
of reserving a percentage of the whole volume. The default hard reserve is 512
MiB, output estimates receive 1.25x headroom, and less than 5 GiB free is a
warning rather than a block. With no output estimate, 2-3 GiB free remains
usable. A task is blocked only when its free space cannot cover the hard reserve
and the declared output estimate.

The global Registry audit is also read-only. It consumes
`registry-lifecycle-declarations.v1.json`, reuses the earlier bounded
SQLite/hardlink scanner, and scans only explicit verified synthetic roots. Each
root has an independent timeout/checkpoint. Pending owner adapters and protected
service/business state produce blocked or not-applicable receipts instead of
being guessed into cleanup scope.

`refresh-declarations` deterministically rebuilds the local declaration
projection from the current Registry. A malformed Registry lifecycle contract is
preserved as `blocked_missing_declaration`; it cannot be projected back into the
Registry or scanned until its owner contract is repaired.

The Registry audit is a workspace integration entry. It is not required for an
installed core doctor or the portable synthetic demo. Its current generated
projection, `registry-lifecycle-declarations.v1.json`, and the machine-specific
historical `CHANGE-RATIONALE.md` are deliberately excluded from the portable
source payload. They remain local governance evidence, not runtime inputs.

## Offline build and installed CLI

With a locally available `setuptools` build backend:

```powershell
python -m pip wheel . --no-deps --no-build-isolation --wheel-dir dist
python -m venv <venv>
<venv>\Scripts\python.exe -m pip install --no-index --no-deps <wheel>
<venv>\Scripts\local-artifacts.exe doctor
<venv>\Scripts\local-artifacts-demo.exe --workspace <dedicated-root> --run-id demo-01
```

The wheel includes the schemas, profile contract, manifest, discovery document,
and license notices. The demo only mutates its own synthetic run directory and
returns a hash-bound receipt. Repeating the same run id verifies that receipt
without replaying mutations. See [README.zh-CN.md](README.zh-CN.md) and
[docs/CLEAN-COPY.md](docs/CLEAN-COPY.md).

This public source edition is licensed under Apache-2.0. The original
private source history retains its existing license. Machine inventories and
historical task receipts are excluded. Local synthetic validation is recorded
in the release report and does not authorize real artifact mutation.

See [AGENT_DISCOVERY.md](AGENT_DISCOVERY.md) for the machine-use contract and
[RELEASE-NOTES.md](RELEASE-NOTES.md) for portable decisions and rollback.
