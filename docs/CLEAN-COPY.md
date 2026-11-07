# Clean-copy and clean-install verification

Verify relocation with the explicit delivery file list and the bundled reviewed
Windows test runtime:

```powershell
python run_tests.py --enumerate
python run_tests.py --clean-copy --test-root <isolated-test-root>
```

`--clean-copy` copies an explicit bounded file list into a leased test directory,
then runs doctor and the complete source test suite using the copy's own
`tools/windows_test_runtime.py`. It excludes `.git`, build outputs, virtual
environments, egg metadata, caches, all `.test-runtime*` directories, the
workspace Registry projection, and machine-specific historical governance logs.
The excluded Registry projection is exercised only in its authoritative Local
Tools workspace; portable core behavior does not depend on it.

For a clean install, build without isolation or dependencies, install the wheel
with `--no-index --no-deps` into a fresh virtual environment, then run:

```powershell
local-artifacts doctor
local-artifacts-demo --workspace <dedicated-root> --run-id demo-01
```

The installed doctor resolves packaged contract assets under the environment's
data directory. It must report `asset_root_mode=installed_data_files`. The demo
must restore every synthetic source path and digest, reject purge, and return a
hash-bound receipt. No command may require a workspace sibling, network access,
service, credential, personal content, or implicit environment variable.

Windows ACL failures, read-only targets, reparse points, cross-volume targets,
and low disk are structured blockers with a recovery entry. The clean-copy
harness uses bounded short internal directory names so its own lease nesting
does not consume the Windows path budget. User-supplied long paths still depend
on the host's Windows long-path policy and fail as a host capability blocker.

## Revalidation Notes

Updated: 2026-09-05 13:34:00 | Codex (GPT-6 Astra)

Prefer a short explicit managed test root on Windows. A nested clean-copy run
can exceed Git's path budget even when Python supports the same path. Preserve
the failed run's receipt, then rerun with a shorter root; do not change global
Git configuration or take ownership of historical ACL directories.

The bundled runtime is selected before any workspace sibling. An explicit
`--runtime` or `CODEX_WINDOWS_TEST_RUNTIME` remains a deliberate override.
Source delivery rejects links/reparse points rather than following them.

The installed doctor needs only Python. Synthetic plan/quarantine/restore also
needs Git for the existing dirty-tree gate; without it the demo returns
`GIT_UNAVAILABLE` before creating the run. Read-only/ACL errors return
`PATH_ACCESS_DENIED`, long paths return `PATH_TOO_LONG`, and corrupted prior
receipts return `DEMO_RECEIPT_INVALID`. None of these grants repair or deletion
authority. Optional dependencies are not installed automatically.
