# Release-readiness notes

## Portable payload

The portable source payload and wheel contain the fail-closed core, schemas,
profiles, machine discovery metadata, a bundled Windows test runtime, and a
synthetic-only round-trip demo. The installed doctor resolves packaged assets
without a workspace sibling or implicit environment variable.

The portable payload intentionally excludes two Local Tools workspace records:

- `registry-lifecycle-declarations.v1.json` is a generated projection of the
  current shared Registry and must be rebuilt from the receiving workspace.
- `CHANGE-RATIONALE.md` is an append-only local governance history that can
  contain machine-specific evidence paths. This file is not a runtime input.

## Safety decisions

- `apply-purge` remains permanently disabled by policy.
- Quarantine and restore require an exact verified plan and explicit execution.
- The bundled demo mutates only its dedicated synthetic workspace and restores
  every source path and digest before completion.
- A successful doctor or demo does not prove current online status, real usage,
  public release, or authorization to operate on real artifacts.

## Rollback

Remove the packaging metadata, installed console scripts, bundled test runtime,
release-readiness verifier, and synthetic demo entry. The underlying core CLI,
schemas, and workspace Registry projection remain independent of those files.

## Public source edition

The owner-authorized public edition uses Apache-2.0 for first-party code.
The original private baseline retains its license and history. Machine inventories
and historical audit receipts are excluded. The release report records the
current validation independently of historical clean-copy evidence.
