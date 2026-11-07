# Third-Party Notices

The runtime modules use only the Python standard library and have no mandatory
third-party runtime dependencies.

The build backend is `setuptools` (MIT) and is required only to build a wheel.
It is not bundled in this repository.

`tools/windows_test_runtime.py` is reused first-party workspace code, not a
third-party dependency. The repository copy carries only a location adapter so
it can resolve the adjacent core and failure catalog. Source at review time:

- workspace path: `scripts/windows_test_runtime.py`
- SHA-256: `470c815137d1a58ce5e71967be347fc30ca9f0f351e347e28cad2e6efbb84f36`
- repository-adapted SHA-256: `cc206f245e212d0c0962b41bbcfba4a804b9b1774079fe5ad5b2003997fc6428`
- copied failure catalog SHA-256: `672f21ea2aa7c12a6183da045f66147b2e666b8d4a1abe9637d533fe79e69071`

The project behavior was informed by earlier first-party audit and self-media
lifecycle implementations. Those implementations are referenced as provenance
and are not copied into the installed package.
