from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import stat
import shutil
import subprocess
import sys
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent
EXCLUDED_DELIVERY_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    ".test-runtime",
    ".test-runtime-final",
    ".test-runtime-pass2",
    ".release-runtime",
    ".t",
    ".venv",
    "build",
    "dist",
    "__pycache__",
}
EXCLUDED_PORTABLE_FILES = {
    "CHANGE-RATIONALE.md",
    "registry-lifecycle-declarations.v1.json",
}
RELEASE_RECEIPT_PREFIX = "ARTIFACT-CORE-CLEANCLONE-RELEASE-READINESS-20260829-01."


def atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    data = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    try:
        temporary.write_text(data, encoding="utf-8", newline="\n")
        if temporary.read_text(encoding="utf-8") != data:
            raise OSError("atomic_write_readback_mismatch")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def find_windows_test_runtime(explicit: str | None) -> Path:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    configured = os.environ.get("CODEX_WINDOWS_TEST_RUNTIME")
    if configured:
        candidates.append(Path(configured))
    candidates.append(ROOT / "tools" / "windows_test_runtime.py")
    for ancestor in (ROOT, *ROOT.parents):
        candidates.append(ancestor / "scripts" / "windows_test_runtime.py")
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise FileNotFoundError("windows_test_runtime_not_found")


def managed_root_for(runtime: Path, explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).resolve(strict=False)
    configured = os.environ.get("ARTIFACT_LIFECYCLE_TEST_ROOT")
    if configured:
        return Path(configured).resolve(strict=False)
    if runtime.parent == ROOT / "tools":
        return ROOT / ".test-runtime"
    workspace = runtime.parent.parent
    return workspace / ".runtime" / "managed-test-runs" / "artifact-lifecycle-core"


def delivery_file_list() -> tuple[list[str], list[str], list[str], list[str]]:
    files: list[str] = []
    excluded_directories: list[str] = []
    excluded_files: list[str] = []
    errors: list[str] = []

    def onerror(error: OSError) -> None:
        errors.append(f"{type(error).__name__}:{error}")

    for current, directories, names in os.walk(ROOT, topdown=True, onerror=onerror):
        current_path = Path(current)
        retained: list[str] = []
        for name in sorted(directories):
            candidate = current_path / name
            if (name in EXCLUDED_DELIVERY_DIRECTORIES
                    or name.startswith(".test-runtime")
                    or name.endswith(".egg-info")):
                excluded_directories.append(str(candidate.relative_to(ROOT)))
            else:
                try:
                    info = candidate.lstat()
                    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                        errors.append(f"delivery_reparse_forbidden:{candidate.relative_to(ROOT)}")
                    else:
                        retained.append(name)
                except OSError as error:
                    onerror(error)
        directories[:] = retained
        for name in sorted(names):
            relative = (current_path / name).relative_to(ROOT)
            if str(relative).replace("\\", "/") in EXCLUDED_PORTABLE_FILES:
                excluded_files.append(str(relative))
                continue
            if relative.parent == Path("docs") and relative.name.startswith(RELEASE_RECEIPT_PREFIX):
                excluded_files.append(str(relative))
                continue
            try:
                info = (ROOT / relative).lstat()
                if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                    errors.append(f"delivery_reparse_forbidden:{relative}")
                    continue
            except OSError as error:
                onerror(error)
                continue
            files.append(str(relative))
    return files, excluded_directories, excluded_files, errors


def enumerate_delivery_files() -> int:
    files, excluded_directories, excluded_files, errors = delivery_file_list()
    payload = {
        "schema_version": "artifact-lifecycle-delivery-enumeration.v1",
        "status": "ok" if not errors else "blocked",
        "root": str(ROOT),
        "files": files,
        "file_count": len(files),
        "excluded_directories": excluded_directories,
        "excluded_files": excluded_files,
        "errors": errors,
    }
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 2


def load_runtime(path: Path):
    spec = importlib.util.spec_from_file_location("artifact_lifecycle_windows_test_runtime", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("windows_test_runtime_import_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def run_clean_copy(args: argparse.Namespace) -> int:
    runtime_path = find_windows_test_runtime(args.runtime)
    runtime = load_runtime(runtime_path)
    files, excluded_directories, excluded_files, errors = delivery_file_list()
    if errors:
        print(json.dumps({"status": "blocked", "errors": errors}, ensure_ascii=False))
        return 2
    runtime_workspace = ROOT if runtime_path.parent == ROOT / "tools" else runtime_path.parent.parent
    clean_root = (
        Path(args.test_root).resolve(strict=False)
        if args.test_root
        else runtime_workspace / ".runtime" / "alc-cc"
    )
    with runtime.managed_test_directory(
        purpose="artifact-lifecycle-core-clean-copy",
        profile="clean_copy",
        root=clean_root,
    ) as run_path:
        destination = run_path / "src"
        for relative in files:
            source = ROOT / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        doctor = subprocess.run(
            [sys.executable, "-B", "artifact_lifecycle_core.py", "doctor"],
            cwd=destination,
            shell=False,
            check=False,
        )
        if doctor.returncode != 0:
            raise RuntimeError(f"clean_copy_doctor_failed:{doctor.returncode}")
        tests = subprocess.run(
            [
                sys.executable,
                "-B",
                "run_tests.py",
                "--runtime",
                str(destination / "tools" / "windows_test_runtime.py"),
                "--test-root",
                str(destination / ".t"),
                "--timeout-seconds",
                str(args.timeout_seconds),
            ],
            cwd=destination,
            shell=False,
            check=False,
        )
        if tests.returncode != 0:
            raise RuntimeError(f"clean_copy_tests_failed:{tests.returncode}")
        receipt = {
            "schema_version": "artifact-lifecycle-clean-copy-receipt.v1",
            "status": "passed",
            "file_count": len(files),
            "excluded_directories": excluded_directories,
            "excluded_files": excluded_files,
            "copy_mode": "explicit_file_list",
            "recursive_copy_used": False,
            "doctor_returncode": doctor.returncode,
            "tests_returncode": tests.returncode,
            "bundled_test_runtime_sha256": hashlib.sha256(
                (destination / "tools" / "windows_test_runtime.py").read_bytes()
            ).hexdigest(),
            "workspace_parent_dependency_used": False,
        }
        (run_path / "clean-copy-receipt.json").write_text(
            json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.receipt:
        atomic_write_json(Path(args.receipt).resolve(strict=False), receipt)
    print(json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


def run_tests(args: argparse.Namespace) -> int:
    try:
        runtime = find_windows_test_runtime(args.runtime)
    except FileNotFoundError as error:
        print(json.dumps({"status": "blocked", "reason_code": str(error)}))
        return 2
    command = [
        sys.executable,
        str(runtime),
        "adapter",
        "--root",
        str(managed_root_for(runtime, args.test_root)),
        "--cwd",
        str(ROOT),
        "--purpose",
        "artifact-lifecycle-core-focused-tests",
        "--adapter",
        "unittest",
        "--timeout-seconds",
        str(args.timeout_seconds),
        "--",
        "discover",
        "-s",
        "tests",
        "-v",
    ]
    completed = subprocess.run(command, cwd=ROOT, shell=False, check=False)
    return completed.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime")
    parser.add_argument("--test-root")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--enumerate", action="store_true")
    parser.add_argument("--clean-copy", action="store_true")
    parser.add_argument("--receipt")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.enumerate:
        return enumerate_delivery_files()
    if args.clean_copy:
        return run_clean_copy(args)
    return run_tests(args)


if __name__ == "__main__":
    raise SystemExit(main())
