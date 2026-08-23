#!/usr/bin/env python3
"""Verify protected security assets against a versioned SHA-256 manifest."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile


MANIFEST_NAME = ".security-rule-manifest.json"
MANIFEST_VERSION = 1
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}")
TOP_LEVEL_FILES = ("AGENTS.md", "CLAUDE.md", "README.md")


def project_root() -> Path:
    configured = os.environ.get("CLAUDE_PROJECT_DIR")
    if configured:
        return Path(configured).resolve(strict=True)
    return Path(__file__).resolve(strict=True).parents[2]


def protected_paths(root: Path) -> list[Path]:
    candidates = [root / name for name in TOP_LEVEL_FILES if (root / name).is_file()]
    candidates.extend((root / ".ai-security-rules").rglob("*.md"))
    candidates.extend((root / ".claude" / "hooks").glob("*.py"))
    settings = root / ".claude" / "settings.json"
    if settings.is_file():
        candidates.append(settings)
    resolved_paths: list[Path] = []
    for candidate in candidates:
        if candidate.is_symlink():
            raise ValueError("protected-symlink")
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        resolved_paths.append(resolved)
    return sorted(set(resolved_paths))


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65_536), b""):
            hasher.update(block)
    return hasher.hexdigest()


def current_entries(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): digest(path)
        for path in protected_paths(root)
    }


def read_manifest(root: Path) -> dict[str, str]:
    path = root / MANIFEST_NAME
    try:
        raw = path.read_text(encoding="utf-8")
        manifest = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid-manifest") from exc
    if manifest.get("version") != MANIFEST_VERSION or manifest.get("algorithm") != "sha256":
        raise ValueError("invalid-manifest-metadata")
    entries = manifest.get("files")
    if not isinstance(entries, dict):
        raise ValueError("invalid-manifest-files")
    for relative, expected in entries.items():
        if (
            not isinstance(relative, str)
            or not relative
            or relative.startswith(("/", "../"))
            or not isinstance(expected, str)
            or DIGEST_PATTERN.fullmatch(expected) is None
        ):
            raise ValueError("invalid-manifest-entry")
    return entries


def report_drift(root: Path) -> int:
    try:
        expected = read_manifest(root)
        actual = current_entries(root)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 2
    missing = sorted(set(expected) - set(actual))
    unexpected = sorted(set(actual) - set(expected))
    modified = sorted(
        path for path in set(expected) & set(actual) if expected[path] != actual[path]
    )
    drift_report = {
        "status": "drift" if missing or unexpected or modified else "ok",
        "missing": missing,
        "modified": modified,
        "unexpected": unexpected,
    }
    print(json.dumps(drift_report, sort_keys=True))
    return 2 if drift_report["status"] == "drift" else 0


def write_manifest(root: Path) -> int:
    try:
        manifest = {
            "version": MANIFEST_VERSION,
            "algorithm": "sha256",
            "files": current_entries(root),
        }
        serialized = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=root, delete=False
        ) as stream:
            stream.write(serialized)
            temporary = Path(stream.name)
        os.replace(temporary, root / MANIFEST_NAME)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "error", "reason": str(exc)}))
        return 2
    print(json.dumps({"status": "manifest-updated", "files": len(manifest["files"])}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--write",
        action="store_true",
        help="replace the manifest with hashes of the current protected files",
    )
    arguments = parser.parse_args()
    root = project_root()
    return write_manifest(root) if arguments.write else report_drift(root)


if __name__ == "__main__":
    raise SystemExit(main())
