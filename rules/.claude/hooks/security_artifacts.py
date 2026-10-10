#!/usr/bin/env python3
"""Strict parsing helpers for local security phase artifacts.

An artifact's phase (specification / threat-model / plan) is identified by its
`Type:` metadata marker, so the artifact location is not fixed. The scan is
bounded to configurable search roots (default `docs`, override with the
`SECURITY_PHASE_SEARCH_ROOTS` environment variable, separated by the OS path
separator). For backward compatibility, an artifact that carries no `Type:`
marker is still classified by the legacy subdirectory name it lives under.
"""

import fnmatch
import os
from pathlib import Path


# Required `## ` headings per phase. The keys are the canonical artifact types
# the gate iterates over.
REQUIRED_SECTIONS = {
    "specification": ("## Acceptance criteria",),
    "threat-model": (
        "## Scope and protection requirement",
        "## User story and abuse stories",
        "## Threats and mitigations",
        "## Accepted risks",
    ),
    "plan": ("## Implementation steps",),
}

# Names the gate imports and iterates. Kept as a tuple of canonical types.
ARTIFACT_TYPES = tuple(REQUIRED_SECTIONS)

# Explicit `Type:` marker value (case-folded) -> canonical artifact type.
TYPE_MARKERS = {
    "specification": "specification",
    "threat-model": "threat-model",
    "plan": "plan",
}

# Legacy convention: subdirectory name -> canonical type. Kept so artifacts that
# predate the `Type:` marker, and projects that follow the original layout, keep
# satisfying the gate without a marker. An explicit marker always wins.
LEGACY_DIRECTORIES = {
    "specifications": "specification",
    "threat-models": "threat-model",
    "plans": "plan",
}

DEFAULT_SEARCH_ROOTS = ("docs",)


def search_roots(root: Path) -> list[Path]:
    """Return the configured artifact search roots, bounded to the project.

    Roots that are absolute, contain a NUL byte or resolve outside the project
    root are dropped. Non-existent roots are kept so the first document can be
    created before the directory exists; a non-existent root simply yields no
    artifacts during discovery.
    """
    configured = os.environ.get("SECURITY_PHASE_SEARCH_ROOTS")
    names = (
        [part.strip() for part in configured.split(os.pathsep)]
        if configured
        else list(DEFAULT_SEARCH_ROOTS)
    )
    roots: list[Path] = []
    for name in names:
        if not name or name.startswith("/") or "\\" in name or "\x00" in name:
            continue
        candidate = (root / name).resolve(strict=False)
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        if candidate not in roots:
            roots.append(candidate)
    return roots


def classify(metadata: list[str], artifact: Path, search_root: Path) -> str | None:
    """Return the canonical type of an artifact, or None if it is not one.

    An explicit `Type:` marker is authoritative: an unknown marker value yields
    None rather than falling back to the legacy directory name.
    """
    for line in metadata:
        stripped = line.strip()
        if stripped.startswith("Type:"):
            value = stripped[len("Type:"):].strip().casefold()
            return TYPE_MARKERS.get(value)
    try:
        relative_parts = artifact.relative_to(search_root).parts
    except ValueError:
        return None
    for part in relative_parts[:-1]:
        if part in LEGACY_DIRECTORIES:
            return LEGACY_DIRECTORIES[part]
    return None


def sections_have_content(lines: list[str], required_sections: tuple[str, ...]) -> bool:
    """Require non-empty content below every exact required heading."""
    for section in required_sections:
        start = lines.index(section) + 1
        body: list[str] = []
        for line in lines[start:]:
            if line.startswith("#"):
                break
            body.append(line)
        if not any(line.strip() for line in body):
            return False
    return True


def approved_patterns(root: Path, artifact_type: str) -> list[str]:
    """Return target globs from structurally complete approved artifacts."""
    required_sections = REQUIRED_SECTIONS[artifact_type]
    patterns: list[str] = []
    for search_root in search_roots(root):
        for artifact in sorted(search_root.rglob("*.md")):
            try:
                lines = artifact.read_text(encoding="utf-8").splitlines()
            except OSError:
                continue
            first_heading = next(
                (index for index, line in enumerate(lines) if line.startswith("#")),
                len(lines),
            )
            metadata = lines[:first_heading]
            if classify(metadata, artifact, search_root) != artifact_type:
                continue
            if not any(line.strip() == "Status: approved" for line in metadata):
                continue
            if not any(
                line.startswith("Approved-by: ") and line[13:].strip()
                for line in metadata
            ):
                continue
            if not any(
                line.startswith("Approved-at: ") and line[13:].strip()
                for line in metadata
            ):
                continue
            if not all(section in lines for section in required_sections):
                continue
            if not sections_have_content(lines, required_sections):
                continue
            in_paths = False
            artifact_patterns: list[str] = []
            for line in metadata:
                if line.strip() == "Applies-to:":
                    in_paths = True
                    continue
                if in_paths and line.startswith("- `") and line.endswith("`"):
                    pattern = line[3:-1]
                    segments = pattern.split("/")
                    if (
                        pattern
                        and len(pattern) <= 4096
                        and not pattern.startswith("/")
                        and "\\" not in pattern
                        and "\x00" not in pattern
                        and ".." not in segments
                    ):
                        artifact_patterns.append(pattern)
                    continue
                if in_paths and line.strip():
                    break
            patterns.extend(artifact_patterns)
    return patterns


def has_approval(root: Path, artifact_type: str, target: str) -> bool:
    """Return whether an approved artifact of the type covers the target."""
    return any(
        fnmatch.fnmatchcase(target, pattern)
        for pattern in approved_patterns(root, artifact_type)
    )
