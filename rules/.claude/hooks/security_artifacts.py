#!/usr/bin/env python3
"""Strict parsing helpers for local security phase artifacts."""

import fnmatch
from pathlib import Path


ARTIFACT_TYPES = {
    "specification": (
        Path("docs/specifications"),
        ("## Acceptance criteria",),
    ),
    "threat-model": (
        Path("docs/threat-models"),
        (
            "## Scope and protection requirement",
            "## User story and abuse stories",
            "## Threats and mitigations",
            "## Accepted risks",
        ),
    ),
    "plan": (
        Path("docs/plans"),
        ("## Implementation steps",),
    ),
}


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
    directory, required_sections = ARTIFACT_TYPES[artifact_type]
    patterns: list[str] = []
    for artifact in sorted((root / directory).glob("*.md")):
        try:
            lines = artifact.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        first_heading = next(
            (index for index, line in enumerate(lines) if line.startswith("#")),
            len(lines),
        )
        metadata = lines[:first_heading]
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
