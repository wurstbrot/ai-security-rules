#!/usr/bin/env python3
"""Defense-in-depth phase-artifact check for Claude write tools.

This local hook is not an authorization boundary: a developer can use tools it
does not observe. Protected CI and human review remain authoritative.

Exit 0 allows the write. Exit 2 blocks ambiguous or unauthorized writes.
"""
import json
import os
import sys
from pathlib import Path

from security_artifacts import ARTIFACT_TYPES, has_approval, search_roots


def deny(reason: str) -> "NoReturn":
    """Deny without echoing untrusted event data."""
    print(f"Phase artifact gate: denied ({reason}).", file=sys.stderr)
    raise SystemExit(2)


def relative_target(raw_path: str, root: Path) -> str:
    """Return a canonical project-relative target or deny outside writes."""
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve(strict=False)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        deny("target-outside-project")


def is_documentation(rel: str, root: Path) -> bool:
    """Allow markdown writes inside a configured search root.

    Planning documents must stay writable to create the artifacts this gate
    requires. Their exact subdirectory is not fixed, so any ``.md`` file under a
    configured search root is allowed; non-markdown source remains gated.
    """
    if not rel.endswith(".md"):
        return False
    target = (root / rel).resolve(strict=False)
    for root_path in search_roots(root):
        try:
            target.relative_to(root_path)
            return True
        except ValueError:
            continue
    return False

try:
    event = json.load(sys.stdin)
except (json.JSONDecodeError, ValueError):
    deny("invalid-event")

tool_input = event.get("tool_input")
if not isinstance(tool_input, dict):
    deny("missing-tool-input")

path = tool_input.get("file_path") or tool_input.get("notebook_path")
if not isinstance(path, str) or not path.strip() or len(path) > 4096:
    deny("invalid-target")

root_value = os.environ.get("CLAUDE_PROJECT_DIR")
if not root_value:
    deny("missing-project-root")
root = Path(root_value).resolve(strict=True)
rel = relative_target(path, root)

# Planning documents must remain writable to create the required model.
if is_documentation(rel, root):
    raise SystemExit(0)

for artifact_type in ARTIFACT_TYPES:
    if not has_approval(root, artifact_type, rel):
        deny(f"no-approved-{artifact_type}-for-target")

raise SystemExit(0)
