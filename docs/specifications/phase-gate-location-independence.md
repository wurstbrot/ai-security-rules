# Design decision: location-independent phase-artifact classification

Status: proposed
Approved-by:
Approved-at:
Applies-to: rules/.claude/hooks/security_artifacts.py, rules/.claude/hooks/threat-model-gate.py

## Problem

The phase gate discovered approved specification, threat-model and plan
artifacts only in three hard-coded subdirectories (`docs/specifications/`,
`docs/threat-models/`, `docs/plans/`), scanned non-recursively. Workflows that
place planning documents elsewhere - for example BMAD, which keeps its PRD,
architecture and story files under its own `docs/` layout - could not satisfy
the gate without renaming folders. The requirement being enforced is "an
approved artifact of each phase covers the target", not "a file exists in a
specific folder"; the folder coupling was incidental.

## Decision

Identify an artifact's phase by a `Type:` metadata marker
(`specification` | `threat-model` | `plan`) rather than by its folder. The gate
scans configurable search roots recursively (default `docs/`, overridable via
the `SECURITY_PHASE_SEARCH_ROOTS` environment variable) and classifies each
`*.md` file by its marker. An explicit marker is authoritative: an unknown
marker value is not an artifact and does not fall back to the directory name.
Artifacts without a marker keep being classified by the legacy subdirectory
name (`specifications/`, `threat-models/`, `plans/`), so existing layouts and
pre-marker artifacts continue to pass unchanged.

The approval contract is unchanged: `Status: approved`, non-empty
`Approved-by:`/`Approved-at:`, a target-matching `Applies-to:` list and the
phase's required `## ` sections with non-empty content are all still required
for every target before non-document source may be written.

## Security-critical changes requiring human review

- `.claude/hooks/security_artifacts.py` - new `Type:` marker classification,
  configurable/bounded search roots and recursive discovery (guardrail logic).
- `.claude/hooks/threat-model-gate.py` - `is_documentation` now allows markdown
  writes anywhere under a configured search root instead of only under the three
  fixed planning prefixes. This is a deliberate, bounded relaxation of the
  bootstrap write-allowance (markdown only, within search roots); it is flagged
  here per the `AGENTS.md` "never weaken a rule silently" obligation.
- `.security-rule-manifest.json` must be refreshed (`--write`) only after this
  decision and the diff are reviewed; the refresh is itself security-critical.

## Sources

OpenSSF Security-Focused Guide for AI Code Assistant Instructions; DSOMM
Agentic AI dimension. Full URLs in `rules/AGENTS.md`.
