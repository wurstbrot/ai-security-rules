# Developer Guide

This guide covers working on this repository itself (or on a copy adapted
to your organization). For using the rules in a project, see `README.md`.

## Running the tests

The local hooks (shipped in `rules/.claude/hooks/`) have regression
tests:

```shell
python3 -m unittest discover -s tests -v
```

They cover the phase-artifact write gate
(`tests/test_threat_model_gate.py`), the security-context loader
(`tests/test_security_context_hook.py`) and drift verification
(`tests/test_security_drift.py`).

## Refreshing the integrity baseline

The manifest protects the distributable content in `rules/`. Before
refreshing the integrity baseline, review the protected changes and run:

```shell
CLAUDE_PROJECT_DIR="$PWD/rules" python3 rules/.claude/hooks/verify-security-drift.py --write
CLAUDE_PROJECT_DIR="$PWD/rules" python3 rules/.claude/hooks/verify-security-drift.py
```

Protected CI should run the second command and require independent review
for manifest changes. The local hash check detects divergence but cannot
identify or authenticate the approver.

## Changing rule files

The phase gate ships with `rules/` for consuming projects and does not
gate authoring in this repository. Authoring is governed by the root
`AGENTS.md` (rules for designing the rules): canonical file per topic,
cited sources with preserved attribution, no silent weakening. Rule
changes are security-critical - keep them small, document
security-relevant decisions under `docs/`, and present the diff for
independent human review together with the drift-check result.
