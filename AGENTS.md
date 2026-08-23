# Ruleset Authoring Rules

This repository authors the secure-ai-rules content. The distributable
ruleset lives in `rules/`; consuming projects copy the contents of
`rules/` into their project root. The phase gate (approved
specification, threat model and plan) ships with `rules/` and applies
to source-code generation in consuming projects - it does not gate
authoring work in this repository.

## Changing rule files (rules/.ai-security-rules/)

- Read the target rule file fully before changing it.
- One canonical file per topic; other files cross-reference it instead of
  restating. Exception: MUST-critical one-liners (parameterized queries,
  no hardcoded secrets, output encoding) may be repeated so they survive
  partial context loads.
- Keep the MUST/SHOULD convention defined in `rules/.ai-security-rules/
  general.md`. Never weaken or remove an existing rule silently; flag any
  weakening explicitly for human review.
- Every rule needs an authoritative source; keep the file's `Sources`
  section current. Adapted third-party material keeps its attribution and
  modification note (CC BY 4.0 obligations, e.g. TSS-WEB, OpenSSF).
- Document security-relevant design decisions under `docs/`
  (specifications, threat models, plans), even though no hook enforces
  this for authoring.

## Verification of ruleset changes

- Run the regression tests: `python3 -m unittest discover -s tests -v`.
- Run the drift check:
  `CLAUDE_PROJECT_DIR="$PWD/rules" python3 rules/.claude/hooks/verify-security-drift.py`.
  Refresh the manifest (`--write`) only after human review of the
  protected changes; the refresh itself is security-critical.
- Keep `README.md` and `DEVELOPER.md` consistent with the `rules/`
  layout when paths or behavior change.
- Changes to hooks, `rules/.claude/settings.json` or tests are
  security-critical; point them out explicitly when presenting a diff.
