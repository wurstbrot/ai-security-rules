# secure-ai-rules

Secure coding rules for AI coding assistants (Claude Code, Cursor, GitHub
Copilot, ...), implementing selected *Guidance* and *Verification* activities of the
[DSOMM Agentic AI dimension](https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml).

The goal: when an AI assistant generates code in your projects, it follows an
organization-wide secure-coding baseline, loads technology-specific rules at
the right development step, and never starts implementing before a threat
model exists.

## Usage in a project

The distributable ruleset lives in the `content/` folder. Copy the contents
of `content/` (`AGENTS.md`, `CLAUDE.md`, `.ai-security-rules/`, `.claude/`,
`.security-rule-manifest.json`) into the project root (or add this
repository as a git submodule and reference `content/` from the project's
instruction file). Tools that read `CLAUDE.md`/`AGENTS.md` pick up the
baseline automatically; the framework-specific and phase-specific rules are
loaded on demand via the "Step Depending Security Rules" mapping, so the
session context stays small.

The repository root outside `content/` is the authoring workspace: its own
`AGENTS.md` contains the rules for designing the rules, and the phase gate
does not apply there - it is meant for real source-code generation in
consuming projects.

Other assistants: many agents (GitHub Copilot coding agent, Codex, Cursor)
read `AGENTS.md` natively; for the rest, reference it from the tool's
instruction file (e.g. `.github/copilot-instructions.md`,
`.cursor/rules/security.mdc`).

Defense in depth: `content/.claude/settings.json` ships three local controls
for Claude:

- A `UserPromptSubmit` hook loads fixed phase rules and stack rules recognized
  in the prompt into the model context. Unknown phases add no context; the
  normal `AGENTS.md` mapping remains the fallback.
- A `PreToolUse` hook permits implementation targets only when structurally
  complete, approved specification, threat model and plan artifacts all contain
  a matching repository-relative `Applies-to` pattern.
- A `SessionStart` hook verifies the security-rule SHA-256 manifest and reports
  missing, modified or unexpected protected files.

The `.claude/` directory and `.security-rule-manifest.json` inside
`content/` activate these controls when copied along with the rest of the
folder.

The local hook is deliberately **not described as a security boundary**. A
developer controls the workstation and can write through tools the hook does
not observe. Authoritative enforcement belongs in protected CI/branch rules;
changes to hooks, security instructions and CI configuration require independent
human review. The marker is syntactic and cannot prove the approver's identity;
CODEOWNERS/branch protection must enforce that identity.

The hook rejects write-tool targets outside the canonical project root. This is
an intentional fail-closed choice: use project-local scratch space or a
separately controlled temporary-file mechanism instead of granting the hook a
broad outside-root exemption.

Specifications are stored in `docs/specifications/` and require
`## Acceptance criteria`; plans are stored in `docs/plans/` and require
`## Implementation steps`; threat models are stored in `docs/threat-models/`
and require the sections documented in `threat-modeling.md`. All three use this
machine-readable header:

```markdown
Status: approved
Approved-by: reviewer@example.org
Approved-at: 2026-08-21

Applies-to:
- `src/payments/**`
- `policy/payments/**`
```

The metadata preamble must also contain non-empty `Approved-by:` and
`Approved-at:` fields. The status represents a documented human decision, not
merely file creation.

## Development

Maintainer tasks - running the hook regression tests and refreshing the
security-rule integrity baseline - are documented in `DEVELOPER.md`.

## DSOMM activities covered

### Agentic AI dimension

- **Static load of security rules** (Guidance, level 1) - baseline in `AGENTS.md`, auto-loaded via `CLAUDE.md`
- **Instructed load of security rules** (Guidance, level 2) - step-to-artifact mapping in `AGENTS.md`
- **Language and framework specific security rules** (Guidance, level 2) - per-framework files in `.ai-security-rules/`
- **Threat modeling rule** (Guidance, level 2) - `threat-modeling.md`, supported by a local defense-in-depth hook
- **Spec-driven development and human phase review** - approved specification,
  threat model and plan artifacts are required by the local write gate
- **Dynamic load of security rules** (Guidance, level 4) - phase- and
  stack-dependent context injection via `UserPromptSubmit`
- **Verification activities** - `verification.md` (self-verification,
  dependency validation, no verification bypass, human review)
- **Drift detection for agent instructions and guardrails** (Verification,
  level 5) - versioned manifest plus session-start verification

### Other dimensions

The rule content also supports DSOMM activities outside the Agentic AI
dimension. The rules make the AI assistant perform or demand these
practices; they support the activity but do not by themselves implement
the organization-wide process DSOMM describes:

- **Use correct OAuth2/OIDC authorization flows** (Identity and Access
  Management) - `web.md`, authentication flows
- **Infrastructure as Code** - `iac.md`, `frameworks/terraform.md`
- **Least-privilege access baseline** - `iac.md`
- **Containers are running as non-root** - `frameworks/docker.md`
- **Logging of security events** - named security events in
  `threat-modeling.md`, logging rules in `architecture.md`/`general.md`
- **Determining the protection requirement** - step-0 classification in
  `threat-modeling.md`

Partially supported through rule content (no dedicated activity
implementation): SBOM generation, pinning and signing of artifacts,
secret scanning, SAST usage and network segmentation
(NetworkPolicy/mTLS). As stated above for compliance in general: coverage
claims require verification in the concrete project, not rule files
alone.

## Related rule collections

For extending coverage to further languages/frameworks, orient on these
ready-made collections (referenced by DSOMM):

- Secure Code Warrior AI Security Rules (backend/frontend/mobile + per-language): https://github.com/SecureCodeWarrior/ai-security-rules
- TikiTribe Claude Secure Coding Rules (100+ rule sets, Do/Don't/Why/Refs structure, incl. AI/ML, RAG, IaC, containers, CI/CD): https://github.com/TikiTribe/claude-secure-coding-rules
- Wiz Secure Rules Files (reference collection only; its CC BY-NC-ND 4.0
  license does not permit distributing adaptations): https://github.com/wiz-sec-public/secure-rules-files

## AI assistance

This repository was created with the assistance of AI (Claude Code). The
content is based on the sources cited below and in each rule file and is
subject to human review.

## Sources

- DSOMM Agentic AI dimension: https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- Per-file sources are listed in each rule file's `Sources` section, including
  the license and modification note for adapted third-party material.

## License

This repository is licensed under [Creative Commons Attribution 4.0
International (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) -
see `LICENSE`. You may copy, adapt and redistribute the rules, including
commercially, as long as you give appropriate credit and indicate changes.
Adapted third-party material keeps its own attribution, noted in the
affected rule files' `Sources` sections (e.g. TSS-WEB, CC BY 4.0).
