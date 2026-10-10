# Design decision: Agent Authority rule file

Status: proposed
Approved-by:
Approved-at:
Applies-to: rules/.ai-security-rules/agent-authority.md

## Problem

The ruleset expressed the classical protection principles (least privilege,
fail-safe defaults, complete mediation, economy of mechanism) only as they
apply to conventional application resources. It did not model an **AI agent
deployed in a consuming project** as a delegated-authority subject. The
agent-specific thesis - enforcement outside the agent's own context,
re-approval when a proposed action changes, least privilege over tool scopes
with a removal test, ownership of authority and task-change re-justification,
and "no authority from the environment" - had no home.

## Decision

Add one canonical file, `.ai-security-rules/agent-authority.md`, for the
agent-as-subject topic. It reuses the decision mechanics defined in
`authorization.md` and `opa.md` (ABAC, deny by default, policy table,
STOP-AND-ASK, bounded caching/revocation) by cross-reference rather than
restating them, per the one-canonical-file rule in `AGENTS.md`.

`architecture.md`, `authorization.md` and `general.md` cross-reference the new
file; `AGENTS.md` adds it to the step-dependent loading map; the
`load-security-context.py` hook loads it alongside the phase rules when the
prompt mentions a deployed agent (specific multi-word terms, so a bare "agent"
does not trigger it).

## Sources

Saltzer & Schroeder 1975; OWASP LLM Top 10 LLM06 Excessive Agency; OWASP GenAI
Security Project AI Agent Security; NIST SP 800-207 Zero Trust Architecture.
Full URLs in the rule file's `Sources` section.

## Security-critical changes requiring human review

- `.claude/hooks/load-security-context.py` (new `AGENT_RULE`/`AGENT_TERMS`
  branch) - a guardrail-logic change.
- `.security-rule-manifest.json` must be refreshed (`--write`) only after this
  decision and the diff are reviewed; the refresh is itself security-critical.
