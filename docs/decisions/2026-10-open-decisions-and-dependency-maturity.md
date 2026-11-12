# Decision: label open security decisions instead of inventing values; dependency maturity criteria

Date: 2026-10-13

## Context

The ruleset is an opinionated organization baseline and deliberately fixes
many security parameters (session lifetimes, CSP, crypto per BSI TR-02102,
oauth2-proxy, OPA, Istio). It did not say what an assistant must do when a
security parameter is fixed by neither the rules nor the approved phase
artifacts, and the only explicit stop-and-ask lived in `authorization.md`.
A review of an external spec-bootstrap prompt showed three further gaps:
compliance regimes being inferred from data types, unverifiable claims
about which sources or rule files were consulted, and missing maturity
criteria (end-of-life, pre-release, transitive tree) for libraries.

## Decision

- `general.md` gains "Open decisions and unknown facts": undetermined
  parameters are asked, not invented; where asking is impossible they are
  labelled `TO BE DECIDED` / `UNKNOWN` / `ASSUMPTION` and the result is not
  production-ready. Compliance regimes are never inferred from data types.
  Labels are explicitly subordinate to the existing hard stop-and-ask gates
  (undefined authorization policy, local credentials, sensitive browser
  storage, missing approved threat model): there the gated code is not
  generated and the question is handed back to the main agent or human.
- `threat-modeling.md` Step 0 records unknown jurisdiction as `TO BE DECIDED`.
- `verification.md` requires naming the rule files and references actually
  read and forbids fabricated sources or requirement identifiers.
- `supply-chain.md` adds: justification of every new dependency, no
  reimplementation of security-critical functionality to avoid one, no
  deprecated/EOL/pre-release packages, twelve-month maintenance evidence,
  newest supported stable release after cooldown, transitive-graph review.

The external prompt served as inspiration only; all rules are written in
the ruleset's own words and are backed by the sources already listed in the
affected files (OpenSSF guide, OWASP Vulnerable Dependency Management Cheat
Sheet, OWASP AISVS Appendix C, DSOMM).

## Not adopted

- A blanket "do not invent session timeouts, CSP, algorithms, rate limits"
  list: these values are intentionally set by this ruleset.
- "Do not ask clarifying questions": asking remains the default; labels are
  the fallback for unattended execution only.
- A per-mitigation status column in threat models: conflicts with the
  lightweight artifact the hook expects.

## Risk accepted

Labelled gaps may survive into a merge if reviewers ignore them. Mitigation:
`verification.md` requires listing them when presenting and forbids calling
such a change production-ready; existing rules forbid self-approval.
