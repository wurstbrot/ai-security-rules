# JavaScript / TypeScript / npm Security Rules

Apply these rules for all JavaScript and TypeScript code (Node.js and
browser), in addition to the framework rules (`.ai-security-rules/frameworks/angular.md`, `.ai-security-rules/frameworks/reactjs.md`).

## Language-level rules
- Prefer TypeScript with `strict: true`; in plain JS use strict mode.
- Never use `eval`, `new Function`, `vm` modules or string arguments to
  `setTimeout`/`setInterval` with user-influenced data.
- Prevent prototype pollution: never deep-merge or `Object.assign` untrusted
  objects into configuration/state; reject or strip `__proto__`,
  `constructor` and `prototype` keys; use `Object.create(null)` or `Map` for
  lookup tables keyed by user input.
- Watch for ReDoS: avoid catastrophic-backtracking regexes on user input;
  prefer linear-time validation or bounded input length first.
- Use `===`/`!==`; validate types at trust boundaries (e.g. zod, joi) -
  TypeScript types do not exist at runtime.

## Node.js rules
- Spawn processes with `child_process.execFile`/`spawn` with an argv array
  and no `shell: true`; never build shell strings from user input.
- Prevent path traversal: resolve user-supplied paths against a base
  directory and verify the result stays inside it before any fs operation.
- Never `require`/`import` from dynamic, user-influenced paths.
- HTTP servers: set security headers (e.g. helmet), cookie flags
  (`HttpOnly`, `Secure`, `SameSite`), request body size limits and timeouts.
- Parameterize all database queries; encode output for its context (HTML,
  URL, JSON) - same as any other language.
- Secrets via environment/secret manager; never commit `.env` files.
- Cryptography only via `node:crypto`/WebCrypto following `.ai-security-rules/cryptography.md`
  (BSI-approved mechanisms only).

## npm / dependency hygiene
- Always add dependencies via npm/pnpm/yarn with exact, pinned versions -
  no version ranges (`^`, `~`, `>=`) - and a committed lockfile; use
  frozen/immutable installation (`npm ci` or the package-manager equivalent)
  in CI.
- Evaluate every new package per `.ai-security-rules/supply-chain.md` (existence,
  publisher, source identity, Scorecard where available, maintenance and
  provenance) before adding it - LLM-suggested
  package names are frequently hallucinated or typosquatted.
- Be suspicious of install scripts: review `postinstall` hooks of new
  packages; consider `--ignore-scripts` where feasible.
- Run the dependency checks (OSV-SCALIBR or agent-performed:
  vulnerabilities, newer release, 7-day cooldown - see
  `.ai-security-rules/supply-chain.md`) and fix findings; keep dependencies
  updated; prefer packages with provenance/attestations.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Cheat Sheet Series (Node.js Security, Prototype Pollution Prevention, Regular Expression DoS): https://cheatsheetseries.owasp.org/
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- npm security best practices: https://docs.npmjs.com/security-best-practices
