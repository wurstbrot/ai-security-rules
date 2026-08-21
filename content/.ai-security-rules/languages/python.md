# Python Security Rules

Apply these rules for all Python code, in addition to
`.ai-security-rules/frameworks/flask.md` when Flask is used.

## Unsafe evaluation & deserialization
- Never call `eval`, `exec` or `compile` on user-influenced data.
- Never unpickle untrusted data (`pickle`, `shelve`, `marshal`); use JSON
  with a validated schema instead. Use `yaml.safe_load`, never `yaml.load`.
- Parse XML with `defusedxml` (or explicitly disabled DTD/external
  entities) to prevent XXE.

## OS, files, processes
- Start processes with `subprocess` using a list argv and `shell=False`;
  never `os.system` or shell strings built from user input.
- Prevent path traversal: resolve user-supplied paths (`Path.resolve()`)
  and verify `is_relative_to()` the intended base directory.
- Use the `tempfile` module for temporary files; never predictable names in
  `/tmp`.
- Never use `assert` for security checks - asserts are stripped with `-O`.

## Network & crypto
- `requests`/`httpx`: always set timeouts; never `verify=False`; validate
  and allowlist user-supplied URLs before fetching (SSRF).
- Randomness for tokens/keys via the `secrets` module, never `random`.
- Cryptography via the `cryptography` package with BSI-approved mechanisms
  only - see `.ai-security-rules/cryptography.md`.

## Data & hygiene
- Parameterized queries / ORM for all database access; never build SQL with
  f-strings or `%` formatting.
- Validate data at trust boundaries with pydantic/marshmallow; use type
  hints and follow PEP 8.
- Use virtual environments; pin exact dependency versions - no version
  ranges - with a lockfile
  (uv/poetry/pip-tools) and evaluate new packages per
  `.ai-security-rules/supply-chain.md`; run Bandit and the dependency
  checks (OSV-SCALIBR or agent-performed: vulnerabilities, newer release,
  7-day cooldown) as part of self-verification.
- Never log secrets or PII; sanitize CR/LF from user input before logging.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- OWASP Cheat Sheet Series (Injection Prevention, Deserialization, XXE Prevention, SSRF Prevention): https://cheatsheetseries.owasp.org/
- Python security documentation: https://docs.python.org/3/library/security_warnings.html
