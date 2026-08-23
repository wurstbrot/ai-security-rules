# General Security Principles

These rules are the organization-wide baseline. Apply a rule when its stated
technology or risk is in scope. `MUST` is mandatory; a deviation requires a
documented risk decision and human approval. `SHOULD` is the secure default and
may be changed when the threat model records why. Technology-specific files
may refine this baseline but must not silently weaken it.

## Inputs, outputs and data

- Validate untrusted input at trust boundaries for expected type, format,
  length/range and allowed values. Validate function arguments where callers
  cannot already guarantee the contract.
- Use parameterized database queries. Encode untrusted output for its exact
  context using framework encoders or safe APIs; generic "special-character
  escaping" is not a substitute for contextual HTML, URL, JavaScript or SQL
  handling.
- Classify sensitive data and PII. Protect it in transit and at rest according
  to the threat model, minimize collection and retention, and never put it in
  logs. "Encrypted storage" includes an approved platform/database encryption
  boundary with controlled key access; applications may process plaintext in
  memory only where functionally necessary.
- Return safe client errors without stack traces, secrets or internal details.
  Handle exceptions centrally so the application stays in a secure state on
  any expected or unexpected error. Use configurable structured logging and
  prevent log injection; tag security-relevant events (e.g. `[SEC]`) with
  timestamp, subject (user ID or source IP), affected component and outcome
  - without secrets or PII.

## Identity, authorization and secrets

- Delegate authentication to the central identity provider via OAuth2/OIDC;
  the standard integration is **oauth2-proxy** in front of the application.
  The application validates the forwarded token with evaluated libraries and
  does not implement local login or store and hash user passwords. If a task
  explicitly requires local credential storage, stop and ask the user. Never
  hardcode credentials,
  API keys or cryptographic keys; obtain them through a secret manager or
  controlled runtime injection.
- Apply `.ai-security-rules/architecture.md` and `authorization.md` to protected
  application resources. Authentication alone is not authorization; decisions
  deny by default and use OPA where the architecture rules declare it in scope.
- Use constant-time comparison when timing can disclose an unpredictable secret
  such as a MAC, bearer token or API key. Do not compare password hashes as a
  replacement for the password-hashing library's verification function.
- Follow least privilege for processes, database grants, IAM, containers and
  CI identities. Prefer short-lived workload identity over static CI or
  service credentials.

## Dependencies, builds and external artifacts

- Use the ecosystem's official package manager. Verify new dependency identity
  and assess it under `.ai-security-rules/supply-chain.md`; never invent a
  package name or copy an unaudited replacement from an arbitrary snippet.
- Pin exact dependency versions in the package manager - no version ranges -
  and commit the ecosystem lockfile or equivalent resolved-dependency record.
  Apply security updates deliberately by raising the pinned version.
- Keep an SPDX or CycloneDX SBOM for deployable products where the build system
  supports it. Use provenance/attestations for release artifacts according to
  deployment risk.
- Verify integrity and authenticity of important external scripts, actions,
  packages and images with publisher signatures, provenance or trusted hashes.
  Container images use trusted sources and immutable digests in deployments.
- Run the dependency checks when integrating a new library - OSV-SCALIBR
  preferred, agent-performed allowed (see
  `.ai-security-rules/supply-chain.md`).

## Platform defaults

- Use HTTPS and secure protocols across trust boundaries. Apply
  `.ai-security-rules/web.md` to HTTP/browser changes and `iac.md` to IaC,
  containers and CI/CD.
- Use high-level cryptographic libraries and `.ai-security-rules/cryptography.md`;
  never design custom primitives or protocols.
- Services SHOULD run as non-root with minimal capabilities. Containers SHOULD
  use a minimal image where operational needs such as debugging and incident
  response are still addressed.
- Do not weaken deserialization, XML entity, type-safety, browser or transport
  protections merely to make a feature work.

## Verification and review

- Add negative tests for security requirements and controls proportionate to
  risk. Mark incomplete security-sensitive placeholders as not production-ready.
- Use `.ai-security-rules/verification.md` before presenting a generated change.
  Actual tool output and manual analysis must remain clearly distinguishable.
- Apply OWASP Top 10/ASVS and relevant compliance requirements according to the
  system's protection requirement; do not claim compliance from these rules
  alone.

# Sources

- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- DSOMM Agentic AI dimension, activity "Static load of security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
