# ARCHITECTURE REQUIREMENTS

## Authorization: Open Policy Agent (mandatory for protected application resources)

- Services that make authorization decisions for protected application
  resources externalize those decisions to **Open Policy Agent (OPA)**.
  Static sites, libraries, local tools without protected multi-user resources,
  and authentication-only public endpoints are outside this requirement.
  Document the classification in the threat model. Deviations for an in-scope
  service require an architecture decision and explicit human approval.
- Application code never hardcodes authorization logic (no inline role checks
  scattered through handlers). Instead, the application builds a decision
  request (subject, action, resource, context) and asks OPA for the decision.
- Policies are written in Rego, live in the repository (e.g. `policy/`), are
  reviewed like code and tested with `opa test`.
- Default deny: both the Rego policies and the application integration must
  fail closed. If OPA is unreachable or returns no decision, access is denied.
- The authorization model is attribute-based (ABAC) and deny by default -
  see `.ai-security-rules/authorization.md` for the binding rules.
- See `.ai-security-rules/opa.md` for the OPA/Rego coding rules.

## Development workflow

- Spec-driven: specify -> **threat model** (see `threat-modeling.md`) -> plan ->
  implement -> verify. Threat modeling is completed before implementation starts.
- Keep phase artifacts (specification, threat model, plan) under version
  control. Record explicit human approval in each artifact before starting the
  next phase; an undocumented continuation or the artifact's existence is not
  review evidence.

## General architecture rules

- Document trust boundaries. Authenticate callers and authorize protected
  actions at each applicable boundary; explicitly model intentionally anonymous
  public access and machine/system subjects.
- Protect network communication against interception and tampering. Use TLS for
  traffic crossing hosts or trust boundaries. Same-host communication may use
  Unix sockets, loopback plus operating-system isolation, or service-mesh
  controls when justified by the threat model.
- Secrets come from a secret manager or environment injection, never from
  files committed to the repository.
- Least privilege for every component: minimal database grants, minimal cloud
  IAM permissions, minimal container capabilities, non-root containers.
- Centralized, structured logging of security-relevant events (authentication,
  authorization decisions, input validation failures) without secrets or PII.

# Sources
- DSOMM Agentic AI dimension (Guidance activities): https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OPA documentation: https://www.openpolicyagent.org/docs/latest/
