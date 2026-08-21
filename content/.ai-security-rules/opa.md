# Open Policy Agent (OPA) Security Rules

OPA is mandatory for the protected application-resource decisions defined as
in scope by `architecture.md`. Apply these rules whenever you write Rego
policies or integrate an application with OPA.

## Policy authoring (Rego)

- Default deny: every entry-point rule starts from `default allow := false`
  (or an equivalent deny-by-default structure). Never write policies that are
  allow-by-default with deny exceptions.
- Use modern Rego (`import rego.v1`), one package per service/domain, and run
  `opa fmt` and `opa check --strict` on all policies.
- Every policy has unit tests (`opa test`), including **negative tests**
  (requests that must be denied). Policy changes without tests are incomplete.
- Never embed secrets, API keys or credentials in policies or data documents.
- JWT claims used in policies must come from verified tokens: use
  `io.jwt.decode_verify` (never `io.jwt.decode` alone), or have the
  application/gateway verify the token before its claims enter `input`.
- Keep policies readable and small; prefer several focused rules over one
  complex expression - policies are security-critical code and get reviewed.

## Application integration

The ABAC model, the STOP-AND-ASK gate, attribute trust rules and the PDP
requirements are defined in `.ai-security-rules/authorization.md`; the rules
here cover only the OPA-specific mechanics.

- Integrate OPA as sidecar, embedded library or central PDP.
- Fail closed: treat OPA errors, timeouts or missing decisions as **deny**.
- Define availability requirements, bounded timeouts and overload behavior.
  Caching is allowed only for a bounded lifetime with policy/version keys and
  documented revocation risk; never turn an indeterminate result into allow.
- Send a minimal, well-defined decision input (subject, action, resource,
  context). Do not pass raw request bodies or unvalidated user data into
  `input` without a defined schema.
- When generating OPA deployment or configuration: enable decision logging
  and mask sensitive input fields (decision log masking), configure signed
  bundles with signature verification, and never expose OPA's management
  APIs publicly or without authentication.
- Authenticate and protect network access to both decision and management APIs;
  use workload identity/mTLS across hosts or trust boundaries and least-
  privilege network policy for sidecars.

## CI/CD and infrastructure

- Keep policies in version control next to the application code; include
  `opa test` in your self-verification of any policy change.
- When generating CI pipelines, IaC or Kubernetes manifests, include
  OPA/conftest policy checks and run them before presenting the change.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OPA security documentation: https://www.openpolicyagent.org/docs/latest/security/
- OPA policy testing: https://www.openpolicyagent.org/docs/latest/policy-testing/
- OPA decision log masking: https://www.openpolicyagent.org/docs/latest/management-decision-logs/
- Conftest: https://www.conftest.dev/
