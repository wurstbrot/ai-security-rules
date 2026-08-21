# Infrastructure as Code, Container & Pipeline Security Rules

Apply these rules when generating Terraform/Pulumi, Kubernetes manifests,
Helm charts, Dockerfiles or CI/CD workflows.

## General IaC
- Least-privilege IAM: avoid wildcard actions or resources. Where an API cannot
  be scoped further, document the specific wildcard, conditions, affected
  principal and compensating monitoring. Use dedicated service accounts per
  workload.
- Private by default: no unrestricted ingress, public buckets/storage or public
  management ports. Internet-facing application listeners may allow
  `0.0.0.0/0` only when the threat model requires public access and network,
  TLS, authentication, rate-limit and monitoring controls are documented.
- Encrypt data at rest and in transit in every resource that supports it;
  prefer customer-managed keys (CMK/KMS) over provider-managed defaults for
  sensitive data.
- Enable audit logging on generated infrastructure (CloudTrail, Azure
  Activity Logs, GCP Audit Logs) and ship it to the central logging target.
- Cross-account/cross-service trust policies: explicit principals and
  actions only - never wildcards in trust relationships without strong
  conditions.
- Secrets come from a secret manager, never from IaC code, tfvars, state
  files or workflow YAML; mark variables `sensitive`.
- Terraform specifics (versions, state, provisioners, plan review): see
  `.ai-security-rules/frameworks/terraform.md`.
- Run the policy-as-code checks on every generated change before presenting
  it: OPA/conftest (see `.ai-security-rules/opa.md`) plus Checkov/tfsec/KICS
  where available.

## Dockerfiles
- Docker specifics (mandatory non-root user, image content, runtime flags):
  see `.ai-security-rules/frameworks/docker.md`.

## Kubernetes / Helm
- Pod security: `runAsNonRoot`, `readOnlyRootFilesystem`,
  `allowPrivilegeEscalation: false`, drop all capabilities; never
  `privileged`, `hostPath`, `hostNetwork` or `hostPID` without user
  confirmation.
- Set resource requests and limits on every container.
- Default-deny `NetworkPolicy` per namespace; open only required flows.
- Use a service mesh to encrypt pod-to-pod traffic with mutually authenticated
  TLS. Enforce the mesh's strict mTLS mode by default for every participating
  namespace/workload; plaintext fallback or permissive migration mode is not a
  steady-state configuration. Mesh identity must be workload-bound, certificates
  must rotate automatically, and certificate validation must fail closed.
  Explicitly cover ingress, egress and workloads that cannot join the mesh, or
  document their equivalent TLS control and approved risk decision. A mesh does
  not replace `NetworkPolicy`, application-layer authentication, or OPA
  authorization.
- Dedicated ServiceAccounts; `automountServiceAccountToken: false` when the
  pod does not use the API.
- Reference images by digest; separate namespaces per workload/environment.

### Rate limiting (Istio/Envoy)

The standard infrastructure implementation of the rate-limit requirements
in `.ai-security-rules/web.md` (API security, anti-automation):

- **Local rate limiting** (Envoy `local_ratelimit`, per-instance token
  bucket): coarse self-protection of a workload without external
  dependencies. Limits multiply with replica count - use only where that
  imprecision is acceptable.
- **Global rate limiting** (Envoy rate limit service, e.g. the reference
  RLS with Redis): cluster-wide limits keyed on descriptors; required
  where precise per-client or per-account budgets matter. Assess the RLS
  and its backend per `.ai-security-rules/supply-chain.md`.
- Enforce at the **ingress gateway** for all external traffic; add
  per-workload limits for high-value internal services.
- Key descriptors on **authenticated identity**: validated JWT claims
  (via `RequestAuthentication`) or the mTLS SPIFFE principal. Source-IP
  keying is weak behind NAT/CDNs, and `X-Forwarded-For` is
  client-controlled unless set by the trusted edge - never key on
  client-supplied headers.
- Decide and document **fail-open vs fail-closed** (`failure_mode_deny`)
  per limit class when the rate limit service is unreachable: fail closed
  for security-critical limits (authentication endpoints), otherwise a
  documented availability tradeoff. Envoy's default is fail-open.
- Return plain `429` responses without internal details; export and alert
  on throttled-request metrics.
- `EnvoyFilter` resources are version-sensitive: pin the Istio version,
  keep the filters in version control under policy-as-code checks, and
  re-run negative tests (expected `429`) after every mesh upgrade.
- Mesh-level limits are defense-in-depth: they **complement, never
  replace** application-level anti-automation (account-keyed lockout,
  delays, enumeration defenses - `.ai-security-rules/web.md`), which sees
  account context the mesh does not have.

## CI/CD workflows
- Pin actions/plugins to a full commit SHA, not tags.
- Minimal token permissions (top-level `permissions:` read-only; elevate per
  job only where needed).
- Never check out and execute untrusted fork code in a privileged context
  (`pull_request_target` + checkout of the PR head); flag any change to
  workflow trigger configuration for review.
- Authenticate to clouds via short-lived OIDC workload identity, not stored
  static credentials (see `.ai-security-rules/general.md`).
- Keep build and deploy as separate jobs/identities; deploy only verified,
  pinned artifacts.

# Sources
- Istio documentation, "Enabling Rate Limits using Envoy": https://istio.io/latest/docs/tasks/policy-enforcement/rate-limit/
- DSOMM (activities "Infrastructure as Code", "Least-privilege access baseline", Agentic AI Guidance/Verification): https://dsomm.owasp.org/
- OWASP Cheat Sheet Series (Docker Security, Kubernetes Security, Infrastructure as Code Security, CI/CD Security, Key Management, Logging): https://cheatsheetseries.owasp.org/
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
