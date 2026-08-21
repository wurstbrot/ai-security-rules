# Terraform Security Rules

Apply these rules when generating or changing Terraform code, in addition to
the general IaC rules in `.ai-security-rules/iac.md` (least-privilege IAM,
private by default, encryption, audit logging, trust policies).

## Versions & modules
- Use constraints appropriate to module type. Reusable modules declare tested
  minimum Terraform/provider versions without unnecessarily narrow upper
  bounds. Root modules use bounded constraints and commit `.terraform.lock.hcl`
  so providers resolve reproducibly. Pin third-party registry modules to a
  reviewed version and git modules to an immutable commit SHA.
- Evaluate third-party modules like any dependency per
  `.ai-security-rules/supply-chain.md`; prefer official/verified registry
  modules.

## State & secrets
- Use a remote backend with encryption at rest, state locking and
  restricted access; never commit `*.tfstate` or `*.tfvars` with secrets.
- Assume everything a resource returns lands in state as plaintext: prefer
  resource patterns that keep secrets out of state (e.g. write-only/
  ephemeral values, references to secret-manager ARNs instead of values),
  and treat state access as secret access.
- Mark secret variables and outputs `sensitive = true`; source secret
  values from the secret manager at apply time, never hardcoded.

## Code patterns
- Avoid `local-exec`/`remote-exec` provisioners, especially with
  user-influenced input; prefer native resources or configuration
  management.
- Protect critical resources (databases, state buckets, KMS keys) with
  `lifecycle { prevent_destroy = true }`.
- No public exposure by default (`0.0.0.0/0`, public ACLs) - flag and ask
  the user before generating any (see `iac.md`).

## Self-verification
- Run `terraform fmt -check` and `terraform validate`, plus the
  policy-as-code checks (OPA/conftest, tfsec/Checkov/Trivy where available)
  before presenting the change.
- Present the `terraform plan` output with the change and explicitly flag
  every destroy/replace of an existing resource; never suggest
  auto-approving applies with destructive actions.

# Sources
- DSOMM (activity "Infrastructure as Code"; Agentic AI Guidance/Verification): https://dsomm.owasp.org/
- OWASP Infrastructure as Code Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Infrastructure_as_Code_Security_Cheat_Sheet.html
- HashiCorp: sensitive data in state: https://developer.hashicorp.com/terraform/language/state/sensitive-data
