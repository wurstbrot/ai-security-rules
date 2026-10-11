# General Security Principles
Always follow the secure coding baseline in `.ai-security-rules/general.md` (read it before writing code).

# Step Depending Security Rules
Read the matching file from `.ai-security-rules/` when the step starts; load rule files on demand, not all at once.

## Planning Phase (specify / plan)
- Phase artifacts are identified by a `Type:` marker (`specification`,
  `threat-model`, `plan`), not by folder. Store them under any of the configured
  search roots (default `docs/`, override with `SECURITY_PHASE_SEARCH_ROOTS`);
  subfolders are free, so BMAD-style layouts work unchanged. Without a `Type:`
  marker the legacy subdirectories (`specifications/`, `threat-models/`,
  `plans/`) still classify the artifact.
- Record the specification with `Type: specification`, `Status: approved`,
  non-empty `Approved-by:` and `Approved-at:` metadata, a target-matching
  `Applies-to:` list and `## Acceptance criteria` before implementation.
- Read `threat-modeling.md` - a threat model is mandatory before implementation starts. Start a dedicated threat-modeling agent per feature (tm_skills where installed: `ctm`, `4qpytm`, `pytm`); it writes a `Type: threat-model` artifact with `Status: proposed`, the user approves.
- Create abuse stories for each user story.
- Read `architecture.md` - in-scope application authorization is enforced via Open Policy Agent; document out-of-scope cases and approved exceptions.
- Read `authorization.md` - every protected application resource needs a deny-by-default policy table; if attributes or per-action policies are unknown: stop and ask.
- Record the implementation plan with `Type: plan`, `Status: approved`, a
  target-matching `Applies-to:` list, approval metadata and
  `## Implementation steps`. The local write gate requires all three approved
  phase artifacts.

## Implementation
- Check user inputs for expected format and length.
- Read the rule files matching the touched stack - languages: `languages/javascript.md`, `languages/java.md`, `languages/python.md`; frameworks: `frameworks/flask.md`, `frameworks/angular.md`, `frameworks/reactjs.md`, `frameworks/spring-boot.md`.
- IaC, Dockerfiles, Kubernetes/Helm or CI/CD pipelines touched -> read `iac.md`; for Terraform also read `frameworks/terraform.md`, for Dockerfiles/Compose also `frameworks/docker.md`.
- HTTP responses/endpoints/UI touched -> read `web.md` - security headers, cookie flags, caching and browser storage rules.
- When protected resources or authorization are touched, read `authorization.md` and `opa.md` - ABAC, deny by default, enforced via OPA; the STOP-AND-ASK rule is a hard gate for missing policy semantics.
- Crypto touched -> read `cryptography.md` - only BSI TR-02102 mechanisms; otherwise ask the user.
- Dependency or container image added/changed -> read `supply-chain.md` - perform the risk assessment; a Scorecard result is one signal, not proof of trustworthiness.

## Review / Verification
- Read `verification.md` before presenting a change - run the project's checks, never weaken or bypass them, present the result for review.
- Every feature needs negative security tests (rejected inputs, denied access, forbidden states) - not only OPA policies.

# Sources
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- DSOMM Agentic AI dimension (Guidance and Verification activities; the step-dependent loading follows its "Instructed load of security rules" example): https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
