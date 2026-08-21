# Threat Modeling Rules

Threat modeling is **mandatory and happens before the implementation phase starts**
for a feature or security-relevant change. Documentation-only edits, diagnosis
and emergency remediation that restores an existing control may use a short
record created alongside the change; document why the normal sequence was not
possible.
Do not generate implementation code for a feature that has no applicable threat model.
If the user asks for implementation and no threat model exists for the feature,
create one first (or ask the user to run through this process with you).

Before AI-assisted implementation, analyze the threats of the individual
feature. Convert the controls identified by that analysis into verifiable
acceptance criteria, and include those criteria both in the user story and in
the AI assistant's implementation task.

## Dedicated threat-modeling agent per feature

- Start a dedicated threat-modeling agent (subagent) for every feature/user
  story before its implementation. The agent receives the feature
  description, the specification and this rule file, runs the process below
  and writes the artifact to `docs/threat-models/<feature>.md` with
  `Status: proposed` and the required sections and `Applies-to:` list.
- Where the tm_skills agent skills are installed, the agent uses them:
  `ctm` to evaluate the user story for security-notable events, `4qpytm`
  for the guided four-question model, `pytm` for a codebase-level model
  with data-flow diagrams.
- The agent never approves its own artifact. The user (or designated
  reviewer) reviews the proposed model and records the approval
  (`Status: approved`, `Approved-by:`, `Approved-at:`); only then may
  implementation of the covered targets start (enforced by the local write
  gate).

## Process (per feature / user story)

**Step 0 - Determine the protection requirement.** Classify the feature
before modeling; the classification drives the depth of the threat model
and the strictness of controls (encryption, logging, caching):
- Criticality of the processed data (PII, credentials, financial or health
  data?)
- Accessibility (internal only vs. internet-facing)
- Regulatory requirements (e.g. GDPR, PCI-DSS, HIPAA)
Record the classification in the threat model notes; if it is unclear, ask
the user.

**Step 1 - Conduct Threat Modeling.** Answer these four standard threat-modeling questions:

1. **What are we working on?**
   Sketch the data flow of the feature: entry points, assets/data touched,
   components involved, trust boundaries crossed (browser <-> API, service <->
   service, service <-> database, service <-> third party).
2. **What can go wrong?**
   Walk STRIDE (Spoofing, Tampering, Repudiation, Information disclosure,
   Denial of service, Elevation of privilege) over each element and boundary.
   Write an abuse story for each user story ("As an attacker, I ...").
3. **What are we going to do about it?**
   Turn each relevant threat into a concrete mitigation. Every
   authorization-related threat must name the OPA/Rego policy that enforces
   the mitigation (see `architecture.md` - OPA is mandatory).
4. **Did we do a good job?**
   Present the threat model to the user before implementation. Explicit user
   or designated-reviewer approval must be recorded in the artifact before
   implementation. Policy semantics, accepted risks and protection requirements
   always remain human decisions; human review is also required before merge or
   deployment.

## Output requirements

- Security requirements are recorded as **acceptance criteria in the user
  story** and passed into the implementation task/prompt.
- Threat model notes are stored under version control, e.g.
  `docs/threat-models/<feature>.md`.
- For machine-assisted enforcement, include `Status: proposed|approved` and an
  `Applies-to:` list of repository-relative glob patterns. An approved artifact
  also records non-empty `Approved-by:` and `Approved-at:` metadata. Approval
  must be an explicit user or designated-reviewer decision; file existence
  alone is not approval.
- The local hook requires these exact second-level section headings:
  `## Scope and protection requirement`, `## User story and abuse stories`,
  `## Threats and mitigations`, and `## Accepted risks`. Missing or renamed
  sections do not authorize implementation targets.
- The security events the feature must log are named as acceptance criteria
  (authentication failures, authorization denials, input validation
  rejections, sensitive actions).
- Accepted risks are documented explicitly with a justification.
- Keep it lightweight: for a small feature this is half a page, not a workshop.

# Sources
- DSOMM, activities "Threat modeling rule", "Spec-driven development", "Determining the protection requirement" and "Logging of security events": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Threat Modeling Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
- Toreon Threat Modeling Playbook: https://github.com/Toreon/threat-model-playbook
- tm_skills - agent skills for continuous threat modeling (pytm): https://github.com/izar/tm_skills
