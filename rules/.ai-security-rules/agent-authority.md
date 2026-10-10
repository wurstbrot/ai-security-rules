# Security Rule: Agent Authority (Delegated Authority for AI Agents)

Apply this file when the project **deploys an AI agent** - an LLM (or
LLM-driven component) that can invoke tools, call services, or create, modify
or delete records at runtime on behalf of a principal. It does not apply to
projects that only *use* an assistant to author code. Authority over those
resources stays with the people accountable for them; the agent only acts on
their behalf. Classify the agent and its granted authority in the threat model.

This file governs **the agent as a subject**. The mechanics of an access
decision - ABAC, deny by default, the policy table, the STOP-AND-ASK gate,
attribute trust - are defined once in `.ai-security-rules/authorization.md`
and enforced via `.ai-security-rules/opa.md`; this file does not restate them.
Classical protection principles (Saltzer & Schroeder 1975) are applied here to
the agent's delegated authority, and each is phrased as a question the design
must answer with evidence, not a control that certifies the system by itself.

## Non-negotiable principle

An agent action is a **delegated-authority** action: it carries a principal's
authority into an operation someone else is accountable for. For every tool or
operation an agent can invoke, the design MUST establish:

1. **why** the action is permitted (the approved task it serves),
2. **on whose behalf** it runs (the principal whose authority it carries), and
3. **what stops the agent exceeding its task** (the control that bounds it).

The agent's ability to perform an approved task is NOT evidence that it is
prevented from exercising wider powers. A demonstration of enforcement does not
establish that the policy is correct - an agent can faithfully comply with a
badly specified policy. Name the property a control actually establishes, and
what remains dependent on another decision or control.

## Enforcement outside the agent (complete mediation)

- The authorization decision for a sensitive operation MUST be made by a
  control **outside the agent's own context** - the agent proposes, a separate
  mediator decides. Never let the model decide whether its own action is
  allowed (OWASP LLM06 Excessive Agency; OWASP AI Agent Security).
- The decision MUST be bound to the **actor and the exact operation and
  arguments** being approved. If the proposed action, its target or its
  arguments change after approval, the prior approval is void and the action
  is **re-checked** before execution.
- **Every route** to a protected resource enforces the policy, not only the
  agent-initiated path: direct API, background jobs, scheduled runs, retries,
  tool chains and callbacks. Decision caching follows the bounded-lifetime /
  revocation rule in `.ai-security-rules/opa.md`; a stale cached allow after an
  authority change is a mediation failure.
- A schema or input validation that checks the **shape** of a request (types,
  fields, length) does NOT establish that the record belongs to the requester
  or that changing it serves a legitimate purpose. Validation is not
  authorization (see `.ai-security-rules/general.md`,
  `.ai-security-rules/authorization.md`).

## Least privilege for agent tools

- Grant the agent the **minimal set of tools and scopes** its approved task
  requires. A tool the task does not need is not granted "for convenience" or
  "to match another agent".
- Scope each tool to the narrowest resources, actions and parameters that
  satisfy the workload (e.g. read-only where the task only reads; a single
  resource class rather than a wildcard).
- Justify every granted permission against an identifiable task need. Apply the
  **removal test**: if revoking a permission leaves the approved workload
  intact, the permission was unnecessary and is removed. Integration
  convenience is not a justification.
- Standing administrative or broad access to avoid scoping work is forbidden;
  flag any such grant for explicit human approval in the threat model.

## Fail-safe defaults and failure ownership

- When valid authorization for an agent action cannot be established, the
  action is **denied** (deny by default, fail closed - see
  `.ai-security-rules/authorization.md` and `.ai-security-rules/opa.md`). An
  indeterminate decision is never promoted to allow.
- The behaviour when the authorization service is **unavailable** is an owned
  decision, not an implementation accident: the action stops unless a
  **separately authorised, documented emergency procedure** applies. An
  undocumented "let requests through" path is a hidden policy choice and is
  not permitted. Emergency procedures are documented in the threat model and
  tested like any other control.

## Economy of mechanism

- Keep the agent's security-relevant design **no more complex than the
  protection task requires**. Prefer one mediated decision path over
  authority scattered across prompts, tools and glue code.
- Maintain an inventory of the agent's tools, granted scopes and every
  exception to the default-deny posture, each with a named owner and a
  justification. Complexity that no one can account for is a finding.

## No authority from the environment (zero trust)

Running inside the organisation's network, cluster or service mesh gives the
agent **no blanket authority** over the resources reachable there (NIST
SP 800-207). Mesh membership or co-location authenticates a workload; it does
not authorise an action. Each access is decided on subject, resource, action
and context regardless of network position. This complements, and does not
replace, the transport controls in `.ai-security-rules/architecture.md`.

## Ownership of the agent's authority

- The **business owner** defines the agent's approved task. The **owners of the
  affected resources** determine the access it requires. The **implementation
  team** translates those decisions into controls whose behaviour can be
  inspected and tested.
- A **task change re-opens the authority question**. When the agent's approved
  task grows, specify which additional resources it may touch and under what
  conditions, justified against the new need. Granting broader (e.g.
  administrative) access to skip that work is forbidden.
- A named owner has authority to resolve scope disagreements, require a
  correction when the evidence for a grant is inadequate, and ensure the
  revised workflow is tested against both permitted and forbidden actions.

## Scope boundary

Staying within granted authority does not make an agent's output correct or its
policy sound: an agent can remain fully in-scope and still produce false
information or enact a harmful decision. These rules bound **what the agent is
permitted to do**; correctness of its output and of the policy itself is a
separate concern for the specification, threat model and review.

## Required tests (definition of done)

For each named principle, test the property, not the happy path:

- **Least privilege**: a removal test per granted permission - revoke it and
  confirm the approved workload still completes (permission unnecessary) or
  fails (permission justified); confirm out-of-scope tools/actions are denied.
- **Fail-safe defaults**: with the authorization dependency unavailable and
  with invalid/expired credentials, the agent action is denied; any emergency
  procedure behaves exactly as documented.
- **Complete mediation**: every route (direct API, background job, scheduled
  run, retry, tool chain) enforces the policy; after an authority change
  (revocation, expiry, policy change) a previously cached allow no longer
  grants access; a post-approval change to the operation or its arguments
  forces re-approval.
- **Economy of mechanism**: the tool/scope inventory matches what is actually
  granted, and every default-deny exception has a recorded owner and
  justification.

Happy-path tests alone do not complete the task (see
`.ai-security-rules/authorization.md`).

# Sources
- J. H. Saltzer and M. D. Schroeder, "The Protection of Information in Computer Systems", Proc. IEEE 63(9), 1975 (least privilege, fail-safe defaults, complete mediation, economy of mechanism): https://www.cs.virginia.edu/~evans/cs551/saltzer/
- OWASP Top 10 for LLM Applications, LLM06:2025 Excessive Agency: https://genai.owasp.org/llmrisk/llm062025-excessive-agency/
- OWASP GenAI Security Project - AI Agent Security (agentic authorization, out-of-context approval): https://genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
- NIST SP 800-207 Zero Trust Architecture (no implicit trust from network location or ownership): https://doi.org/10.6028/NIST.SP.800-207
- DSOMM Agentic AI dimension: https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
