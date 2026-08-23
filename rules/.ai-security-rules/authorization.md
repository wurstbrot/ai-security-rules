# Security Rule: Authorization (ABAC, Deny by Default)

## Non-negotiable principle

Access control for protected application resources is **attribute-based
(ABAC)** and **deny by default** (NIST SP 800-162; OWASP Authorization Cheat
Sheet). The threat model identifies which resources are protected. Every such
access decision:

    decision = policy(subject attributes, resource attributes, action, context)

- **Subject**: e.g. `user.id`, `user.tenant_id`, `user.department`,
  `user.clearance`, `user.roles` (a role is ONE attribute among others)
- **Resource**: e.g. `resource.owner_id`, `resource.tenant_id`,
  `resource.status`, `resource.classification`
- **Action**: read / create / update / delete / list / export / approve ...
- **Context**: e.g. time window, request origin, MFA level, approval state

Forbidden shortcuts: authentication ("user is logged in") is NOT
authorization; a bare role check (`user.role == "admin"`) is NOT a policy -
pure RBAC cannot express ownership, tenancy or state where those constraints
apply, so do not use it as a shortcut for a richer policy;
never hardcode policy logic in handlers - all decisions go through OPA
(mandatory, see `.ai-security-rules/opa.md`).

## STOP-AND-ASK rule (hard gate)

Before generating or modifying an endpoint, resolver, handler, background job
or query that performs a protected action, you MUST know:

1. the relevant **subject attributes** (tenant, ownership, department, role,
   clearance),
2. the constraining **resource attributes** (owner_id, tenant_id,
   status/lifecycle, classification),
3. the attribute condition **per action** (they usually differ),
4. any **context conditions** (time, MFA, approval, origin),
5. the **failure mode** on denial (403 vs. 404 to hide existence).

If any answer is missing from the spec, ticket or conversation: **STOP. Do
not generate code. Ask the user.** Never assume "public", "any authenticated
user", "same tenant is fine" or "same as the other endpoints".

## Required spec artifact: ABAC policy table

Every protected resource needs a policy table (in the spec or next to the policy code)
before implementation starts, e.g.:

| Action | Policy (attribute condition)                                      | On deny |
|--------|-------------------------------------------------------------------|---------|
| read   | subject.tenant_id == resource.tenant_id                           | 404     |
| update | subject.id == resource.owner_id AND resource.status == "draft"    | 403     |
| export | read-policy AND subject.mfa_level >= 2                            | 403     |

The table enumerates what is allowed - **any action, subject or resource not
matching a listed condition is denied**; there is no implicit fallback to
allow. Conditions must reference the concrete attributes needed by the policy.
A role may be the complete condition only when the threat model establishes
that no ownership, tenancy, lifecycle, classification or contextual constraint
applies; record that decision in the table. Cannot define the required
condition? -> STOP-AND-ASK.

## Implementation requirements

- Handlers only call `authorize(subject, action, resource, context)`; the
  decision logic lives in OPA/Rego (`.ai-security-rules/opa.md`).
- Attributes from trusted sources only: subject from the verified
  session/token, resource from the datastore - never from client input.
  Never mass-assign authorization-relevant fields (owner_id, tenant_id,
  roles, status, classification) from requests.
- Attribute-scoped queries at the data layer (tenant filter, row-level
  security) - including list endpoints; never raw `find(id)` on
  client-supplied IDs (IDOR).
- Fail closed: a route without a registered policy is rejected; register the
  policy in the same change that adds the route.
- Any protected endpoint, helper route or query not in the spec -> STOP-AND-ASK
  applies to it as well. Health/readiness endpoints and intentionally public
  resources still need an explicit classification, but not a fabricated ABAC
  policy.

## Required tests (definition of done)

Negative tests that vary the ATTRIBUTES: unauthenticated -> 401; wrong
attribute value (other tenant / not owner) on a VALID foreign ID -> denied
(IDOR/cross-tenant); correct owner but wrong resource state -> denied;
missing context condition (e.g. no MFA) -> denied; role alone without the
other required attributes -> denied; list endpoints return ONLY records
matching the subject's attributes. Happy-path tests alone do not complete
the task.

## References

- OWASP Top 10 2021 A01 Broken Access Control; OWASP Authorization Cheat Sheet
- OWASP ASVS 5.0, chapter Access Control
- NIST SP 800-162 (ABAC reference model)
