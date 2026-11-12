# Decision: identity, session, token and key hardening requirements

Date: 2026-11-02

## Context

A review against a zero-trust identity checklist (mTLS and workload
identity, passkeys, device-bound sessions, sender-constrained OAuth
tokens, JWT validation, deny-by-default authorization, hardware-backed
keys, verification) showed that the ruleset already covered strict mTLS,
cookie flags, session rotation and expiry, short-lived audience-restricted
access tokens, ABAC/deny-by-default authorization and security logging,
but left gaps. The checklist text was not copied; every requirement was
rewritten in the ruleset's own wording and backed by a primary source.

## Decision

The following requirements were added:

- `web.md`, "Authentication flows": explicit algorithm allowlist and token
  type check for JWTs; ID tokens MUST NOT be accepted as access tokens;
  downscoped tokens for downstream calls; sender-constrained tokens (DPoP
  or mTLS-bound) where a client holds tokens itself; refresh-token rotation
  with reuse detection and revocation.
- `web.md`, new section "Authentication strength (IdP configuration)":
  passkeys with user verification as the preferred primary factor,
  authenticated enrollment with notification, account recovery not weaker
  than the primary factor.
- `web.md`, "Session lifecycle": canonical CSRF rule for cookie-authenticated
  state changes, server-side revocation at any time, device-bound sessions
  (DBSC) as SHOULD where the platform supports it.
- `iac.md`, Kubernetes/Helm: mesh-level deny-by-default `AuthorizationPolicy`
  with one identity per workload; no path to the application port that
  bypasses the ingress gateway, oauth2-proxy or the sidecar.
- `cryptography.md`: prefer non-exportable KMS/HSM-held keys; rotation is
  automated and designed into key identifiers.
- `verification.md`: negative tests for replay, token-type confusion,
  authorization boundaries and proxy/mesh bypass; security decisions must
  show up in logs.

## Open points

- DBSC is a W3C draft with limited browser support; it is therefore SHOULD,
  not MUST. Revisit when support is general.
- The ruleset still has no single sentence that forbids self-built
  authentication, session or authorization components independently of
  the oauth2-proxy and OPA requirements; the prohibition currently follows
  from `general.md` ("evaluated libraries", no local login), `web.md`
  ("never hand-write token parsing or validation"), `architecture.md`
  (OPA mandatory) and `supply-chain.md` ("never reimplement
  security-critical functionality"). A dedicated MUST in `general.md` is a
  candidate follow-up.

## Sources

RFC 9700, RFC 9449, RFC 8705, RFC 8725, RFC 9068, W3C WebAuthn Level 3,
NIST SP 800-63B, W3C WebAppSec DBSC draft, Istio security concepts, OWASP
Key Management / Authentication / CSRF Prevention Cheat Sheets, NIST SP
800-57 Part 1. URLs are listed in the `Sources` sections of the changed
rule files.
