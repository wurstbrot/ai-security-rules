# Spring Boot Security Rules

Apply these rules when generating or changing Spring Boot code.

## Spring Security baseline
- Keep Spring Security enabled with its secure defaults (security headers,
  CSRF, session fixation protection). Never suggest disabling it to "make
  things work".
- Keep CSRF protection enabled for all cookie/session-based browser-facing
  endpoints.
- Deny by default in the security filter chain. Match intentionally public
  endpoints explicitly, route protected requests through an OPA-backed
  `AuthorizationManager`, and end the matcher chain with
  `.anyRequest().denyAll()` so unmatched requests fail closed.
  `.authenticated()` verifies identity only and must not replace OPA
  authorization. Never use `.permitAll()` as a catch-all.

## Authorization via OPA
- Fine-grained authorization decisions are delegated to OPA (see
  `.ai-security-rules/opa.md`) through the OPA-backed `AuthorizationManager`
  or an equivalent fail-closed integration with the sidecar/PDP. Deny when OPA
  is unavailable, returns no decision, or rejects the request.
- Where method-level defense in depth is required, enable method security and
  use an OPA-backed authorization component. Do not duplicate policy semantics
  in `@PreAuthorize` SpEL expressions; the decision logic lives in Rego.

## Input, persistence, serialization
- Validate request DTOs with Bean Validation (`@Valid`, constraint
  annotations). Bind requests to dedicated DTOs - never directly to JPA
  entities (mass assignment).
- Use Spring Data JPA or parameterized queries. Never concatenate user input
  into `@Query` strings, JPQL, native queries or `JdbcTemplate` SQL.
- Never enable Jackson default/polymorphic typing
  (`activateDefaultTyping`, `@JsonTypeInfo` with user-controlled class names)
  for untrusted input; never use Java native deserialization on untrusted data.
- Never evaluate SpEL/OGNL expressions built from user input.

## Authentication & secrets
- Authentication is terminated by **oauth2-proxy**; the deployment model,
  OAuth2/OIDC flow requirements, identity-header trust conditions and the
  local-credentials stop-and-ask rule are canonical in
  `.ai-security-rules/web.md` ("Authentication flows") and `general.md`.
  Spring-specific: implement no login flow of your own (no `oauth2Login()`,
  no login forms); validate the forwarded token as a resource server
  (`oauth2ResourceServer(...)` with JWT validation: issuer, audience,
  signature, expiry) and build the OPA subject attributes from the
  **validated** claims - never from raw `X-Forwarded-*` headers.
- Secrets come from environment variables, Spring Cloud Vault/Config or the
  platform's secret store - never from `application.properties`/`yml` files
  committed to git.

## Operations & error handling
- Actuator: expose only needed endpoints
  (`management.endpoints.web.exposure.include` minimal, e.g. `health`),
  require authentication/authorization for the rest, prefer a separate
  management port not exposed publicly.
- Set `server.error.include-stacktrace=never` and return generic error
  responses; log details server-side without secrets or PII (use
  parameterized logging, never concatenate user input into log messages).
- Enforce HTTPS and HSTS; keep Spring Security's default security headers.
- Limit uploads via `spring.servlet.multipart.max-file-size` /
  `max-request-size` and validate file type and content.
- Manage dependency versions through the Spring Boot BOM and keep Spring
  Boot at the latest stable patch release.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- Spring Security reference: https://docs.spring.io/spring-security/reference/
- OWASP Cheat Sheet Series (Java Security, Injection Prevention, Deserialization, Mass Assignment): https://cheatsheetseries.owasp.org/
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
