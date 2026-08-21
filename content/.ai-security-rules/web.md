# Web Security Rules (HTTP Headers, Cookies, Caching, Browser Storage)

Apply these rules to every component that produces HTTP responses or runs in
the browser, regardless of framework (Flask, Spring Boot, Node/Express,
Angular, React, SSR frontends). Several sections are adapted from TSS-WEB
(CC BY 4.0, Secodis): HTTP Header Security, Secure Fileuploads and
Downloads, Secure User Registration & Authentication, User Passwords,
Secure Session Management, Data Security and API Security.

## Baseline response headers (set centrally, e.g. middleware/filter/gateway)

| Header | Value |
|---|---|
| `Content-Type` | Correct media type; add `charset=utf-8` for textual bodies |
| `Strict-Transport-Security` | `max-age=31536000` after HTTPS rollout |
| `X-Frame-Options` | `SAMEORIGIN` (or CSP `frame-ancestors`) |
| `Referrer-Policy` | `same-origin` |
| `X-Content-Type-Options` | `nosniff` |
| `Permissions-Policy` | Deny by default, e.g. `camera=(), microphone=(), geolocation=(), payment=(), usb=()`; grant only the features the UI actually uses, scoped to the origins that need them |

## Conditional headers

- Do not add entity headers to responses that cannot contain a body (for
  example 204). Preserve protocol/framework semantics.
- Add HSTS only over HTTPS. Enable `includeSubDomains` only after every
  subdomain is HTTPS-capable. Add `preload` only after an explicit operational
  review of the irreversible/long-lived impact and after meeting current
  browser preload requirements.

- **Session/authentication cookies**: `Set-Cookie: ...; HttpOnly; Secure;
  SameSite=Lax` (`Strict` where the UX allows). `SameSite=None` requires
  `Secure`, a documented cross-site need and CSRF protection.
- **Responses with confidential data**: `Cache-Control: no-cache, no-store`,
  `Pragma: no-cache`, `Expires: -1`.
- **Untrusted file downloads**: `Content-Disposition: attachment;
  filename=<sanitized>` and `X-Download-Options: noopen`.

## Content-Security-Policy (distinguish backend and frontend)

- **Backend (APIs and every response that is not the browser UI)**: always
  set the strict policy

  ```
  Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox
  ```

  `default-src 'none'` denies loading any resource, `frame-ancestors 'none'`
  prevents framing, and `sandbox` prevents popups and the execution of
  plugins and scripts even if a response ends up rendered in a browser
  (direct navigation, MIME confusion, reflected content). Set it centrally
  in middleware so no endpoint can miss it.
- **Frontend (browser UI/SPA)**: a deliberately permissive policy is used
  because the frameworks in use require it (e.g. inline styles/scripts).
  Treat it as **defense-in-depth only, never as the XSS defense**: XSS
  prevention comes from framework auto-escaping, context-sensitive output
  encoding and input validation. The permissive policy is a recorded
  accepted risk (`docs/threat-models/web-header-rules-update.md`); still
  keep `object-src 'none'` and `frame-ancestors` restrictions where
  possible, and tighten towards nonce-based `script-src` when the
  framework allows it.
- Do not copy the frontend policy onto backend responses or vice versa;
  the split is intentional.

## Fetch metadata (`Sec-Fetch-*`) — backend enforcement

The backend evaluates the fetch metadata request headers `Sec-Fetch-Site`,
`Sec-Fetch-Mode` and `Sec-Fetch-Dest` as a **resource isolation policy**,
centrally in middleware (not per endpoint):

- Allow requests where `Sec-Fetch-Site` is `same-origin` or `none`
  (user-initiated navigation, bookmarks, address bar).
- Allow requests **without** `Sec-Fetch-*` headers: older browsers and
  non-browser clients (service-to-service, CLIs) do not send them.
- Allow simple top-level navigations: `Sec-Fetch-Mode: navigate` with
  `GET` and a `Sec-Fetch-Dest` that is not `object`/`embed`.
- Reject everything else (browser-attributed cross-site requests) with
  `403` and log the rejection.
- Exempt only documented endpoints that must accept cross-site requests
  (e.g. OAuth2/OIDC redirect endpoints, webhooks); record each exemption.
- Roll out in log/report-only mode first and check the logs before
  enforcing, so legitimate cross-site flows are not broken.
- Fetch metadata headers are client-controlled input: they are
  defense-in-depth against CSRF, XSSI and cross-origin leaks and **never
  replace** authentication, authorization (OPA), CSRF tokens or `SameSite`
  cookie attributes.

## File uploads and downloads

- Accept uploads only from server-side authenticated users; anonymous
  upload endpoints require an explicit decision plus DoS controls (size
  and rate limits below).
- Store uploads outside the web/document root (or in a database/object
  store), with restrictive permissions and never executable. Never serve
  files directly from the upload location.
- Use unique, server-generated filenames; never a user-supplied path or
  name (path traversal - see the language rules).
- Validate against an **allowlist of permitted types**, checking file
  extension, declared MIME type and actual file content (magic
  bytes/parsing). Block executable and active content (`.html`, `.js`,
  `.svg`, binaries, documents with macros); sanitize or reject macro
  content.
- Enforce a maximum file size and a per-user/IP upload frequency limit.
- Scan uploads for malware; reject or quarantine on detection. A negative
  scan is one signal, not proof - storage and serving isolation stay
  mandatory.
- Serve user-supplied files from a **separate origin/domain** so injected
  content cannot run with the application's origin; apply the download
  headers from "Conditional headers" and encode user-controlled filenames
  (reflected file download).

## API security (REST, GraphQL, WebSockets)

- Expose only the endpoints a consumer actually needs; external APIs run
  behind a hardened gateway or reverse proxy.
- Validate API requests restrictively against a schema (preferably the
  OpenAPI definition); reject unknown fields and wrong types at the
  boundary (input-validation baseline: `general.md`).
- Rate-limit public endpoints according to business need (see
  "Anti-automation" below for authentication endpoints). Standard
  infrastructure implementation: Istio/Envoy rate limiting, see
  `.ai-security-rules/iac.md`.
- **CORS**: restrictive allowlist only. Authorize the `Origin` header on
  the server side; never `Access-Control-Allow-Origin: *` together with
  credentials, and never reflect arbitrary request origins.
- API keys and other shared secrets: never in URLs (use POST bodies or
  headers), unique per service **and** environment; storage per
  `general.md` secrets rules.
- Access tokens: short-lived, restrictive `scope` and `audience`,
  validated per the OAuth2/OIDC section below.
- Frontend-facing APIs enforce the same authorization as the UI they
  serve (OPA, `authorization.md`) and need CSRF protection when cookies
  authenticate the request.
- **WebSockets**: `wss://` only; authorize the `Origin` header during the
  handshake (cross-site WebSocket hijacking); apply the same
  authentication and authorization as HTTP endpoints; treat every message
  as untrusted input.
- **GraphQL**: enforce query depth, complexity/cost and result-size
  limits; disable introspection in production; prefer persisted queries;
  authorization happens per resolver/field via OPA, not only at the
  endpoint.

## Browser storage (localStorage, sessionStorage, IndexedDB, Cache API)

- Never store secrets, session/auth tokens (incl. JWTs), API keys, passwords
  or PII in `localStorage`, `sessionStorage`, IndexedDB or the Cache API:
  scripts executing with the application's origin can access these stores.
  Consequently, injected script can steal their contents; the stores also do
  not provide application-controlled encryption at rest.
- Auth tokens are held **in RAM only** (a JS variable/closure), never
  persisted: short-lived, renewed via silent re-authentication, accepting
  that a page reload drops them. Never put tokens in JS-accessible storage;
  do not generate the "JWT in localStorage" pattern.
- **Documented exception**: tokens may be transported via `HttpOnly; Secure;
  SameSite` cookies set by the backend (see the cookie rule above) - e.g.
  the oauth2-proxy session cookie in the standard deployment, or an
  `HttpOnly` refresh-token cookie. Record the exception and its reason in
  the threat model/security decision; cookie transport requires CSRF
  protection.
- Do not fake security with client-side encryption: encrypting data in JS
  with a key that lives in the same origin/storage protects nothing.
- If a task requires persisting sensitive data in the browser, stop and ask
  the user instead of picking a storage mechanism silently.
- Treat everything read back from browser storage as untrusted input -
  another tab, script or extension may have modified it. Validate it before
  use; never render it as HTML or feed it into `eval`/DOM sinks.
- Never base authorization on browser-storage state (flags like
  `isAdmin=true`); decisions come from the server via OPA
  (`.ai-security-rules/authorization.md`).
- Prefer `sessionStorage` over `localStorage` for transient, non-sensitive
  UI state; `localStorage` persists indefinitely on shared machines.
- Clear application-owned sensitive or session-related browser state on logout
  with targeted removal, in addition to server-side session invalidation. Do
  not erase unrelated user preferences without a product requirement.

## Authentication flows (OAuth2/OIDC)

- Use the flow matching the client type: **Authorization Code with PKCE** for
  user-facing clients (SPA, mobile, native, server-rendered web);
  **Client Credentials** for service-to-service/machine access.
- Standard deployment: authentication is terminated by **oauth2-proxy** in
  front of the application - the proxy runs the code flow with the IdP and
  manages the session cookie; the application only validates the forwarded
  token. Identity headers are trusted solely when the request comes through
  the proxy (network isolation; the proxy strips client-supplied identity
  headers). For SPAs behind oauth2-proxy no token handling in the browser is
  needed at all (see "Browser storage").
- Never generate the Implicit Grant or Resource Owner Password Credentials
  (ROPC) flow - they leak tokens and credentials. If existing code uses
  them, flag it for retirement instead of extending it.
- Register redirect URIs as exact-match allowlists; never wildcards.
- Use the framework's/IdP's evaluated OIDC libraries; validate issuer,
  audience, signature and expiry of every token (claims entering
  authorization decisions: see `.ai-security-rules/opa.md`).

## Session lifecycle

In the standard deployment these are **configuration obligations for
oauth2-proxy and the IdP**; applications managing local sessions enforce
them directly:

- Idle timeout: invalidate sessions after at most 30 minutes of
  inactivity (tune per protection requirement, document deviations).
- Absolute lifetime: invalidate active sessions after at most 24 hours.
- Renew the session ID after successful authentication (session
  fixation); never accept a client-proposed session ID.
- Invalidate sessions server-side on logout, in addition to clearing
  browser state (see "Browser storage").
- Limit concurrent sessions per user where the protection requirement
  demands it; invalidate existing sessions on new login.
- Locally generated session IDs: at least 120 bit from a CSPRNG
  (`cryptography.md`), never transmitted in URLs; cookie flags per
  "Conditional headers".

## Anti-automation and account enumeration

- Login, registration and account-recovery endpoints MUST have
  brute-force protection: rate limits keyed on both account and source
  (IP/device), increasing delays and temporary lockout. CAPTCHA is an
  additional measure, not a replacement (accessibility/UX decision).
  Framework implementations: see `frameworks/flask.md` (Flask-Limiter)
  and the equivalent mechanism of the stack in use; infrastructure-level
  limits via Istio/Envoy (`.ai-security-rules/iac.md`) complement but do
  not replace these account-aware controls.
- Prevent account enumeration: generic error messages ("username or
  password is incorrect"), and uniform responses with comparable timing
  for existing and unknown accounts in registration and reset flows.

## Local credential flows (documented exception)

These rules apply only when the stop-and-ask in `general.md` (no local
login by default) was answered with an explicit, documented approval:

- Password storage and hashing per `cryptography.md` (memory-hard,
  BSI-approved).
- Password change requires re-authentication with the current password;
  notify the user (e.g. email) after every password change or reset.
- Password reset: single-use, short-lived token delivered over a
  registered channel; the account state MUST NOT change before the reset
  completes; the reset link itself never establishes an authenticated
  session. Apply the anti-automation rules above.
- Never log, cache or transmit passwords in URLs; mask them in input
  fields.

## TLS operation (external endpoints)

Protocol versions, ciphers and key lengths come from BSI TR-02102
(`cryptography.md`); operationally:

- Redirect HTTP to HTTPS with `301`; HSTS per the baseline header table.
- Confidential data belongs in request bodies or headers, never in URLs
  (URLs end up in logs, proxies and browser history).
- Use valid certificates from trusted CAs; **no wildcard certificates**.
- Verify externally reachable endpoints with an up-to-date TLS
  configuration test (e.g. SSL Labs grade A, `testssl.sh`) as part of
  verification.

## Rules

- Set the baseline headers centrally, not per endpoint, so new routes cannot
  miss them; prefer the framework mechanism (Flask-Talisman, Spring Security
  headers config, helmet).
- Prevent open redirects: never redirect to a user-supplied URL. Validate
  redirect targets against an allowlist of relative paths/known hosts (this
  includes OAuth2 `redirect_uri` handling and post-login "next"/"returnTo"
  parameters).
- Do not weaken or remove existing headers to "fix" a feature; adjust the
  policy explicitly and flag it for human review.
- Load third-party scripts and styles with Subresource Integrity
  (`integrity` plus `crossorigin` attributes) and pinned versions; prefer
  self-hosting. A compromised CDN then cannot execute in users' browsers.
- Activating a new header can break functionality - combine it with
  functional tests (TSS-WEB caveat).

# Sources
- W3C Fetch Metadata Request Headers: https://www.w3.org/TR/fetch-metadata/
- web.dev "Protect your resources from web attacks with Fetch Metadata": https://web.dev/articles/fetch-metadata
- DSOMM (Identity and Access Management, activity "Use correct OAuth2/OIDC authorization flows"): https://dsomm.owasp.org/
- TSS-WEB - Technical Security Standard for Web Applications (CC BY 4.0, Secodis; requirements adapted and modified from controls B.3 Fileuploads/Downloads, B.5 Registration & Authentication, B.6 User Passwords, B.7 Session Management, B.10 Data Security, B.12 API Security, B.14 HTTP Header Security): https://tss-web.secodis.com/
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- OWASP HTML5 Security Cheat Sheet (Local Storage), Session Management and Unvalidated Redirects Cheat Sheets: https://cheatsheetseries.owasp.org/
- oauth2-proxy documentation: https://oauth2-proxy.github.io/oauth2-proxy/
