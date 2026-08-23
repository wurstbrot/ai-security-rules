# Flask Security Rules

Apply these rules when generating or changing Flask code.

## Configuration & sessions
- Load `SECRET_KEY` from the environment or a secret manager; never hardcode
  it and never commit it. Generate it with a CSPRNG (`secrets.token_hex(32)`).
- Never run with `debug=True` or the Werkzeug debugger in production; the
  debugger allows arbitrary code execution.
- Set `SESSION_COOKIE_SECURE=True`, `SESSION_COOKIE_HTTPONLY=True` and
  `SESSION_COOKIE_SAMESITE="Lax"` (or `"Strict"`). Remember that Flask's
  default session cookie is signed but **not encrypted** - never store
  sensitive data in it.

## Templates & output
- Render with `render_template` and keep Jinja2 autoescaping on. Never pass
  user input through `| safe`, `Markup()` or `autoescape false`.
- Never build templates from user input and never call
  `render_template_string` with user-controlled content - this is server-side
  template injection (SSTI) leading to remote code execution.

## Input handling & database
- Validate all request data (args, form, JSON, headers, files) for expected
  type, format and length at the boundary, e.g. with marshmallow or pydantic.
- Use SQLAlchemy ORM or parameterized queries. Never build SQL with f-strings,
  `%` or `+` concatenation of user input.
- Never call `eval`/`exec` on user input; use `subprocess` with `shell=False`
  and a list argv; use `yaml.safe_load`, never `pickle` on untrusted data.

## Authentication, authorization, CSRF
- Authentication is terminated by **oauth2-proxy**; the deployment model,
  identity-header trust conditions and the local-credentials stop-and-ask
  rule are canonical in `.ai-security-rules/web.md` ("Authentication flows")
  and `general.md`. Flask-specific: implement no login flow of your own;
  validate the forwarded token (`Authorization: Bearer ...`) in a
  `before_request` hook with an evaluated library (e.g. Authlib or PyJWT
  with JWKS; issuer, audience, signature, expiry) and build the OPA subject
  from the **validated** claims - never from raw `X-Forwarded-*` headers.
- Authorization: every route performing a protected application-resource
  action obtains its decision from OPA (see `.ai-security-rules/opa.md`), e.g.
  via a decorator or `before_request` hook that queries the OPA sidecar and
  denies on error (fail closed). Explicitly classify public and operational
  routes; do not hardcode policy logic in views.
- Enable CSRF protection with Flask-WTF `CSRFProtect` for all browser-facing
  state-changing endpoints.
- Rate-limit authentication and other sensitive endpoints (Flask-Limiter).

## Files & uploads
- Use `werkzeug.utils.secure_filename` for uploaded filenames and
  `werkzeug.utils.safe_join` (or equivalent checks) for any user-influenced
  filesystem path; set `MAX_CONTENT_LENGTH` to limit upload size.

## Headers, CORS, errors
- Add security headers (CSP, HSTS, X-Content-Type-Options, frame protection),
  e.g. via Flask-Talisman.
- Configure CORS (Flask-CORS) with an explicit origin allowlist; never use
  `*` together with credentials.
- Register error handlers that return generic messages; log details
  server-side, never expose stack traces or internals to clients.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- Flask security considerations: https://flask.palletsprojects.com/en/stable/web-security/
- OWASP Cheat Sheet Series (XSS, SQL Injection, Session Management, File Upload): https://cheatsheetseries.owasp.org/
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
