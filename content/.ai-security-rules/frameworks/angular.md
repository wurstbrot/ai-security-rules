# Angular Security Rules

Apply these rules when generating or changing Angular code.

## XSS & DOM safety
- Rely on Angular's built-in escaping and sanitization: use interpolation
  (`{{ }}`) and property binding; let Angular sanitize `[innerHTML]` values.
- Treat every `bypassSecurityTrust*` call (`DomSanitizer`) as
  security-critical: avoid it; when unavoidable, sanitize the value first
  (e.g. DOMPurify), document why it is safe, and flag it for human review.
- Never manipulate the DOM directly with `ElementRef.nativeElement.innerHTML`,
  `document.write` or third-party DOM libraries on user data - this bypasses
  Angular's sanitizer. Use templates, bindings or `Renderer2`.
- Never generate templates from user input and never concatenate user data
  into template strings (template injection). Keep AOT compilation; do not
  use the JIT compiler on dynamic strings.
- Validate user-provided URLs before binding to `href`/`src`; reject
  `javascript:` URLs.

## HTTP, CSRF, tokens
- Use `HttpClient` and configure its built-in XSRF support
  (`withXsrfConfiguration` / `HttpClientXsrfModule`) to match the backend's
  CSRF cookie and header names.
- Hold auth tokens in RAM only (service field/closure); never in
  `localStorage`/`sessionStorage`. Transport via `HttpOnly` cookies set by
  the backend is a documented exception - see `.ai-security-rules/web.md`,
  "Browser storage".
- Call APIs over HTTPS only; never disable certificate validation in tooling.

## Authorization
- Route guards (`CanActivate`) and hidden UI elements are user experience,
  **not** security. Every protected action must be authorized server-side via OPA (see
  `.ai-security-rules/opa.md`); the frontend only reflects the decision.

## Hardening & hygiene
- Ship a Content Security Policy; avoid `unsafe-inline`/`unsafe-eval`.
- Never put secrets or API keys in Angular code or `environment.ts` - every
  byte of the bundle is public.
- Keep Angular and its dependencies up to date with the latest stable
  releases; never use a locally modified ("forked") copy of the framework.
- Validate all inputs server-side; client-side validators are UX only.

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- Angular security guide: https://angular.dev/best-practices/security
- OWASP Cheat Sheet Series (XSS Prevention, DOM based XSS Prevention): https://cheatsheetseries.owasp.org/
