# React Security Rules

Apply these rules when generating or changing React code.

## XSS
- Keep JSX's default escaping: render user data via `{value}` in JSX. Never
  use `dangerouslySetInnerHTML` with user-controlled content; if raw HTML is
  genuinely required, sanitize it first with DOMPurify and flag the usage for
  human review.
- Validate user-provided URLs before using them in `href`, `src` or
  `window.open`; reject `javascript:` and `data:` URLs.
- Never use `eval`, `new Function`, or string arguments to
  `setTimeout`/`setInterval` with user data.
- Server-side rendering: never inject serialized state into the HTML with a
  plain `JSON.stringify` in a `<script>` tag; escape it (e.g.
  `serialize-javascript` or explicit `<`/`>` escaping) to prevent script
  breakout.
- Use `rel="noopener noreferrer"` with `target="_blank"` links.

## Secrets & tokens
- Never put secrets in React code or build-time env vars (`REACT_APP_*`,
  `VITE_*`, `NEXT_PUBLIC_*`) - the entire bundle is public.
- Hold auth tokens in RAM only (state/closure, not persisted); never in
  `localStorage`/`sessionStorage`. Transport via `HttpOnly` cookies set by
  the backend is a documented exception (see `.ai-security-rules/web.md`,
  "Browser storage"); when cookies are used, implement CSRF protection
  matching the backend.

## Authorization
- Conditional rendering, hidden routes and client-side route guards are UX,
  **not** security. Every protected action and data access is authorized server-side
  via OPA (see `.ai-security-rules/opa.md`).

## Hardening & hygiene
- Validate all inputs server-side; client-side validation is UX only.
- Keep React and dependencies current; commit lockfiles; run the dependency
  checks (OSV-SCALIBR or agent-performed, see
  `.ai-security-rules/supply-chain.md`) and fix findings. Follow `.ai-security-rules/verification.md` before adding any
  new npm package (typosquatting/slopsquatting risk).

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Cheat Sheet Series (XSS Prevention, DOM based XSS Prevention, HTML5 Security): https://cheatsheetseries.owasp.org/
- React docs, `dangerouslySetInnerHTML`: https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
