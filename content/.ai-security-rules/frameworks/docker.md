# Docker Security Rules

Apply these rules when generating or changing Dockerfiles or Docker Compose
files, in addition to the general IaC rules in `.ai-security-rules/iac.md`.

## Non-root user (mandatory)

- Every image defines a dedicated unprivileged user and runs as it - never
  leave the default root user:

  ```dockerfile
  RUN addgroup --system --gid 10001 app \
      && adduser --system --ingroup app --uid 10001 app
  USER app
  ```

  For distroless bases, use the `:nonroot` variant. Place `USER` before
  `ENTRYPOINT`/`CMD`; verify with the image config that the runtime UID is
  non-zero.
- Grant write access only where the application needs it
  (`COPY --chown=app:app`, dedicated volume paths); keep everything else
  root-owned and read-only.
- Bind only unprivileged ports (> 1024) inside the container.
- Do not install `sudo` or add setuid/setgid binaries; the container image
  evaluation checks for them (`.ai-security-rules/supply-chain.md`).

## Image content

- Base images selected per `.ai-security-rules/supply-chain.md`, pinned by
  immutable digest; prefer minimal/distroless.
- Multi-stage builds: build tools stay in the builder stage; the final stage
  contains only the runtime artifacts.
- Never put secrets in layers, `ENV`, `ARG` or build context; use BuildKit
  secret mounts (`RUN --mount=type=secret,...`) for build-time credentials
  and a `.dockerignore` that excludes `.env`, `.git` and key material.
- Clean package caches in the same layer; define a `HEALTHCHECK`.

## Runtime configuration (Compose/`docker run`)

- `read_only: true` with explicit writable volumes/tmpfs where needed.
- `cap_drop: [ALL]` and add back only required capabilities;
  `security_opt: ["no-new-privileges:true"]`; never `privileged: true`.
- Never mount the Docker socket (`/var/run/docker.sock`) into application
  containers.
- Set memory/CPU limits; do not use `network_mode: host` without an explicit
  user decision.

# Sources
- Evaluation of Container Images (Timo Pagel; non-root and setuid criteria): https://pagel.pro/en/evaluation-of-container-images
- OWASP Docker Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html
- DSOMM (activity "Containers are running as non-root"): https://dsomm.owasp.org/
