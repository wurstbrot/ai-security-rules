# Decision: container images MUST be pinned to a specific version tag

Date: 2026-10-08

## Context

Earlier wording (before commit 33ce12b) described image references as
digest-pinned (`sha256:...`) without using the formal `MUST` keyword.
Commit 33ce12b allowed version tags and kept digest as `SHOULD`. Digests
are opaque, interfere with version-bump tooling and were frequently
replaced by assistants with `latest` when they could not resolve one.

## Decision

Container image references MUST be pinned to a specific version tag
(e.g. `1.2.3`). Floating tags such as `latest` or `stable` are forbidden.
Digest pinning is no longer mentioned in the rules; projects may still use
digests, but the ruleset does not require or prefer them.

Affected files: `rules/.ai-security-rules/general.md`, `iac.md`,
`supply-chain.md`, `frameworks/docker.md`.

## Risk accepted

A version tag is movable: a registry can re-publish a tag with different
content (accidental or malicious). This is accepted by the maintainer in
favour of maintainability; image trust is established through the
publisher/channel evaluation in `supply-chain.md` and the signature
verification rule in `general.md`. Projects with stricter supply-chain
requirements should add digest pinning as `MUST` in their own overrides.
