# Decision: container image references may use specific version tags

Date: 2026-10-08 (rule change in commit 33ce12b, manifest refreshed afterwards)

## Context

Before 33ce12b the ruleset described image references as digest-pinned in
four places (`general.md`, `iac.md`, `supply-chain.md`,
`frameworks/docker.md`). None of them used the formal `MUST` keyword;
`supply-chain.md` used the imperative "must resolve to a fixed content
digest", the others stated digest pinning as the expected practice without
a keyword. In practice this made generated Dockerfiles, Compose files and
manifests hard to maintain: digests are opaque, interfere with version-bump
tooling in some setups, and were frequently replaced by assistants with
`latest` when they could not resolve a digest.

## Decision

Image references use either a specific version tag (e.g. `1.2.3`) or an
immutable digest. Digest pinning is now explicitly `SHOULD` (preferred).
Floating tags such as `latest` or `stable` remain forbidden.

## Risk accepted

A version tag is movable: a registry can re-publish a tag with different
content (accidental or malicious). The change is a deliberate relaxation of
the previous wording and is recorded here so it is not a silent weakening.
Projects with stricter supply-chain requirements should keep digest pinning
as `MUST` in their own overrides.
