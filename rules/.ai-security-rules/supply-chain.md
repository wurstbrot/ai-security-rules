# Supply Chain Rules

Apply these rules whenever a change adds or updates a library dependency or
selects a container base image.

## Libraries

- Verify every new dependency exists on the official registry (npm, PyPI,
  Maven Central, ...) and is the intended project: matching publisher, source
  repository, realistic age and download counts. LLM-suggested names are
  frequently hallucinated ("slopsquatting").
- Use OpenSSF Scorecard as one input when the canonical source repository is
  supported. A score above 3.5 is a positive signal, not an approval or proof
  that the published package is safe. Check with `scorecard --repo=<url>` or the public API
  (`https://api.scorecard.dev/projects/github.com/<org>/<repo>`).
- If the score is 3.5 or below, no score exists, or package-to-repository
  identity cannot be established, perform enhanced review. Document why the
  dependency is needed, alternatives, publisher identity, known
  vulnerabilities, maintenance, provenance/signatures and compensating
  controls. High-risk or unresolved results require an explicit user decision.
- Prefer dependencies already used in the organization/project; pin exact
  versions - no version ranges - and commit resolved lockfiles; keep the
  SBOM (CycloneDX/SPDX) up to date.
- Dependency checks happen **at integration time** - in the same step in
  which a new or updated library is added, before the change is presented.
  **OSV-SCALIBR is the preferred tool but optional**: an agent may answer
  the same questions itself (registry metadata, OSV lookups). Either way,
  answer and report all three (no separate SCA scan is required):
  1. Are there known vulnerabilities (OSV) for the version being adopted?
  2. Does a newer release of the dependency exist?
  3. Is the adopted release at least 7 days old (**release cooldown**)?
  Adopting a release younger than 7 days requires an explicit user decision
  (protection against freshly published malicious/compromised versions).
  The CI run only repeats these checks independently, never performs them
  first.

## Container images

When selecting or changing a base/runtime image, evaluate it against the
criteria from "Evaluation of Container Images" (Timo Pagel, https://pagel.pro).

**Must-have requirements** - an image failing any of these is not used
without an explicit user decision:

1. **Malware and vulnerability analysis**: scan with container-aware tooling.
   A signature-based ClamAV scan may add a signal but cannot establish that an
   image or its build process is trustworthy.
2. **Privileges**: image runs as non-root (check `USER`/runtime UID); no
   unnecessary setuid/setgid binaries (`find / -perm /6000`).
3. **Currency**: image is actively maintained and incorporates relevant base-OS
   and runtime fixes within the organization's remediation SLA. Release count
   alone is not a quality metric.

**Comparison criteria** - used to rank several candidate images that pass
the must-haves, not as pass/fail gates:

4. **Attack surface**: small images preferred - < 250 MB very good,
   < 500 MB acceptable; prefer distroless/minimal (no shell present).
5. **Architectures**: available for all required platforms (amd64, arm64, ...).
6. **Community reception**: download counts, stars, open security issues and
   maintainer response times.
7. **SBOM**: image ships an SBOM (label/attestation or `/sbom.json`).
8. **Versioning**: proper semantic versioning of tags across registries.
9. **Reproducibility**: rebuilds produce identical layers where the project
   claims reproducible builds.
10. **Signing**: image is signed and the signature verifies (cosign,
    notation, Docker Content Trust).
11. **Dockerfile quality**: maintainer label, multi-stage build, layer/cache
    hygiene.

Check the criteria you can verify yourself (registry metadata, tags,
architectures, image config/Dockerfile, signatures, size); for criteria you
cannot verify from available data (e.g. malware scan, build
reproducibility), state that explicitly and ask the user. Select images only
after establishing that the publisher and distribution
channel are trustworthy. Deployment references must resolve to a fixed
content digest such as `sha256:...`; a movable tag, including `latest`, is not
a sufficient identity. If a required image fails a must-have criterion,
document the deviation and prompt the user for a decision before using it;
weaknesses in the comparison criteria only lower an image's ranking and are
reported when presenting the chosen option.

# Sources
- OSV-SCALIBR (dependency inventory, OSV vulnerability matching, release checks): https://github.com/google/osv-scalibr
- Evaluation of Container Images (Timo Pagel): https://pagel.pro/en/evaluation-of-container-images
- OpenSSF Scorecard: https://scorecard.dev/
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions (CC BY
  4.0; adapted):
  https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
- DSOMM Agentic AI dimension, activity "Validation of AI-suggested dependencies" (Scorecard-threshold and identity-check approach adapted from it): https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Cheat Sheet Series (Vulnerable Dependency Management, Docker Security): https://cheatsheetseries.owasp.org/
