# Java Security Rules

Apply these rules for all Java code, in addition to `.ai-security-rules/frameworks/spring-boot.md` when
Spring Boot is used.

## Injection & unsafe evaluation
- Database access only via `PreparedStatement`/JPA with bound parameters;
  never concatenate user input into SQL/JPQL.
- Start processes with `ProcessBuilder` and an argv list; never pass
  user-influenced strings to `Runtime.exec` as a shell command.
- Never evaluate user input with `ScriptEngine`, EL, SpEL, OGNL or
  reflection (`Class.forName`, `Method.invoke` on user-controlled names).
- Prevent path traversal: `Path.normalize()` the resolved path and verify it
  `startsWith` the intended base directory before file operations.
- Prevent SSRF (CWE-918): validate user-supplied URLs against an allowlist
  (host and protocol) before fetching with `RestTemplate`/`WebClient`/
  `HttpClient`; restrict to `https`, block redirects to untrusted targets
  and never fetch internal/metadata addresses on user input.

## Deserialization & XML
- Never deserialize untrusted data with Java native serialization
  (`ObjectInputStream`); prefer JSON with a fixed schema. If native
  deserialization is unavoidable, enforce a strict allowlist via
  serialization filters (JEP 290, `ObjectInputFilter`).
- Configure every XML parser against XXE: disable DTDs and external
  entities (`disallow-doctype-decl`, secure processing feature) on
  `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, etc.
- Do not use Jackson polymorphic/default typing on untrusted input.

## Cryptography & randomness
- Use the JCA/JCE providers with mechanisms allowed by BSI TR-02102 only -
  see `.ai-security-rules/cryptography.md`; ask the user before deviating.
- Use `SecureRandom` for anything security-relevant, never
  `java.util.Random`; use `MessageDigest.isEqual` for constant-time
  comparison of secrets.

## Platform & hygiene
- Target a current LTS JDK and keep it patched.
- Validate all inputs at trust boundaries (Bean Validation or explicit
  checks for type, format, length, range).
- Logging: use a logging framework with parameterized messages; sanitize
  CR/LF from user input before logging (log injection); never log secrets
  or PII; keep logging libraries (e.g. Log4j) current.
- Return generic error messages; never expose stack traces to clients.
- Manage dependencies via Maven/Gradle with exact, pinned versions in the
  BOM/version catalog - no version ranges; verify new dependencies per
  `.ai-security-rules/supply-chain.md` and run its dependency checks
  (OSV-SCALIBR or agent-performed: vulnerabilities, newer release, 7-day
  cooldown).
- Do not use `sun.*`/internal APIs; do not disable the module system or
  security features to "make it compile".

# Sources
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Cheat Sheet Series (Java Security, Deserialization, XXE Prevention, SSRF Prevention, Logging): https://cheatsheetseries.owasp.org/
- Oracle Secure Coding Guidelines for Java SE: https://www.oracle.com/java/technologies/javase/seccodeguide.html
- OpenSSF Security-Focused Guide for AI Code Assistant Instructions: https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions.html
