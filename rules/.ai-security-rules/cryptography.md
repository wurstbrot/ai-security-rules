# Cryptography Rules (BSI)

Apply these rules whenever generated code touches cryptography (encryption,
hashing, signatures, key exchange, TLS configuration, randomness).

## Authoritative reference: BSI

- All cryptographic algorithms, modes, key lengths and protocol
  configurations used in the implementation phase **must be taken from the
  BSI Technical Guideline TR-02102** ("Cryptographic Mechanisms:
  Recommendations and Key Lengths", parts 1-4).
- **If a cipher or mechanism is not allowed/recommended by BSI, do not use it
  silently: stop and ask the user** for an explicit decision, and document
  the outcome (including justification) in the repository.
- BSI updates TR-02102 regularly; when in doubt about a mechanism, check the
  current edition instead of relying on memorized values.

## Non-authoritative orientation

Do not copy algorithm, curve, key-length or validity-period values from this
repository into an implementation. Determine them from the current applicable
TR-02102 part at implementation time and record the document edition/date in
the threat model or security decision. Prefer authenticated encryption and
memory-hard password hashing when the current BSI guidance and platform support
them. MD5, SHA-1 for new security uses, DES/3DES, RC4, ECB and home-grown
cryptographic protocols are prohibited unless an explicitly approved legacy
interoperability decision documents containment and migration.

## Implementation rules

- Use the platform's evaluated high-level crypto libraries (Java JCA,
  `node:crypto`/WebCrypto, Python `cryptography`); never implement primitives
  or protocols yourself.
- Use cryptographically secure randomness only: `SecureRandom` (Java),
  `crypto.randomBytes`/WebCrypto (JS), `secrets` (Python). Never `Math.random`
  or `java.util.Random` for anything security-relevant.
- Generate fresh, unpredictable IVs/nonces as the mode requires; never reuse
  a nonce with the same key (especially GCM).
- Keys come from a secret manager/KMS, never from source code.
- Prefer keys that are generated and held inside a KMS/HSM (on clients: the
  platform keystore or secure element) and marked non-exportable: the
  application asks the service to sign, decrypt or unwrap and never receives
  the private key material. Where an exported key is unavoidable, record why
  and how it is protected in the threat model.
- Rotation is automated, not manual: period, procedure and the
  overlap/re-encryption strategy are defined in the threat model and run by
  tooling (KMS key rotation, cert-manager, the mesh CA). Design key
  identifiers (`kid`, key versions) so a rotation needs no code change.
- Use constant-time comparison for secrets (MACs, tokens, hashes).

# Sources
- BSI TR-02102 Cryptographic Mechanisms: Recommendations and Key Lengths (parts 1-4): https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr02102/tr02102_node.html
- DSOMM Agentic AI dimension, activity "Language and framework specific security rules": https://github.com/devsecopsmaturitymodel/DevSecOps-MaturityModel/blob/a87320ebc358ffc12e9bbde88ff31356f460747f/src/assets/YAML/default/model.yaml
- OWASP Cryptographic Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Key Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Key_Management_Cheat_Sheet.html
- NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management: https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final
