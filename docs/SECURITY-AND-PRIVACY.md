# AeroPad Security and Privacy Model

This document describes the current browser application and is not legal advice or an independent security certification. Hosting, trademark, and jurisdiction-specific privacy obligations remain the responsibility of the distributor.

## Product boundary and precise claims

AeroPad is a static, local-first browser application. The shipped runtime has no backend API, user account, remote search index, telemetry pipeline, or server-side decryption. **AeroPad does not upload vault content.** Vault content is encrypted at rest before the current IndexedDB snapshot is committed.

The browser still makes ordinary requests to the static host to load the application. A hosting provider may process normal network metadata such as an IP address, request time, user agent, and requested asset. This is separate from vault content and must be covered by the operator’s hosting privacy notice.

## Data categories

### Sensitive vault data

- Notes and note metadata.
- TOTP seeds, issuer/account labels, algorithm, digits, and period.
- Account passwords entered into the security workbench.
- The encrypted vault envelope and encrypted `.aeropad` backup payload.
- Decoder/generator values while they are being edited.

New vault data is encrypted with AES-256-GCM and committed as one versioned IndexedDB record. The master-derived key is non-extractable and session-only. The application may hold plaintext in memory and selected DOM fields while unlocked; it clears transient secret controls during locking where practical.

### Local metadata and preferences

Theme and language preferences, plus the last encrypted-backup timestamp, are stored locally to make the interface work. They are not vault content. No category is sent to a remote search service or telemetry system by AeroPad.

## Threat model

The design protects persisted vault bytes from casual storage inspection, wrong-password attempts, malformed envelopes, and partial-write corruption. It does not protect plaintext after unlock from hostile same-origin JavaScript delivered by a compromised deployment, a malicious future update, or an extension with access to the page. It also cannot protect a device or browser session that is already compromised.

Strict CSP, self-hosted dependencies, pinned build inputs, artifact parity checks, strict TOTP parsing, bounded envelope validation, automatic locking, and flush-before-lock reduce the attack surface. They do not turn a web application into a trusted execution environment.

## Recovery and durability

- A forgotten master password cannot be recovered by AeroPad.
- The encrypted `.aeropad` export is the recovery path; restoring requires the password used to protect that backup.
- Restore validates the version, checksum, envelope bounds, and password before replacing the current record.
- Browser storage is best-effort. Users should keep backups outside the browser and periodically test a restore on a spare profile.
- Persistent-storage requests are advisory; browser cleanup, profile deletion, device loss, or quota pressure can still remove local data.
- AeroPad does not offer a plaintext secret export through the backup flow.

## Security controls

- Web Crypto AES-256-GCM with generation-bound AAD.
- PBKDF2-HMAC-SHA256 with a 600,000-iteration baseline and bounded versioned envelopes.
- One encrypted IndexedDB snapshot for notes and TOTP accounts, with serialized commits and `flush()`.
- Strict `totp` URI parsing; unsupported HOTP, algorithms, digits, and periods are rejected rather than reinterpreted.
- Secret masking, reveal controls, inactivity locking, DOM cleanup, explicit save states, and accessible security dialogs.
- Self-hosted fonts and QR libraries, self-only script/style CSP, `Referrer-Policy: no-referrer`, and restrictive permissions policy.

## Privacy and telemetry

AeroPad has no account registration, analytics SDK, advertising identifier, remote search, or telemetry endpoint in the runtime. There is no telemetry. The application does not intentionally transmit notes, passwords, TOTP seeds, decoder input, or backup contents. Distributors must still document their static-host provider, CDN/logging configuration, cookie behavior, support channels, and any changes made outside this repository.

## Reporting and release status

Report suspected vulnerabilities privately to the project maintainer before public disclosure. This document describes a tested local utility; it is not a promise of resistance to all browser, deployment, extension, or supply-chain compromise. An independent security review and trademark clearance remain prerequisites for security-critical paid positioning.
