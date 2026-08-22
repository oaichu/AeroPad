# AeroPad Security Remediation Specification

**Status:** locked after Gate A approval; core remediation verified 2026-08-22
**Date:** 2026-08-22
**Scope:** commercial-readiness remediation for the local-first browser vault

## Goal

Make AeroPad safe to describe as a local-first, encrypted-at-rest 2FA and security workbench without claiming protection that a same-origin web application cannot provide.

## Product invariants

1. Vault content never uses a remote API, remote search index, telemetry pipeline, or account service.
2. New vault content is encrypted before durable persistence. Plaintext localStorage is a legacy migration input only.
3. Notes and TOTP accounts are committed as one encrypted snapshot. A failed write leaves the last committed generation readable.
4. A successful save is reported only after the durable storage transaction completes.
5. A forgotten master password remains unrecoverable, but an encrypted portable backup is a first-class recovery path.
6. TOTP imports reject unsupported semantics instead of silently changing them.
7. `src/` is the source of truth for crypto, storage, notes, and browser behavior. Generated artifacts are never hand-edited.

## Remediation slices

### P0 — data safety and correctness

- Replace the two-record localStorage vault with the versioned IndexedDB record specified in [`vault-schema.md`](vault-schema.md).
- Add encrypted `.aeropad` export/import, checksum validation, backup reminders, and best-effort persistent-storage detection.
- Add a serialized storage queue with `flush()`. Lock, password changes, and export await the queue before clearing session state.
- Generate 32-character Base32 secrets by default; retain import compatibility for valid shorter legacy secrets.
- Enforce per-account TOTP windows, strict `totp` URI parsing, strict `SHA1`/`SHA256`/`SHA512` handling, and 6/8-digit policy.
- Remove dynamic HTML sinks for user-controlled messages and secret values.

### P1 — lifecycle, privacy, and engineering

- Version the envelope and bound every field before invoking PBKDF2 or AES-GCM. The v2 baseline is PBKDF2-HMAC-SHA256 with 600,000 iterations; a future KDF must use a new supported version.
- Add automatic lock after 15 minutes of inactivity, visibility-change refresh, DOM secret cleanup, and explicit save-error UI.
- Vendor fonts and QR libraries; use a self-only CSP and include third-party notices.
- Make production import the tested `src` modules, declare every build/test dependency, and make E2E paths portable.
- Downsample QR images to a maximum 2048px edge before pixel extraction.
- Add local debounced search with Unicode normalization and title-first scoring without a remote index.
- Update copy, title, package metadata, privacy text, and security model to remove unsupported legal/security claims.

### P2 — product expansion after the core gate

- HOTP support with a counter-management UX.
- PWA install/offline shell, camera scanning, bulk migration, and encrypted device-to-device transfer.
- Tags and richer local search ranking.
- Independent security review and trademark clearance before paid positioning.

## Release acceptance

A commercial beta may not use security-vault positioning until all P0 slices pass unit, browser, migration, corruption, recovery, and artifact checks. P1 items required for the public security story must pass before public launch. A closed experimental beta may ship with an explicit “local utility / no recovery guarantee” notice only if the current baseline is kept isolated from commercial claims.

## Non-goals

- No backend, account system, cloud sync, remote analytics, or server-side decryption.
- No silent HOTP-to-TOTP conversion.
- No claim that a web app can resist hostile same-origin JavaScript delivered by a compromised deployment.

## Current release gate

The evidence packet is [`../docs/release-readiness.md`](../docs/release-readiness.md).
The core P0/P1 acceptance baseline passes the unit, browser, migration,
recovery, CSP, dependency, and artifact checks. This supports a closed
experimental beta, but the recommendation remains `NO-GO` for paid or
security-critical release until the independent security review, trademark
clearance, and clean release-commit checks are complete. HOTP, PWA/camera,
bulk migration, device transfer, and richer search remain explicit post-beta
work rather than hidden release blockers.
